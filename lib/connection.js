'use strict';

const { ImapFlow } = require('imapflow');
const { Mailbox } = require('./mailbox');
const logger = require('./logger');
const crypto = require('crypto');
const packageData = require('../package.json');
const { backOff } = require('exponential-backoff');
const msgpack = require('msgpack5')();
const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');

const { normalizePath, resolveCredentials } = require('./tools');

const LIST_REFRESH_DELAY = 30 * 60 * 1000;
const RESYNC_DELAY = 15 * 60 * 1000;
const ENSURE_MAIN_TTL = 5 * 1000;

const MAX_BACKOFF_DELAY = 10 * 60 * 1000; // 10 min

class Connection {
    constructor(options) {
        this.options = options || {};

        this.account = this.options.account || '';
        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;

        this.emitLogs = this.options.accountLogger.enabled;

        this.cid = this.getRandomId();

        this.closing = false;
        this.closed = false;

        this.logger = this.getLogger();

        this.imapConfig = {
            // Set emitLogs to true if you want to get all the log entries as objects from the IMAP module
            logger: this.mainLogger.child({
                sub: 'imap-connection'
            }),
            clientInfo: {
                name: packageData.name,
                version: packageData.version,
                vendor: packageData.author
            },
            emitLogs: this.emitLogs
        };

        this.mailboxes = new Map();
        this.untaggedExistsTimer = false;
        this.redis = options.redis;
        this.notifyQueue = options.notifyQueue;

        this.refreshListingTimer = false;
        this.resyncTimer = false;

        this.completedTimer = false;

        this.pathCache = new Map();
        this.idCache = new Map();

        this.state = 'connecting';
    }

    getAccountKey() {
        return `iad:${this.account}`;
    }

    getMailboxListKey() {
        return `ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `iaz:logged`;
    }

    onTaskCompleted() {
        // check if we need to re-select main mailbox
        this.completedTimer = setTimeout(() => {
            clearTimeout(this.completedTimer);
            this.ensureMainMailbox().catch(err => this.logger.error(err));
        }, ENSURE_MAIN_TTL);
    }

    async ensureMainMailbox() {
        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        // start waiting for changes
        await this.select(mainPath);
    }

    async packUid(mailbox, uid) {
        if (isNaN(uid)) {
            return false;
        }

        if (typeof uid !== 'number') {
            uid = Number(uid);
        }

        if (typeof mailbox === 'string') {
            if (this.mailboxes.has(normalizePath(mailbox))) {
                mailbox = this.mailboxes.get(normalizePath(mailbox));
            } else {
                return false;
            }
        }

        const storedStatus = await mailbox.getStoredStatus();
        if (!storedStatus.uidValidity || !storedStatus.path) {
            return false;
        }

        let uidValBuf = Buffer.alloc(8);
        uidValBuf.writeBigUInt64BE(storedStatus.uidValidity, 0);
        let mailboxBuf = Buffer.concat([uidValBuf, Buffer.from(storedStatus.path)]);

        let mailboxId;
        if (this.pathCache.has(mailboxBuf.toString('hex'))) {
            mailboxId = this.pathCache.get(mailboxBuf.toString('hex'));
        } else {
            mailboxId = await this.redis.zGetMailboxId(this.getAccountKey(), this.getMailboxHashKey(), mailboxBuf);
            if (isNaN(mailboxId) || typeof mailboxId !== 'number') {
                return false;
            }

            this.pathCache.set(mailboxBuf.toString('hex'), mailboxId);
            this.idCache.set(mailboxId, mailboxBuf);
        }

        let uidBuf = Buffer.alloc(4 + 4);
        uidBuf.writeUInt32BE(mailboxId, 0);
        uidBuf.writeUInt32BE(uid, 4);

        let res = uidBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]+/g, '');

        return res;
    }

    async unpackUid(id) {
        const packed = Buffer.isBuffer(id) ? id : Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

        let mailboxId = packed.readUInt32BE(0);
        let uid = packed.readUInt32BE(4);

        let mailboxBuf;
        if (this.idCache.has(mailboxId)) {
            mailboxBuf = this.idCache.get(mailboxId);
        } else {
            mailboxBuf = await this.redis.zGetMailboxPathBuffer(this.getMailboxHashKey(), mailboxId);
            if (!mailboxBuf) {
                return false;
            }

            this.pathCache.set(mailboxBuf.toString('hex'), mailboxId);
            this.idCache.set(mailboxId, mailboxBuf);
        }

        if (!mailboxBuf) {
            return false;
        }

        let path = mailboxBuf.slice(8).toString();
        return {
            path,
            uidValidity: mailboxBuf.readBigUInt64BE(0).toString(),
            uid
        };
    }

    async getMessageTextPaths(textId) {
        let buf = Buffer.from(textId.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let id = buf.slice(0, 8);
        let textParts = msgpack.decode(buf.slice(8));

        let message = await this.unpackUid(id);
        if (!message) {
            return { message: false };
        }

        return { message, textParts };
    }

    async clearMailboxEntry(entry) {
        this.checkIMAPConnection();

        if (!entry || !entry.path) {
            return; // ?
        }

        let mailbox;
        if (!this.mailboxes.has(normalizePath(entry.path))) {
            mailbox = new Mailbox(this, entry);
        } else {
            mailbox = this.mailboxes.get(normalizePath(entry.path));
        }

        await mailbox.clear();
        mailbox = false;
    }

    async getCurrentListing() {
        this.checkIMAPConnection();

        let listing = await this.imapClient.list();

        // ignore non-selectable folders
        listing = listing.filter(mailbox => !mailbox.flags.has('\\Noselect'));

        let hasChanges = false;

        // compare listing for new / deleted / renamed folders
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());
        storedListing = Object.keys(storedListing || {})
            .map(path => {
                try {
                    return msgpack.decode(storedListing[path]);
                } catch (err) {
                    // should not happen
                }
                return false;
            })
            .filter(entry => entry);

        // compare listings
        for (let mailbox of listing) {
            if (!storedListing.some(entry => normalizePath(entry.path) === normalizePath(mailbox.path))) {
                // found new!
                mailbox.isNew = true;
                hasChanges = true;
            }
        }

        for (let entry of storedListing) {
            if (!listing.some(mailbox => normalizePath(entry.path) === normalizePath(mailbox.path))) {
                // found deleted!
                await this.clearMailboxEntry(entry);
                hasChanges = true;
            }
        }

        // on changes store updated listing
        if (hasChanges) {
            // store
            let listingObject = {};
            listing.forEach(entry => {
                let mailbox = {};
                Object.keys(entry).forEach(key => {
                    if (['path', 'specialUse', 'name', 'listed', 'subscribed'].includes(key)) {
                        mailbox[key] = entry[key];
                    }
                });
                listingObject[normalizePath(entry.path)] = msgpack.encode(mailbox);
            });

            await this.redis.multi().del(this.getMailboxListKey()).hmset(this.getMailboxListKey(), listingObject).exec();
        }

        return listing;
    }

    periodicListRefresh() {
        if (this.closing || this.closed) {
            return false;
        }
        clearTimeout(this.refreshListingTimer);
        this.refreshListingTimer = setTimeout(() => {
            this.getCurrentListing()
                .then(listing => {
                    let syncNeeded = new Set();
                    for (let entry of listing) {
                        if (
                            // previously unseen
                            !this.mailboxes.has(normalizePath(entry.path))
                        ) {
                            if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                                // do not look for changes from this folder
                                entry.syncDisabled = true;
                            }

                            let mailbox = new Mailbox(this, entry);
                            this.mailboxes.set(normalizePath(entry.path), mailbox);
                            syncNeeded.add(mailbox);
                        }
                    }

                    let runSyncs = async () => {
                        // sync new mailboxes
                        for (let mailbox of syncNeeded) {
                            await mailbox.sync();
                        }
                    };

                    return runSyncs();
                })
                .catch(err => {
                    this.logger.error({ msg: 'List refresh error', err });
                })
                .finally(() => {
                    this.periodicListRefresh();
                });
        }, LIST_REFRESH_DELAY);
        this.refreshListingTimer.unref();
    }

    async connect() {
        if (this.closing || this.closed) {
            return false;
        }

        let imapClient = this.imapClient;

        // throws if connection fails
        let response = await imapClient.connect();

        let listing = await this.getCurrentListing();
        this.periodicListRefresh();

        // User might have disabled All Mail folder access and in that case we should treat it as a regular mailbox
        this.isGmail = imapClient.capabilities.has('X-GM-EXT-1') && listing.some(entry => entry.specialUse === '\\All');

        for (let entry of listing) {
            // In case of gmail prefer All mail folder as the folder to actively track
            if ((this.isGmail && entry.specialUse === '\\All') || (!this.isGmail && entry.specialUse === '\\Inbox')) {
                // idle in this folder
                this.main = entry;
            }

            if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                // do not look for changes from this folder
                entry.syncDisabled = true;
            }

            let mailbox = new Mailbox(this, entry);
            this.mailboxes.set(normalizePath(entry.path), mailbox);
        }

        imapClient.on('expunge', event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            mailbox.onExpunge(event).catch(err => {
                this.logger.error({ msg: 'Expunge error', err });
            });
        });

        // Process untagged EXISTS responses
        imapClient.on('exists', event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            mailbox.onExists(event).catch(err => {
                this.logger.error({ msg: 'Exists error', err });
            });
        });

        imapClient.on('mailboxOpen', event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            mailbox.onOpen(event).catch(err => {
                this.logger.error({ msg: 'Open error', err });
            });
        });

        imapClient.on('mailboxClose', event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            mailbox.onClose(event).catch(err => {
                this.logger.error({ msg: 'Close error', err });
            });
        });

        imapClient.on('flags', event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            mailbox.onFlags(event).catch(err => {
                this.logger.error({ msg: 'Flags error', err });
            });
        });

        imapClient.on('close', () => {
            let handler = async () => {
                for (let mailbox of this.mailboxes) {
                    if (mailbox.selected) {
                        // should be at most one though
                        await mailbox.onClose();
                    }
                }

                if (!imapClient.disabled) {
                    await this.reconnect();
                }
            };

            this.logger.info({ msg: 'Connection closed', account: this.account });
            handler().catch(err => {
                this.logger.error({ msg: 'Connection close error', err });
            });
        });

        return response;
    }

    async reconnect(force) {
        if (this._connecting || this.closing || (this.closed && !force)) {
            return false;
        }

        this._connecting = true;
        this.closed = false;

        try {
            await backOff(() => this.start(), {
                maxDelay: MAX_BACKOFF_DELAY,
                numOfAttempts: Infinity,
                retry: () => !this.closing && !this.closed,
                startingDelay: 2000
            });
        } finally {
            this._connecting = false;
        }

        try {
            await this.checkIMAPConnection();
            await this.syncMailboxes();
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up connection', err });
        }
    }

    async syncMailboxes() {
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        for (let mailbox of this.mailboxes.values()) {
            await mailbox.sync();
        }
        this.state = 'connected';
        await this.redis.hset(this.getAccountKey(), 'state', 'connected');

        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        // start waiting for changes
        await this.select(mainPath);

        // schedule next sync
        this.resyncTimer = setTimeout(() => {
            this.syncMailboxes().catch(err => {
                this.logger.error({ msg: 'Mailbox Sync Error', err });
            });
        }, RESYNC_DELAY);
    }

    async select(path) {
        if (!this.mailboxes.has(normalizePath(path))) {
            // nothing to do here, mailbox not found
            return;
        }

        let mailbox = this.mailboxes.get(normalizePath(path));
        await mailbox.select();
    }

    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substr(0, 20);
        }
        return rid;
    }

    async notify(mailbox, event, data) {
        switch (event) {
            case 'connectError':
            case 'authenticationError':
                return await this.setErrorState(event, data);
        }

        let payload = {
            account: this.account,
            date: new Date().toISOString()
        };

        let path = (mailbox && mailbox.path) || (data && data.path);
        if (path) {
            payload.path = path;
        }

        if (mailbox && mailbox.listingEntry && mailbox.listingEntry.specialUse) {
            payload.specialUse = mailbox.listingEntry.specialUse;
        }

        if (event) {
            payload.event = event;
        }

        if (data) {
            payload.data = data;
        }

        await this.notifyQueue.add(event, payload, {
            removeOnComplete: true,
            removeOnFail: true,
            attempts: 5,
            backoff: {
                type: 'exponential',
                delay: 2000
            }
        });
    }

    async start() {
        if (this.imapClient) {
            this.imapClient.disabled = true;
            try {
                this.imapClient.close();
            } catch (err) {
                this.logger.error({ msg: 'IMAP close error', err });
            } finally {
                this.imapClient = null;
            }
        }

        let accountData = await this.accountObject.loadAccountData();
        if (!accountData.imap) {
            // can not make connection
            this.state = 'unset';
            return;
        }

        let imapConfig = Object.assign(accountData.imap, this.imapConfig);

        // If authentication server is set then it overrides authentication data
        if (accountData.imap.useAuthServer) {
            try {
                accountData.imap.auth = await resolveCredentials(this.account, 'imap');
            } catch (err) {
                err.authenticationFailed = true;
                this.notify(false, 'authenticationError', {
                    response: err.message,
                    serverResponseCode: 'HTTPRequestError'
                });
                this.logger.error({
                    account: this.account,
                    err
                });
                this.state = 'authenticationError';
                throw err;
            }
        }

        this.imapClient = new ImapFlow(imapConfig);

        // if emitLogs option is true then separate log event is fired for every log entry
        this.imapClient.on('log', entry => {
            if (!entry) {
                return false;
            }

            if (typeof entry === 'string') {
                // should not happen
                entry = { msg: entry };
            }

            this.accountLogger.log(entry);
        });

        this.imapClient.on('error', err => {
            this.logger.error({ msg: 'IMAP connection error', account: this.account, err });
            this.reconnect().catch(err => {
                this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
            });
        });

        try {
            await this.connect();
            this.notify(false, 'authenticationSuccess', {
                user: imapConfig.auth.user
            });
        } catch (err) {
            if (err.authenticationFailed) {
                this.logger.error({ msg: 'Failed to authenticate', account: this.account, err });
                this.notify(false, 'authenticationError', {
                    response: err.response,
                    serverResponseCode: err.serverResponseCode
                });
                this.state = 'authenticationError';
            } else {
                this.logger.error({ msg: 'Failed to connect', account: this.account, err });
                this.notify(false, 'connectError', {
                    response: err.response || err.message,
                    serverResponseCode: err.serverResponseCode || err.code
                });
                this.state = 'connectError';
            }
            throw err;
        }
    }

    async init() {
        await this.reconnect();
    }

    async setErrorState(event, data) {
        await this.redis.hmset(this.getAccountKey(), {
            state: event,
            lastErrorState: JSON.stringify(data)
        });
    }

    async delete() {
        if (this.closed || this.closing) {
            return;
        }
        this.closing = true;

        if (this.imapClient) {
            this.imapClient.close();
        }

        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        try {
            for (let [, mailbox] of this.mailboxes) {
                await mailbox.clear({ skipNotify: true });
            }

            await this.redis.del(this.getMailboxListKey());
        } finally {
            this.closing = false;
            this.closed = true;
        }

        this.logger.info({ msg: 'Closed account', account: this.account });
    }

    async close() {
        this.state = 'disconnected';
        if (this.closed || this.closing) {
            return;
        }
        this.closing = true;

        if (this.imapClient) {
            this.imapClient.close();
        }

        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        this.closing = false;
        this.closed = true;
    }

    isConnected() {
        return this.imapClient && this.imapClient.usable && !this.closing && !this.closed;
    }

    currentState() {
        if (this.state === 'connected' && !this.isConnected()) {
            this.state = 'disconnected';
        }
        return this.state;
    }

    checkIMAPConnection() {
        if (!this.isConnected()) {
            let err = new Error('IMAP connection temporarily not available');
            err.code = 'IMAPUnavailable';
            err.statusCode = 503;
            throw err;
        }
    }

    // Mailbox level user methods

    /**
     * Fetch message text from IMAP. Resulting value is a unicode string.
     *
     * @param {string} textId ID of the text content
     * @param {object} [options] Options object
     * @param {number} [options.maxLength] If set then limits output stream to specified chars (NB! not bytes but unicode characters). Limit applies to each text type separately, so 1000 would mean you'd get a 1000 char string for plaintext and 1000 char string for html.
     * @param {string} [options.contentType] If set then limits output for selected type only
     * @returns {Object} Text object, where key is text type (either 'plain' or 'html') and value is a unicode string
     */
    async getText(textId, options) {
        options = options || {};
        this.checkIMAPConnection();

        let { message, textParts } = await this.getMessageTextPaths(textId);
        if (!message || !textParts || !textParts.length) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        let textType = (options.textType || '').toLowerCase().trim();

        if (Array.isArray(textParts)) {
            let re = /^\d+(\.\d+)*$/;
            switch (textType) {
                case 'plain':
                    textParts = Array.isArray(textParts[0]) ? textParts[0].filter(entry => re.test(entry)) : false;
                    break;
                case 'html':
                    textParts = Array.isArray(textParts[1]) ? textParts[1].filter(entry => re.test(entry)) : false;
                    break;
                default:
                    textParts = textParts.flatMap(part => part).filter(entry => re.test(entry));
                    break;
            }
        } else {
            textParts = [];
        }

        let result = await mailbox.getText(message, textParts, options);

        if (textType && textType !== '*') {
            result = {
                [textType]: result[textType] || '',
                hasMore: result.hasMore
            };
        }

        return result;
    }

    async getMessage(id, options) {
        options = options || {};
        this.checkIMAPConnection();

        let buf = Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let message = await this.unpackUid(buf.slice(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));
        return await mailbox.getMessage(message, options);
    }

    async updateMessage(id, updates) {
        updates = updates || {};
        this.checkIMAPConnection();

        let buf = Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let message = await this.unpackUid(buf.slice(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.updateMessage(message, updates);
    }

    async moveMessage(id, target) {
        target = target || {};

        this.checkIMAPConnection();

        let buf = Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let message = await this.unpackUid(buf.slice(0, 8));

        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));
        return await mailbox.moveMessage(message, target);
    }

    async deleteMessage(id) {
        this.checkIMAPConnection();

        let buf = Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let message = await this.unpackUid(buf.slice(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.deleteMessage(message);
    }

    /**
     * Downloads an attachment from IMAP as a binary stream
     *
     * @param {string} attachmentId ID of the attachment
     * @param {object} [options] Options object
     * @param {number} [options.maxLength] If set then limits output stream to specified bytes
     * @returns {Boolean|Stream} Attahcment stream or `false` if not found
     */
    async getAttachment(attachmentId, options) {
        this.checkIMAPConnection();

        let buf = Buffer.from(attachmentId.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let id = buf.slice(0, 8);
        let part = buf.slice(8).toString();

        let message = await this.unpackUid(id);
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return mailbox.getAttachment(message, part, options);
    }

    /**
     * Downloads raw message from IMAP as a binary stream
     *
     * @param {string} id ID of the message
     * @param {object} [options] Options object
     * @param {number} [options.maxLength] If set then limits output stream to specified bytes
     * @returns {Boolean|Stream} Attahcment stream or `false` if not found
     */
    async getRawMessage(id, options) {
        this.checkIMAPConnection();

        let buf = Buffer.from(id.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        let message = await this.unpackUid(buf.slice(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return mailbox.getAttachment(message, false, options);
    }

    async listMessages(options) {
        options = options || {};
        this.checkIMAPConnection();

        if (!this.mailboxes.has(normalizePath(options.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(options.path));

        return mailbox.listMessages(options);
    }

    async buildContacts() {
        this.checkIMAPConnection();

        let addresses = [];
        let addressesMap = new Map();

        for (let [, mailbox] of this.mailboxes) {
            if ((this.isGmail && mailbox.listingEntry.specialUse !== '\\All') || ['\\Junk', '\\Trash'].includes(mailbox.listingEntry.specialUse)) {
                // Only look into All Mail for Gmail account, ignore Junk/Trash for other account
                continue;
            }

            let result = await mailbox.buildContacts();
            for (let address of result) {
                if (!address.address) {
                    continue;
                }

                address.address = address.address.replace(/\+[^@]*@/, '@');

                if (!addressesMap.has(address.address)) {
                    addressesMap.set(
                        address.address,
                        new Map([
                            ['count', 0],
                            ['names', new Map()],
                            [
                                'types',
                                new Map([
                                    ['from', 0],
                                    ['to', 0],
                                    ['cc', 0]
                                ])
                            ]
                        ])
                    );
                }

                let addressMap = addressesMap.get(address.address);

                addressMap.set('count', addressMap.get('count') + 1);

                let typeMap = addressMap.get('types');
                if (typeMap.has(address.type)) {
                    typeMap.set(address.type, typeMap.get(address.type) + 1);
                } else {
                    typeMap.set(address.type, 1);
                }

                if (address.name) {
                    let nameMap = addressMap.get('names');
                    if (nameMap.has(address.name)) {
                        nameMap.set(address.name, nameMap.get(address.name) + 1);
                    } else {
                        nameMap.set(address.name, 1);
                    }
                }
            }
        }

        for (let [address, data] of addressesMap) {
            let names = data.has('names') ? Object.fromEntries(data.get('names').entries()) : {};
            let mainName = { name: '', count: -1 };

            if (data.has('names')) {
                for (let [name, count] of data.get('names')) {
                    if (name && count > mainName.count) {
                        mainName = {
                            name,
                            count
                        };
                    }
                }
            }

            addresses.push({
                address,
                name: mainName.name,
                count: data.get('count'),
                names,
                types: data.has('types') ? Object.fromEntries(data.get('types').entries()) : {}
            });
        }

        addresses.sort((a, b) => b.count - a.count);
        return { addresses };
    }

    async deleteMailbox(path) {
        this.checkIMAPConnection();

        let result = {
            path,
            deleted: false // set to true if mailbox is actually deleted
        };
        try {
            let lock = await this.imapClient.getMailboxLock(path);

            try {
                await this.imapClient.mailboxClose();
                try {
                    await this.imapClient.mailboxDelete(path);
                    result.deleted = true;
                } catch (err) {
                    // kind of ignore
                }
            } finally {
                lock.release();
            }
        } catch (err) {
            this.logger.debug({ msg: 'Mailbox select error', path, err });
        }

        if (this.mailboxes.has(normalizePath(path))) {
            let mailbox = this.mailboxes.get(normalizePath(path));
            await mailbox.clear();
        }

        return result;
    }

    async createMailbox(path) {
        this.checkIMAPConnection();
        let result = await this.imapClient.mailboxCreate(path);
        if (result) {
            result.created = !!result.created;
        }

        setImmediate(() => {
            this.getCurrentListing()
                .then(listing => {
                    let syncNeeded = new Set();
                    for (let entry of listing) {
                        if (
                            // previously unseen
                            !this.mailboxes.has(normalizePath(entry.path))
                        ) {
                            if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                                // do not look for changes from this folder
                                entry.syncDisabled = true;
                            }
                            let mailbox = new Mailbox(this, entry);
                            this.mailboxes.set(normalizePath(entry.path), mailbox);
                            syncNeeded.add(mailbox);
                        }
                    }

                    let runSyncs = async () => {
                        // sync new mailboxes
                        for (let mailbox of syncNeeded) {
                            await mailbox.sync();
                        }
                    };

                    return runSyncs();
                })
                .catch(err => {
                    this.logger.error({ msg: 'List refresh error', err });
                });
        });

        return result;
    }

    async getSpecialUseMailbox(specialUse) {
        let storedListing = await this.redis.hgetallBuffer(this.getMailboxListKey());
        return Object.keys(storedListing || {})
            .map(path => {
                try {
                    return msgpack.decode(storedListing[path]);
                } catch (err) {
                    // should not happen
                }
                return false;
            })
            .filter(entry => entry)
            .find(entry => entry.specialUse === specialUse);
    }

    async submitMessage(data) {
        this.checkIMAPConnection();

        let accountData = await this.accountObject.loadAccountData();
        if (!accountData.smtp) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        data.disableFileAccess = true;
        data.disableUrlAccess = true;

        // convert data uri images to attachments
        data.attachDataUrls = true;

        let envelope = {
            from: data.from.address,
            to: []
                .concat(data.to || [])
                .concat(data.cc || [])
                .concat(data.bcc || [])
                .flatMap(addr => addr.address)
        };

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            let referencedMessage = await this.getMessage(data.reference.message, {
                fields: {
                    uid: true,
                    flags: true,
                    envelope: true,
                    headers: ['references']
                }
            });

            if (!referencedMessage) {
                let err = new Error('Referenced message was not found');
                err.code = 'MessageNotFound';
                err.statusCode = 404;
                throw err;
            }

            let references = []
                .concat(referencedMessage.messageId || [])
                .concat(referencedMessage.inReplyTo || [])
                .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                .flatMap(line => line.split(/\s+/))
                .map(ref => ref.trim())
                .filter(ref => ref)
                .map(ref => {
                    if (!/^</.test(ref)) {
                        ref = '<' + ref;
                    }
                    if (!/>$/.test(ref)) {
                        ref = ref + '>';
                    }
                    return ref;
                });

            references = Array.from(new Set(references));
            if (references.length) {
                if (!data.headers) {
                    data.headers = {};
                }
                data.headers.references = references.join(' ');
            }

            if (data.reference.action === 'reply' && referencedMessage.messageId) {
                data.headers['in-reply-to'] = referencedMessage.messageId;
            }

            if (!referencedMessage.flags || !referencedMessage.flags.includes('\\Answered')) {
                try {
                    await this.updateMessage(data.reference.message, {
                        flags: {
                            add: ['\\Answered']
                        }
                    });
                } catch (err) {
                    this.logger.error(err);
                }
            }

            if (!data.subject && referencedMessage.subject) {
                let subject = referencedMessage.subject;
                let prefix;
                switch (data.reference.action) {
                    case 'reply':
                        if (!/^Re:/i.test(subject)) {
                            prefix = 'Re';
                        }
                        break;
                    case 'forward':
                        if (!/^Fwd:/i.test(subject)) {
                            prefix = 'Fwd';
                        }
                        break;
                }
                data.subject = `${prefix ? prefix + ': ' : ''}${subject}`;
            }
        }

        const mail = new MailComposer(data);
        let raw = await mail.compile().build();

        let smtpAuth = accountData.smtp.auth;
        // If authentication server is set then it overrides authentication data
        if (accountData.smtp.useAuthServer) {
            try {
                smtpAuth = await resolveCredentials(this.account, 'smtp');
            } catch (err) {
                err.authenticationFailed = true;
                this.logger.error({
                    account: this.account,
                    err
                });
                throw err;
            }
        }

        let smtpSettings = Object.assign({}, accountData.smtp);

        smtpSettings.auth = {
            user: smtpAuth.user
        };

        if (smtpAuth.accessToken) {
            smtpSettings.auth.type = 'OAuth2';
            smtpSettings.auth.accessToken = smtpAuth.accessToken;
        } else {
            smtpSettings.auth.pass = smtpAuth.pass;
        }

        const transporter = nodemailer.createTransport(smtpSettings);
        try {
            const info = await transporter.sendMail({
                envelope,
                raw
            });

            if (!this.isGmail) {
                // Upload message to Sent Mail folder. Gmail does this automatically.
                try {
                    let sentMailbox = await this.getSpecialUseMailbox('\\Sent');
                    if (sentMailbox) {
                        await this.imapClient.append(sentMailbox.path, raw, ['\\Seen']);
                    }
                } catch (err) {
                    // not really interested if upload fails
                }
            }

            return {
                response: info.response,
                messageId: info.messageId
            };
        } catch (err) {
            err.code = 'SubmitFail';
            err.statusCode = 502;
            throw err;
        }
    }

    getLogger() {
        this.mainLogger =
            this.options.logger ||
            logger.child({
                component: 'imap-client',
                account: this.account,
                cid: this.cid
            });

        let synteticLogger = {};
        let levels = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
        for (let level of levels) {
            synteticLogger[level] = (...args) => {
                this.mainLogger[level](...args);

                if (this.emitLogs && args && args[0] && typeof args[0] === 'object') {
                    let entry = Object.assign({ level, t: Date.now(), cid: this.cid }, args[0]);
                    if (entry.err && typeof entry.err === 'object') {
                        let err = entry.err;
                        entry.err = {
                            stack: err.stack
                        };
                        // enumerable error fields
                        Object.keys(err).forEach(key => {
                            entry.err[key] = err[key];
                        });
                    }

                    this.accountLogger.log(entry);
                }
            };
        }
        return synteticLogger;
    }
}

module.exports.Connection = Connection;
