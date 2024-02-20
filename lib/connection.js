'use strict';

const { parentPort } = require('worker_threads');
const { ImapFlow } = require('imapflow');
const { Mailbox } = require('./mailbox');
const logger = require('./logger');
const crypto = require('crypto');
const punycode = require('punycode/');
const packageData = require('../package.json');
const { backOff } = require('exponential-backoff');
const msgpack = require('msgpack5')();
const nodemailer = require('nodemailer');
const util = require('util');
const { getRawEmail, removeBcc } = require('./get-raw-email');
const { deepEqual } = require('assert');
const os = require('os');
const socks = require('socks');
const { getTemplate } = require('@postalsys/templates');
const { templates } = require('./templates');
const { Gateway } = require('./gateway');
const { webhooks: Webhooks } = require('./webhooks');
const { inlineHtml, inlineText, htmlToText } = require('@postalsys/email-text-tools');
const uuid = require('uuid');
const { oauth2Apps, oauth2ProviderData } = require('./oauth2-apps');
const { getESClient } = require('./document-store');
const { getThread } = require('./threads');
const featureFlags = require('./feature-flags');

const { Subconnection } = require('./subconnection');

const {
    getSignedFormDataSync,
    getServiceSecret,
    getLocalAddress,
    normalizePath,
    resolveCredentials,
    emitChangeEvent,
    convertDataUrisToAtachments,
    getByteSize,
    getBoolean,
    readEnvValue,
    validUidValidity,
    getDuration
} = require('./tools');

const RESYNC_DELAY = 15 * 60;
const ENSURE_MAIN_TTL = 5 * 1000;

const {
    AUTH_ERROR_NOTIFY,
    AUTH_SUCCESS_NOTIFY,
    CONNECT_ERROR_NOTIFY,
    EMAIL_SENT_NOTIFY,
    EMAIL_DELIVERY_ERROR_NOTIFY,
    ACCOUNT_INITIALIZED_NOTIFY,
    REDIS_PREFIX,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    DEFAULT_DOWNLOAD_CHUNK_SIZE,
    MAILBOX_DELETED_NOTIFY,
    MAX_BACKOFF_DELAY,
    TLS_DEFAULTS,
    DEFAULT_DELIVERY_ATTEMPTS
} = require('./consts');

const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;
const DISABLE_IMAP_COMPRESSION = getBoolean(readEnvValue('EENGINE_DISABLE_COMPRESSION'));
const IMAP_SOCKET_TIMEOUT = getDuration(readEnvValue('EENGINE_IMAP_SOCKET_TIMEOUT'));

logger.trace({ msg: 'Worker configuration', DOWNLOAD_CHUNK_SIZE, DISABLE_IMAP_COMPRESSION, IMAP_SOCKET_TIMEOUT });

const settings = require('./settings');
const { redis } = require('./db');
const { addTrackers } = require('./add-trackers');

async function metricsMeta(meta, logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args,
            meta: meta || {}
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

class Connection {
    constructor(options) {
        this.options = options || {};

        this.account = this.options.account || '';
        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;

        this.secret = this.options.secret;

        this.cid = this.getRandomId();

        this.isClosing = false;
        this.isClosed = false;

        this.call = options.call;

        this.logger = this.getLogger();

        this.imapConfig = {
            // Set emitLogs to true if you want to get all the log entries as objects from the IMAP module
            logger: this.mainLogger.child({
                sub: 'imap-connection',
                channel: 'primary'
            }),
            clientInfo: {
                name: packageData.name,
                version: packageData.version,
                vendor: (packageData.author && packageData.author.name) || packageData.author,
                'support-url': (packageData.bugs && packageData.bugs.url) || packageData.bugs
            },
            logRaw: this.options.logRaw
        };

        this.mailboxes = new Map();
        this.untaggedExistsTimer = false;
        this.redis = options.redis;

        this.notifyQueue = options.notifyQueue;
        this.submitQueue = options.submitQueue;
        this.documentsQueue = options.documentsQueue;
        this.flowProducer = options.flowProducer;

        this.refreshListingTimer = false;
        this.resyncTimer = false;

        this.completedTimer = false;

        this.pathCache = new Map();
        this.idCache = new Map();

        this.defaultDelimiter = '/';

        this.subconnections = [];

        this.paused = false;

        this.imapClient = null;
        this.commandClient = null;

        this.syncing = false;

        this.state = 'connecting';
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    onTaskCompleted() {
        // check if we need to re-select main mailbox
        this.completedTimer = setTimeout(() => {
            clearTimeout(this.completedTimer);
            this.ensureMainMailbox().catch(err => this.logger.error({ msg: 'Failed to select main mailbox', err }));
        }, ENSURE_MAIN_TTL);
    }

    async getImapConnection(allowSecondary) {
        let syncing = this.syncing || ['init', 'connecting', 'syncing'].includes(this.state);
        if (!syncing || !allowSecondary) {
            return this.imapClient;
        }

        try {
            const connectionClient = await this.getCommandConnection();
            return connectionClient && connectionClient.usable ? connectionClient : this.imapClient;
        } catch (err) {
            return this.imapClient;
        }
    }

    async getCommandConnection() {
        if (this.commandClient && this.commandClient.usable) {
            // use existing command channel
            return this.commandClient;
        }

        let lock = this.accountObject.getLock();

        let connectLock;
        let lockKey = ['commandCient', this.account].join(':');

        try {
            connectLock = await lock.waitAcquireLock(lockKey, 5 * 60 * 1000, 1 * 60 * 1000);
            if (!connectLock.success) {
                this.logger.error({ msg: 'Failed to get lock', lockKey });
                throw new Error('Failed to get connection lock');
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to get lock', lockKey, err });
            throw err;
        }

        try {
            // create a new connection for the command channel
            let accountData = await this.accountObject.loadAccountData();

            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                return null;
            }

            const commandCid = `${this.cid}:c`;

            let imapConfig = await this.getImapConfig(accountData);

            this.commandClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    disableAutoIdle: true,
                    id: commandCid,
                    logger: this.logger.child({
                        channel: 'command'
                    })
                })
            );

            this.commandClient.secondaryConnection = true;

            try {
                await this.commandClient.connect();
                this.logger.info({ msg: 'Command channel connected', cid: commandCid, channel: 'command', account: this.account });
            } catch (err) {
                this.logger.error({ msg: 'Failed to connect command client', cid: commandCid, channel: 'command', account: this.account, err });
                throw err;
            }

            this.commandClient.on('error', err => {
                this.logger.error({ msg: 'IMAP connection error', cid: commandCid, channel: 'command', account: this.account, err });
                this.commandClient = null;
            });

            this.commandClient.on('close', async () => {
                this.logger.info({ msg: 'Connection closed', cid: commandCid, channel: 'command', account: this.account });
                this.commandClient = null;
            });

            return this.commandClient;
        } finally {
            await lock.releaseLock(connectLock);
        }
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
        if (!validUidValidity(storedStatus.uidValidity) || !storedStatus.path) {
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

        let res = uidBuf.toString('base64url');

        return res;
    }

    async unpackUid(id) {
        const packed = Buffer.isBuffer(id) ? id : Buffer.from(id, 'base64url');

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

        let path = mailboxBuf.subarray(8).toString();
        return {
            path,
            uidValidity: mailboxBuf.readBigUInt64BE(0).toString(),
            uid
        };
    }

    async getMessageTextPaths(textId) {
        let buf = Buffer.from(textId, 'base64url');
        let id = buf.subarray(0, 8);
        let textParts = msgpack.decode(buf.subarray(8));

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

    async getCurrentListing(options) {
        this.checkIMAPConnection();

        let accountData = await this.accountObject.loadAccountData();
        let specialUseHints = {};

        for (let type of ['sent', 'drafts', 'junk', 'trash', 'archive']) {
            if (accountData.imap && accountData.imap[`${type}MailPath`]) {
                specialUseHints[type] = accountData.imap[`${type}MailPath`];
            }
        }

        options = Object.assign({}, options, {
            specialUseHints
        });

        let listing = await this.imapClient.list(options);

        let inboxData = (listing || []).find(entry => /^INBOX$/i.test(entry.path));
        if (inboxData && inboxData.delimiter) {
            this.defaultDelimiter = inboxData.delimiter;
        }

        // ignore non-selectable folders
        listing = listing
            .filter(mailbox => !mailbox.flags.has('\\Noselect'))
            .map(mailbox => {
                mailbox.noInferiors = mailbox.flags.has('\\Noinferiors');
                return mailbox;
            });

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
            let existingMailbox = storedListing.find(entry => normalizePath(entry.path) === normalizePath(mailbox.path));
            if (!existingMailbox) {
                // found new!
                mailbox.isNew = true;
                hasChanges = true;
            } else if (
                existingMailbox.delimiter !== mailbox.delimiter ||
                existingMailbox.specialUseSource !== mailbox.specialUseSource ||
                existingMailbox.noInferiors !== mailbox.noInferiors
            ) {
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
                    if (['path', 'specialUse', 'name', 'listed', 'subscribed', 'delimiter', 'specialUseSource', 'noInferiors'].includes(key)) {
                        mailbox[key] = entry[key];
                    }
                });
                listingObject[normalizePath(entry.path)] = msgpack.encode(mailbox);
            });

            await this.redis.multi().del(this.getMailboxListKey()).hmset(this.getMailboxListKey(), listingObject).exec();
        }

        return listing;
    }

    async refreshFolderList() {
        if (this.refreshingList) {
            return;
        }
        this.refreshingList = true;

        try {
            let accountData = await this.accountObject.loadAccountData();
            let listing = await this.getCurrentListing();

            let syncNeeded = new Set();
            for (let entry of listing) {
                if (
                    // previously unseen
                    !this.mailboxes.has(normalizePath(entry.path))
                ) {
                    if (accountData.path && accountData.path !== '*') {
                        if (accountData.path !== entry.path && accountData.path !== entry.specialUse) {
                            // ignore changes
                            entry.syncDisabled = true;
                        }
                    } else if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                        // do not look for changes from this folder
                        entry.syncDisabled = true;
                    }

                    let mailbox = new Mailbox(this, entry);
                    this.mailboxes.set(normalizePath(entry.path), mailbox);
                    syncNeeded.add(mailbox);
                }
            }

            // sync new mailboxes
            for (let mailbox of syncNeeded) {
                await mailbox.sync(true);
            }

            return syncNeeded;
        } finally {
            this.refreshingList = false;
        }
    }

    async connect() {
        if (this.isClosing || this.isClosed) {
            return false;
        }

        let imapClient = this.imapClient;

        let accountData = await this.accountObject.loadAccountData();

        // throws if connection fails
        let response = await imapClient.connect();

        this.state = 'syncing';
        await this.setStateVal();
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        let listing = await this.getCurrentListing();

        // User might have disabled All Mail folder access and in that case we should treat it as a regular mailbox
        this.isGmail = imapClient.capabilities.has('X-GM-EXT-1') && listing.some(entry => entry.specialUse === '\\All');
        this.isOutlook = /\boffice365\.com$/i.test(imapClient.host); // || /The Microsoft Exchange IMAP4 service is ready/.test(imapClient.greeting);

        for (let entry of listing) {
            if (accountData.path && accountData.path !== '*') {
                if (accountData.path !== entry.path && accountData.path !== entry.specialUse) {
                    entry.syncDisabled = true;
                } else {
                    this.main = entry;
                }
            } else {
                if ((this.isGmail && entry.specialUse === '\\All') || (!this.isGmail && entry.specialUse === '\\Inbox')) {
                    // In case of gmail prefer All mail folder as the folder to actively track, otherwise INBOX
                    // idle in this folder
                    this.main = entry;
                }

                if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                    // do not look for changes from this folder
                    entry.syncDisabled = true;
                }
            }

            let mailbox = new Mailbox(this, entry);
            this.mailboxes.set(normalizePath(entry.path), mailbox);
        }

        // Process untagged EXISTS responses
        imapClient.on('exists', async event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            try {
                await mailbox.onExists(event);
            } catch (err) {
                this.logger.error({ msg: 'Exists error', err });
            }
        });

        imapClient.on('mailboxOpen', async event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            try {
                await mailbox.onOpen(event);
            } catch (err) {
                this.logger.error({ msg: 'Open error', err });
            }
        });

        imapClient.on('mailboxClose', async event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            try {
                await mailbox.onClose(event);
            } catch (err) {
                this.logger.error({ msg: 'Close error', err });
            }
        });

        imapClient.on('flags', async event => {
            if (!event || !event.path || !this.mailboxes.has(normalizePath(event.path))) {
                return; //?
            }

            let mailbox = this.mailboxes.get(normalizePath(event.path));
            try {
                await mailbox.onFlags(event);
            } catch (err) {
                this.logger.error({ msg: 'Flags error', err });
            }
        });

        imapClient.on('close', async () => {
            this.logger.info({ msg: 'Connection closed', type: 'imapClient', account: this.account });

            try {
                for (let mailbox of this.mailboxes) {
                    if (mailbox.selected) {
                        // should be at most one though
                        await mailbox.onClose();
                    }
                }

                if (!imapClient.disabled) {
                    await this.reconnect();
                }
            } catch (err) {
                this.logger.error({ msg: 'Connection close error', err });
            }
        });

        return response;
    }

    async reconnect(force) {
        if (this.paused || this._connecting || this.isClosing || (this.isClosed && !force)) {
            return false;
        }

        this._connecting = true;
        this.isClosed = false;

        if (force) {
            this.closeSubconnections();
            if (this.connectionClient) {
                this.connectionClient.close();
            }
        }

        try {
            await backOff(() => this.start(), {
                maxDelay: MAX_BACKOFF_DELAY,
                numOfAttempts: Infinity,
                retry: () => !this.isClosing && !this.isClosed,
                startingDelay: 2000
            });
        } finally {
            this._connecting = false;
        }

        if (this.paused) {
            return;
        }

        if (this.state === 'unset') {
            return;
        }

        try {
            await this.checkIMAPConnection();
            await this.syncMailboxes();
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up connection', err });
        }
    }

    async setStateVal() {
        let [[e1], [e2, prevVal], [e3, incrVal], [e4, stateVal]] = await this.redis
            .multi()
            .hSetExists(this.getAccountKey(), 'state', this.state)
            .hget(this.getAccountKey(), `state:count:${this.state}`)
            .hIncrbyExists(this.getAccountKey(), `state:count:${this.state}`, 1)
            .hget(this.getAccountKey(), 'state')
            .exec();

        if (e1 || e2 || e3 || e4) {
            throw e1 || e2 || e3 || e4;
        }

        if (stateVal === 'connected' && incrVal === 1 && prevVal === '0') {
            // first connected event!
            await this.notify(false, ACCOUNT_INITIALIZED_NOTIFY, {
                initialized: true
            });
        }
    }

    async syncMailboxes() {
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        if (!this.imapClient) {
            return;
        }

        let synced = await this.refreshFolderList();
        for (let mailbox of this.mailboxes.values()) {
            if (!synced || !synced.has(mailbox)) {
                await mailbox.sync();
            }
        }

        if (!this.imapClient) {
            return;
        }

        this.state = 'connected';

        await this.setStateVal();

        const capabilities = (this.imapClient.rawCapabilities || []).map(entry => entry && entry.value).filter(entry => entry);
        const authCapabilities = [];
        let lastUsedAuthCapability = null;
        if (this.imapClient.authCapabilities) {
            for (let [authCapa, usedAuth] of this.imapClient.authCapabilities) {
                authCapabilities.push(authCapa);
                if (usedAuth) {
                    lastUsedAuthCapability = authCapa;
                }
            }
        }

        const serverInfo = Object.assign({}, this.imapClient.serverInfo || {}, {
            capabilities,
            authCapabilities,
            lastUsedAuthCapability
        });

        await this.redis.hSetExists(this.getAccountKey(), 'imapServerInfo', JSON.stringify(serverInfo));
        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', '{}');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        // start waiting for changes
        await this.select(mainPath);

        // schedule next sync
        clearTimeout(this.resyncTimer);
        this.resyncTimer = setTimeout(() => {
            this.syncMailboxes().catch(err => {
                this.logger.error({ msg: 'Mailbox Sync Error', err });
            });
        }, this.resyncDelay);
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

    async notify(mailbox, event, data, extraOpts) {
        extraOpts = extraOpts || {};
        const { skipWebhook, canSync = true } = extraOpts;

        metricsMeta({ account: this.account }, this.logger, 'events', 'inc', {
            event
        });

        switch (event) {
            case 'connectError':
            case 'authenticationError': {
                let shouldNotify = await this.setErrorState(event, data);

                if (!shouldNotify) {
                    // do not send a webhook as nothing really changed
                    return;
                }
                break;
            }
        }

        let serviceUrl = (await settings.get('serviceUrl')) || true;

        let payload = {
            serviceUrl,
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

        let queueKeep = (await settings.get('queueKeep')) || true;

        let addDocumentQueueJob =
            canSync &&
            this.documentsQueue &&
            [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY].includes(event) &&
            (await settings.get('documentStoreEnabled'));

        if (addDocumentQueueJob && payload.data && event === MESSAGE_NEW_NOTIFY && !payload.data.threadId) {
            // Generate a thread ID for the email. This is also stored in ElasticSearch.
            const { index, client } = await getESClient(logger);
            try {
                if (client) {
                    let thread = await getThread(client, index, this.account, payload.data, logger);
                    if (thread) {
                        payload.data.threadId = thread;
                        logger.info({
                            msg: 'Provisioned thread ID for a message',
                            account: this.account,
                            message: payload.data.id,
                            threadId: payload.data.threadId
                        });
                    }
                }
            } catch (err) {
                if (logger.notifyError) {
                    logger.notifyError(err, event => {
                        event.setUser(this.account);
                        event.addMetadata('ee', {
                            index
                        });
                    });
                }
                logger.error({ msg: 'Failed to resolve thread', account: this.account, message: payload.data.id, err });
            }
        }

        const defaultJobOptions = {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: 10,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        // use more attempts for ElasticSearch updates
        const documentJobOptions = Object.assign(pfStructuredClone(defaultJobOptions), { attempts: 16 });

        if (!skipWebhook && addDocumentQueueJob) {
            // add both jobs as a Flow

            let notifyPayload = await Webhooks.formatPayload(event, payload);

            const queueFlow = [
                {
                    name: event,
                    data: payload,
                    queueName: 'documents'
                }
            ];

            await Webhooks.pushToQueue(event, notifyPayload, {
                routesOnly: true,
                queueFlow
            });

            await this.flowProducer.add(
                {
                    name: event,
                    data: notifyPayload,
                    queueName: 'notify',
                    children: queueFlow
                },
                {
                    queuesOptions: {
                        notify: {
                            defaultJobOptions
                        },
                        documents: {
                            defaultJobOptions: documentJobOptions
                        }
                    }
                }
            );
        } else {
            // add to queues as normal jobs

            if (!skipWebhook) {
                await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
            }

            if (addDocumentQueueJob) {
                await this.documentsQueue.add(event, payload, documentJobOptions);
            }
        }
    }

    async getImapConfig(accountData, ctx) {
        if (!accountData) {
            accountData = await this.accountObject.loadAccountData();
        }

        // the same method is also called by subconnections, so do not mark the primary connection as failing if something happens
        ctx = ctx || this;

        let imapConnectionConfig;
        if (accountData.oauth2 && accountData.oauth2.auth) {
            // load OAuth2 tokens
            let now = Date.now();
            let accessToken;
            if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
                // renew access token
                try {
                    accountData = await this.accountObject.renewAccessToken({
                        logger: this.logger,
                        logRaw: this.options.logRaw
                    });
                    accessToken = accountData.oauth2.accessToken;
                } catch (err) {
                    err.authenticationFailed = true;
                    let notifyData = {
                        response: err.message,
                        serverResponseCode: 'OauthRenewError'
                    };
                    if (err.tokenRequest) {
                        notifyData.tokenRequest = err.tokenRequest;
                    }
                    await ctx.notify(false, AUTH_ERROR_NOTIFY, notifyData);
                    ctx.logger.error({
                        account: this.account,
                        err
                    });
                    ctx.state = AUTH_ERROR_NOTIFY;
                    throw err;
                }
            } else {
                this.logger.info({
                    msg: 'Using cached OAuth2 access token',
                    action: 'ensureAccessToken',
                    target: 'imap',
                    error: null,
                    user: accountData.oauth2.auth.user,
                    expires: accountData.oauth2.expires,
                    scopes: accountData.oauth2.scope,
                    oauth2App: accountData.oauth2.provider
                });
                accessToken = accountData.oauth2.accessToken;
            }

            const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                throw new Error('Missing or disabled OAuth2 app');
            }
            const providerData = oauth2ProviderData(oauth2App.provider);

            let oauth2User = accountData.oauth2.auth.delegatedUser || accountData.oauth2.auth.user;

            if (featureFlags.enabled('gmail api')) {
                if (oauth2App.baseScopes === 'api') {
                    return {
                        type: 'api',
                        app: oauth2App.id,
                        provider: providerData.provider,
                        user: oauth2User,
                        accessToken
                    };
                }
            }

            imapConnectionConfig = Object.assign(
                {
                    auth: {
                        user: oauth2User,
                        accessToken
                    },
                    resyncDelay: 900
                },
                providerData.imap || {}
            );
        } else {
            // deep copy of imap settings
            imapConnectionConfig = JSON.parse(JSON.stringify(accountData.imap));
        }

        // If authentication server is set then it overrides authentication data
        if (imapConnectionConfig.useAuthServer) {
            try {
                imapConnectionConfig.auth = await resolveCredentials(this.account, 'imap');
            } catch (err) {
                err.authenticationFailed = true;
                await ctx.notify(false, AUTH_ERROR_NOTIFY, {
                    response: err.message,
                    serverResponseCode: 'HTTPRequestError'
                });
                ctx.logger.error({
                    account: this.account,
                    err
                });
                ctx.state = AUTH_ERROR_NOTIFY;
                throw err;
            }
        }

        if (!imapConnectionConfig.tls) {
            imapConnectionConfig.tls = {};
        }
        imapConnectionConfig.tls.localAddress = (await getLocalAddress(redis, 'imap', this.account)).localAddress;

        for (let key of Object.keys(TLS_DEFAULTS)) {
            if (!(key in imapConnectionConfig.tls)) {
                imapConnectionConfig.tls[key] = TLS_DEFAULTS[key];
            }
        }

        // reload log config
        await this.accountLogger.reload();

        let imapConfig = Object.assign(
            {
                resyncDelay: RESYNC_DELAY,
                id: this.cid,
                emitLogs: this.accountLogger.enabled
            },
            imapConnectionConfig,
            this.imapConfig
        );
        this.resyncDelay = imapConfig.resyncDelay * 1000;

        // set up proxy if needed
        if (accountData.proxy) {
            imapConfig.proxy = accountData.proxy;
        } else {
            let proxyUrl = await settings.get('proxyUrl');
            let proxyEnabled = await settings.get('proxyEnabled');
            if (proxyEnabled && proxyUrl && !imapConfig.proxy) {
                imapConfig.proxy = proxyUrl;
            }
        }

        if (/(\.rambler\.ru|\.163\.com)$/i.test(imapConfig.host)) {
            // Special case for Rambler and 163. Break IDLE at least once a minute
            imapConfig.maxIdleTime = 55 * 1000;
        } else if (/\.yahoo\.com$/i.test(imapConfig.host)) {
            // Special case for Yahoo. Break IDLE at least once every three minutes
            imapConfig.maxIdleTime = 3 * 60 * 1000;
        }

        /*
        else if (/(\.naver\.com)$/i.test(imapConfig.host)) {
            // NOOP does nothing in Naver, must run SELECT for changes in the folder to apply
            imapConfig.maxIdleTime = 55 * 1000;
            imapConfig.missingIdleCommand = 'SELECT';
        }
        */

        if (DISABLE_IMAP_COMPRESSION) {
            imapConfig.disableCompression = true;
        }

        if (IMAP_SOCKET_TIMEOUT) {
            imapConfig.socketTimeout = IMAP_SOCKET_TIMEOUT;
        }

        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
        if (ignoreMailCertErrors && imapConfig?.tls?.rejectUnauthorized !== false) {
            imapConfig.tls = imapConfig.tls || {};
            imapConfig.tls.rejectUnauthorized = false;
        }

        return imapConfig;
    }

    async start() {
        if (this.paused) {
            return;
        }

        let initialState = this.state;

        if (this.imapClient) {
            this.imapClient.disabled = true;
            try {
                this.imapClient.removeAllListeners();
                this.imapClient.on('error', err => {
                    this.logger.error({ msg: 'IMAP connection error', type: 'imapClient', previous: true, account: this.account, err });
                });
                this.imapClient.close();
                if (this.connectionClient) {
                    this.connectionClient.close();
                }
            } catch (err) {
                this.logger.error({ msg: 'IMAP close error', err });
            } finally {
                this.imapClient = null;
            }
        }

        try {
            let accountData = await this.accountObject.loadAccountData();

            this.notifyFrom = accountData.notifyFrom;
            this.syncFrom = accountData.syncFrom;

            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                // can not make a connection
                this.state = 'unset';
                return;
            }

            let imapConfig = await this.getImapConfig(accountData);

            this.imapClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    expungeHandler: async payload => await this.expungeHandler(payload)
                })
            );

            this.imapClient.primaryConnection = true;

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
                this.logger.error({ msg: 'IMAP connection error', type: 'imapClient', account: this.account, err });
                this.reconnect().catch(err => {
                    this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
                });
            });

            this.imapClient.on('response', data => {
                metricsMeta({}, this.logger, 'imapResponses', 'inc', data);

                // update byte counters as well
                let imapStats = this.imapClient.stats(true);

                metricsMeta({}, this.logger, 'imapBytesSent', 'inc', imapStats.sent);
                metricsMeta({}, this.logger, 'imapBytesReceived', 'inc', imapStats.received);
            });

            try {
                await this.connect();

                let prevConnectedCount = await this.redis.hget(this.getAccountKey(), `state:count:connected`);
                let isFirstSuccessfulConnection = prevConnectedCount === '0'; // string zero means the account has been initialized but not yet connected

                let isiInitial = !!isFirstSuccessfulConnection;

                if (!isFirstSuccessfulConnection) {
                    // check if the connection was previously in an errored state
                    let prevLastErrorState = await this.redis.hget(this.getAccountKey(), 'lastErrorState');
                    if (prevLastErrorState) {
                        try {
                            prevLastErrorState = JSON.parse(prevLastErrorState);
                        } catch (err) {
                            // ignore
                        }
                    }

                    if (prevLastErrorState && typeof prevLastErrorState === 'object' && Object.keys(prevLastErrorState).length) {
                        // was previously errored
                        isFirstSuccessfulConnection = true;
                    }
                }

                if (isFirstSuccessfulConnection) {
                    this.logger.info({ msg: 'Successful login without a previous active session', account: this.account, isiInitial, prevActive: false });
                    await this.notify(false, AUTH_SUCCESS_NOTIFY, {
                        user: imapConfig.auth.user
                    });
                } else {
                    this.logger.info({ msg: 'Successful login with a previous active session', account: this.account, isiInitial, prevActive: true });
                }

                await this.setupSubConnections();
            } catch (err) {
                if (err.oauthError && err.oauthError.status === 'invalid_request') {
                    // access token is invalid, clear it
                    try {
                        await this.accountObject.invalidateAccessToken();
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to invalidate OAuth2 access token', account: this.account, err });
                    }
                }

                if (err.authenticationFailed) {
                    this.logger.error({ msg: 'Failed to authenticate', account: this.account, err });
                    await this.notify(false, AUTH_ERROR_NOTIFY, {
                        response: err.response,
                        serverResponseCode: err.serverResponseCode
                    });
                    this.state = 'authenticationError';
                } else {
                    this.logger.error({ msg: 'Failed to connect', account: this.account, err });
                    await this.notify(false, CONNECT_ERROR_NOTIFY, {
                        response: err.response || err.message,
                        serverResponseCode: err.serverResponseCode || err.code
                    });
                    this.state = 'connectError';
                }
                throw err;
            }
        } finally {
            if (this.state !== initialState) {
                // update state
                try {
                    let existingState = await this.redis.hget(this.getAccountKey(), 'state');
                    if (existingState !== this.state) {
                        await this.setStateVal();
                        await emitChangeEvent(this.logger, this.account, 'state', this.state);
                    }
                } catch (err) {
                    // ignore
                }
            }
        }
    }

    async init() {
        await this.reconnect();
    }

    async setErrorState(event, data) {
        let prevLastErrorState = await this.redis.hget(this.getAccountKey(), 'lastErrorState');
        if (prevLastErrorState) {
            try {
                prevLastErrorState = JSON.parse(prevLastErrorState);
            } catch (err) {
                // ignore
            }
        }

        this.state = event;
        await this.setStateVal();

        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', JSON.stringify(data));

        await emitChangeEvent(this.logger, this.account, 'state', event, { error: data });

        if (data && Object.keys(data).length && prevLastErrorState) {
            // we have an error object, let's see if the error hasn't changed

            if (data.serverResponseCode && data.serverResponseCode === prevLastErrorState.serverResponseCode) {
                return false;
            }

            try {
                deepEqual(data, prevLastErrorState);
                // nothing changed
                return false;
            } catch (err) {
                // seems different, can emit
            }
        }

        return true;
    }

    async delete() {
        if (this.isClosed || this.isClosing) {
            return;
        }
        this.isClosing = true;

        if (this.imapClient) {
            this.imapClient.disabled = true;
            this.imapClient.close();
            if (this.connectionClient) {
                this.connectionClient.close();
            }
        }

        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        try {
            for (let [, mailbox] of this.mailboxes) {
                if (mailbox.selected) {
                    await mailbox.onClose();
                }
                await mailbox.clear({ skipNotify: true });
                mailbox = false;
            }

            await this.redis.del(this.getMailboxListKey());
        } finally {
            this.isClosing = false;
            this.isClosed = true;
        }

        this.logger.info({ msg: 'Closed account', account: this.account });
    }

    close() {
        this.state = 'disconnected';
        if (this.isClosed || this.isClosing) {
            return;
        }
        this.isClosing = true;

        if (this.imapClient) {
            this.imapClient.close();
        }

        if (this.commandClient) {
            this.commandClient.close();
        }

        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        this.isClosing = false;
        this.isClosed = true;

        this.closeSubconnections();
    }

    isConnected() {
        return this.imapClient && this.imapClient.usable && !this.isClosing && !this.isClosed;
    }

    currentState() {
        if (this.state === 'connected' && !this.isConnected()) {
            this.state = 'disconnected';
        }
        return this.state;
    }

    checkIMAPConnection() {
        if (!this.isConnected()) {
            let err = new Error('IMAP connection is currently not available for requested account');
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

        let result = await mailbox.getText(message, textParts, options, true);

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

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.getMessage(message, options, true);
    }

    async updateMessage(id, updates) {
        updates = updates || {};
        this.checkIMAPConnection();

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.updateMessage(message, updates, true);
    }

    async updateMessages(path, search, updates) {
        updates = updates || {};
        this.checkIMAPConnection();

        if (!this.mailboxes.has(normalizePath(path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(path));

        return await mailbox.updateMessages(search, updates, true);
    }

    async listMailboxes(options) {
        this.checkIMAPConnection();

        return await this.getCurrentListing(options);
    }

    async moveMessage(id, target) {
        target = target || {};

        this.checkIMAPConnection();

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));

        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));
        return await mailbox.moveMessage(message, target, true);
    }

    async moveMessages(source, search, target) {
        target = target || {};

        this.checkIMAPConnection();

        if (!this.mailboxes.has(normalizePath(source))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(source));

        let res = await mailbox.moveMessages(search, target, true);

        // force sync target mailbox
        try {
            let targetMailbox = this.mailboxes.get(normalizePath(target.path));
            if (targetMailbox) {
                await targetMailbox.sync();
            }
        } catch (err) {
            this.logger.error({ msg: 'Mailbox sync error', path: target.path, err });
        }

        return res;
    }

    async deleteMessage(id, force) {
        this.checkIMAPConnection();

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.deleteMessage(message, force, true);
    }

    async deleteMessages(path, search, force) {
        this.checkIMAPConnection();
        if (!this.mailboxes.has(normalizePath(path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(path));
        let res = await mailbox.deleteMessages(search, force, true);

        // force sync target mailbox
        try {
            if (res && res.moved && res.moved.destination) {
                let targetMailbox = this.mailboxes.get(normalizePath(res.moved.destination));
                if (targetMailbox) {
                    await targetMailbox.sync();
                }
            }
        } catch (err) {
            this.logger.error({ msg: 'Mailbox sync error', path: res && res.moved && res.moved.destination, err });
        }

        return res;
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
        options = Object.assign(
            {
                chunkSize: DOWNLOAD_CHUNK_SIZE
            },
            options || {}
        );

        this.checkIMAPConnection();

        let buf = Buffer.from(attachmentId, 'base64url');
        let id = buf.subarray(0, 8);
        let part = buf.subarray(8).toString();

        let message = await this.unpackUid(id);
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return mailbox.getAttachment(message, part, options, true);
    }

    async getAttachmentContent(attachmentId, options) {
        let stream = await this.getAttachment(attachmentId, options);
        if (!stream) {
            return false;
        }

        return new Promise((resolve, reject) => {
            let chunks = [];
            let chunklen = 0;
            stream.on('error', reject);
            stream.on('readable', () => {
                let chunk;
                while ((chunk = stream.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });
            stream.on('end', () => resolve(Buffer.concat(chunks, chunklen)));
        });
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
        options = Object.assign(
            {
                chunkSize: DOWNLOAD_CHUNK_SIZE
            },
            options || {}
        );

        this.checkIMAPConnection();

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return mailbox.getAttachment(message, false, options, true);
    }

    async listMessages(options) {
        options = options || {};
        this.checkIMAPConnection();

        if (!this.mailboxes.has(normalizePath(options.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(options.path));

        let listing = await mailbox.listMessages(options, true, true);
        return listing;
    }

    async deleteMailbox(path) {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(true);

        let result = {
            path,
            deleted: false // set to true if mailbox is actually deleted
        };
        try {
            let lock = await connectionClient.getMailboxLock(path);

            try {
                await connectionClient.mailboxClose();
                try {
                    await connectionClient.mailboxDelete(path);
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
            mailbox = false;
        }

        return result;
    }

    runPostListing(accountData) {
        this.getCurrentListing()
            .then(listing => {
                let syncNeeded = new Set();
                for (let entry of listing) {
                    if (
                        // previously unseen
                        !this.mailboxes.has(normalizePath(entry.path))
                    ) {
                        if (accountData.path && accountData.path !== '*') {
                            if (accountData.path !== entry.path && accountData.path !== entry.specialUse) {
                                // ignore changes
                                entry.syncDisabled = true;
                            }
                        } else if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
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
                        await mailbox.sync(true);
                    }
                };

                return runSyncs();
            })
            .catch(err => {
                this.logger.error({ msg: 'List refresh error', err });
            });
    }

    async getQuota() {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(true);

        try {
            let result = await connectionClient.getQuota();
            return (result && result.storage) || false;
        } catch (err) {
            if (err.serverResponseCode) {
                let error = new Error('Quota request failed');
                error.info = {
                    response: err.response && typeof err.response === 'string' && err.response.replace(/^[^\s]*\s*/, '')
                };
                error.code = err.serverResponseCode;
                error.statusCode = 400;
                throw error;
            } else if (err.responseStatus === 'NO') {
                return false;
            } else {
                throw err;
            }
        }
    }

    async createMailbox(path) {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(true);

        try {
            let result = await connectionClient.mailboxCreate(path);
            if (result) {
                result.created = !!result.created;
            }

            let accountData = await this.accountObject.loadAccountData();
            setImmediate(() => this.runPostListing(accountData));

            return result;
        } catch (err) {
            if (err.serverResponseCode) {
                let error = new Error('Create failed');
                error.info = {
                    response: err.response && typeof err.response === 'string' && err.response.replace(/^[^\s]*\s*/, '')
                };
                error.code = err.serverResponseCode;
                error.statusCode = 400;
                throw error;
            } else if (err.responseStatus === 'NO') {
                return {
                    path,
                    created: false
                };
            } else {
                throw err;
            }
        }
    }

    async renameMailbox(path, newPath) {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(true);

        try {
            let result = await connectionClient.mailboxRename(path, newPath);
            if (result) {
                result.renamed = !!result.newPath;

                try {
                    await connectionClient.mailboxSubscribe(result.newPath);
                } catch (err) {
                    this.logger.debug({ msg: 'Failed to subscribe mailbox', path: result.newPath, err });
                }
            }

            let accountData = await this.accountObject.loadAccountData();
            setImmediate(() => this.runPostListing(accountData));

            return result;
        } catch (err) {
            if (err.serverResponseCode && err.serverResponseCode !== 'ALREADYEXISTS') {
                let error = new Error('Rename failed');
                error.info = {
                    response: err.response
                };
                error.code = err.serverResponseCode;
                error.statusCode = 400;
                throw error;
            } else if (err.responseStatus === 'NO') {
                let error = new Error('Can not rename mailbox');
                error.info = {
                    response: err.response && typeof err.response === 'string' && err.response.replace(/^[^\s]*\s*/, '')
                };
                error.code = err.serverResponseCode;
                error.statusCode = 400;
                throw error;
            } else {
                throw err;
            }
        }
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
        let accountData = await this.accountObject.loadAccountData();
        if (!accountData.smtp && !accountData.oauth2 && !data.gateway) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        let smtpConnectionConfig;

        if (gatewayData) {
            smtpConnectionConfig = {
                host: gatewayData.host,
                port: gatewayData.port,
                secure: gatewayData.secure
            };
            if (gatewayData.user || gatewayData.pass) {
                smtpConnectionConfig.auth = {
                    user: gatewayData.user || '',
                    pass: gatewayData.pass || ''
                };
            }
        } else if (accountData.oauth2 && accountData.oauth2.auth) {
            // load OAuth2 tokens
            let now = Date.now();
            let accessToken;
            if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
                // renew access token
                try {
                    accountData = await this.accountObject.renewAccessToken({
                        logger: this.logger,
                        logRaw: this.options.logRaw
                    });
                    accessToken = accountData.oauth2.accessToken;
                } catch (err) {
                    err.authenticationFailed = true;
                    let notifyData = {
                        response: err.message,
                        serverResponseCode: 'OauthRenewError'
                    };
                    if (err.tokenRequest) {
                        notifyData.tokenRequest = err.tokenRequest;
                    }
                    await this.notify(false, AUTH_ERROR_NOTIFY, notifyData);
                    this.logger.error({
                        account: this.account,
                        err
                    });
                    this.state = AUTH_ERROR_NOTIFY;
                    throw err;
                }
            } else {
                this.logger.info({
                    msg: 'Using cached OAuth2 access token',
                    action: 'ensureAccessToken',
                    target: 'smtp',
                    error: null,
                    user: accountData.oauth2.auth.user,
                    expires: accountData.oauth2.expires,
                    scopes: accountData.oauth2.scope,
                    oauth2App: accountData.oauth2.provider
                });
                accessToken = accountData.oauth2.accessToken;
            }

            const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (!oauth2App) {
                throw new Error('Missing or disabled OAuth2 app');
            }
            const providerData = oauth2ProviderData(oauth2App.provider);

            smtpConnectionConfig = Object.assign(
                {
                    auth: {
                        user: accountData.oauth2.auth.user,
                        accessToken
                    },
                    resyncDelay: 900
                },
                providerData.smtp || {}
            );
        } else {
            // deep copy of imap settings
            smtpConnectionConfig = JSON.parse(JSON.stringify(accountData.smtp));
        }

        let { raw, hasBcc, envelope, messageId, queueId, reference, job: jobData } = data;

        let smtpAuth = smtpConnectionConfig.auth;
        // If authentication server is set then it overrides authentication data
        if (smtpConnectionConfig.useAuthServer) {
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

        let { localAddress: address, name } = await getLocalAddress(redis, 'smtp', this.account);

        let smtpLogger = {};
        let smtpSettings = Object.assign(
            {
                name,
                localAddress: address,
                transactionLog: true,
                logger: smtpLogger
            },
            smtpConnectionConfig
        );

        if (smtpAuth) {
            smtpSettings.auth = {
                user: smtpAuth.user
            };

            if (smtpAuth.accessToken) {
                smtpSettings.auth.type = 'OAuth2';
                smtpSettings.auth.accessToken = smtpAuth.accessToken;
            } else {
                smtpSettings.auth.pass = smtpAuth.pass;
            }
        }

        if (!smtpSettings.tls) {
            smtpSettings.tls = {};
        }
        for (let key of Object.keys(TLS_DEFAULTS)) {
            if (!(key in smtpSettings.tls)) {
                smtpSettings.tls[key] = TLS_DEFAULTS[key];
            }
        }

        for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
            smtpLogger[level] = (data, message, ...args) => {
                if (args && args.length) {
                    message = util.format(message, ...args);
                }
                data.msg = message;
                data.sub = 'nodemailer';
                if (typeof this.logger[level] === 'function') {
                    this.logger[level](data);
                } else {
                    this.logger.debug(data);
                }
            };
        }

        // set up proxy if needed
        if (accountData.proxy) {
            smtpSettings.proxy = accountData.proxy;
        } else {
            let proxyUrl = await settings.get('proxyUrl');
            let proxyEnabled = await settings.get('proxyEnabled');
            if (proxyEnabled && proxyUrl && !smtpSettings.proxy) {
                smtpSettings.proxy = proxyUrl;
            }
        }

        if (accountData.smtpEhloName) {
            smtpSettings.name = accountData.smtpEhloName;
        }

        const submitJobEntry = await this.submitQueue.getJob(jobData.id);
        if (!submitJobEntry) {
            // already failed?
            this.logger.error({
                msg: 'Submit job was not found',
                job: jobData.id
            });
            return false;
        }

        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
        if (ignoreMailCertErrors && smtpSettings?.tls?.rejectUnauthorized !== false) {
            smtpSettings.tls = smtpSettings.tls || {};
            smtpSettings.tls.rejectUnauthorized = false;
        }

        const transporter = nodemailer.createTransport(smtpSettings);
        transporter.set('proxy_socks_module', socks);
        try {
            try {
                // try to update
                await submitJobEntry.updateProgress({
                    status: 'smtp-starting'
                });
            } catch (err) {
                // ignore
            }

            const info = await transporter.sendMail({
                envelope,
                messageId,
                // make sure that Bcc line is removed from the version sent to SMTP
                raw: !hasBcc ? raw : await removeBcc(raw),
                dsn: data.dsn || null
            });

            if (info.ehlo) {
                await this.redis.hSetExists(this.getAccountKey(), 'smtpServerEhlo', JSON.stringify(info.ehlo));
            }

            // special rules for MTA servers

            let originalMessageId;

            // Hotmail
            let hotmailMessageIdMatch = (info.response || '').toString().match(/^250 2.0.0 OK (<[^>]+\.prod\.outlook\.com>)/);
            if (hotmailMessageIdMatch && hotmailMessageIdMatch[1] !== info.messageId) {
                // MessageId was overriden
                originalMessageId = info.messageId;
                info.messageId = hotmailMessageIdMatch[1];
            }

            // done

            try {
                // try to update
                await submitJobEntry.updateProgress({
                    status: 'smtp-completed',

                    response: info.response,
                    messageId: info.messageId,
                    originalMessageId
                });
            } catch (err) {
                // ignore
            }

            await this.notify(false, EMAIL_SENT_NOTIFY, {
                messageId: info.messageId,
                originalMessageId,
                response: info.response,
                queueId,
                envelope
            });

            // clean up possible cached SMTP error
            try {
                await redis.hset(
                    this.getAccountKey(),
                    'smtpStatus',
                    JSON.stringify({
                        created: Date.now(),
                        status: 'ok',
                        response: info.response
                    })
                );
            } catch (err) {
                // ignore?
            }

            // The default is to copy message to Sent Mail folder
            let shouldCopy = !Object.prototype.hasOwnProperty.call(accountData, 'copy');

            // Account specific setting
            if (typeof accountData.copy === 'boolean') {
                shouldCopy = accountData.copy;
            }

            // Suppress uploads for Gmail and Outlook
            // Unfortunately, previous default schema for all added accounts was copy=true, so can't prefer account specific setting here

            // Emails for delegated accounts will be uploaded as the sender is different.
            // SMTP is disabled for shared mailboxes, so we need to send using the main account.
            let skipIfOutlook = this.isOutlook && (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.delegatedUser);

            if ((this.isGmail || skipIfOutlook) && !gatewayData) {
                shouldCopy = false;
            }

            // Message specific setting, overrides all other settings
            if (typeof data.copy === 'boolean') {
                shouldCopy = data.copy;
            }

            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                // IMAP is disabled for this account
                shouldCopy = false;
            }

            if (shouldCopy) {
                // Upload the message to Sent Mail folder
                try {
                    this.checkIMAPConnection();

                    let sentMailbox =
                        data.sentMailPath && typeof data.sentMailPath === 'string'
                            ? {
                                  path: data.sentMailPath
                              }
                            : await this.getSpecialUseMailbox('\\Sent');

                    if (sentMailbox) {
                        if (raw.buffer) {
                            // convert from a Uint8Array to a Buffer
                            raw = Buffer.from(raw);
                        }

                        const connectionClient = await this.getImapConnection(true);

                        await connectionClient.append(sentMailbox.path, raw, ['\\Seen']);

                        if (connectionClient === this.imapClient && this.imapClient.mailbox && !this.imapClient.idling) {
                            // force back to IDLE
                            this.imapClient.idle().catch(err => {
                                this.logger.error({ msg: 'IDLE error', err });
                            });
                        }
                    }
                } catch (err) {
                    this.logger.error({ msg: 'Failed to upload Sent mail', queueId, messageId, err });
                }
            }

            // Add \Answered flag to referenced message if needed
            if (reference && reference.update) {
                try {
                    this.checkIMAPConnection();
                    await this.updateMessage(reference.message, {
                        flags: {
                            add: ['\\Answered'].concat(reference.action === 'forward' ? '$Forwarded' : [])
                        }
                    });
                } catch (err) {
                    this.logger.error({ msg: 'Failed to update reference flags', queueId, messageId, reference, err });
                }
            }

            if (data.feedbackKey) {
                await redis
                    .multi()
                    .hset(data.feedbackKey, 'success', 'true')
                    .expire(1 * 60 * 60);
            }

            if (gatewayData) {
                try {
                    await gatewayObject.update({
                        lastError: null,
                        lastUse: new Date(),
                        deliveries: { inc: 1 }
                    });
                } catch (err) {
                    this.logger.error({ msg: 'Failed to update gateway', queueId, messageId, reference, gateway: gatewayData.gateway, err });
                }
            }

            return {
                response: info.response,
                messageId: info.messageId
            };
        } catch (err) {
            if (err.responseCode >= 500 && jobData.attemptsMade < jobData.attempts) {
                jobData.nextAttempt = false;
            }

            let smtpStatus = false;
            switch (err.code) {
                case 'ESOCKET':
                    if (err.cert && err.reason) {
                        smtpStatus = {
                            description: `Certificate check for ${smtpSettings.host}:${smtpSettings.port} failed. ${err.reason}`
                        };
                    }
                    break;
                case 'EMESSAGE':
                case 'ESTREAM':
                case 'EENVELOPE':
                    // Ignore. Too generic or message related
                    break;
                case 'ETIMEDOUT':
                    // firewall?
                    smtpStatus = {
                        description: `Request timed out. Possibly a firewall issue or a wrong hostname/port (${smtpSettings.host}:${smtpSettings.port}).`
                    };
                    break;
                case 'ETLS':
                    smtpStatus = {
                        description: `EmailEngine failed to set up TLS session with ${smtpSettings.host}:${smtpSettings.port}`
                    };
                    break;
                case 'EDNS':
                    smtpStatus = {
                        description: `EmailEngine failed to resolve DNS record for ${smtpSettings.host}`
                    };
                    break;
                case 'ECONNECTION':
                    smtpStatus = {
                        description: `EmailEngine failed to establish TCP connection against ${smtpSettings.host}`
                    };
                    break;
                case 'EPROTOCOL':
                    smtpStatus = {
                        description: `Unexpected response from ${smtpSettings.host}`
                    };
                    break;
                case 'EAUTH':
                    smtpStatus = {
                        description: `Authentication failed`
                    };
                    break;
            }

            if (smtpStatus) {
                let lastError = Object.assign(
                    {
                        created: Date.now(),
                        status: 'error',
                        response: err.response,
                        responseCode: err.responseCode,
                        code: err.code,
                        command: err.command
                    },
                    smtpStatus
                );

                // store SMTP error for the account
                try {
                    await redis.hset(this.getAccountKey(), 'smtpStatus', JSON.stringify(lastError));
                } catch (err) {
                    // ignore?
                }

                if (gatewayData) {
                    try {
                        await gatewayObject.update({
                            lastError,
                            lastUse: new Date()
                        });
                    } catch (err) {
                        // ignore?
                    }
                }
            }

            if (data.feedbackKey && !jobData.nextAttempt) {
                await redis
                    .multi()
                    .hset(data.feedbackKey, 'success', 'false')
                    .hset(data.feedbackKey, 'error', ((smtpStatus && smtpStatus.description) || '').toString() || 'Failed to send email')
                    .expire(data.feedbackKey, 1 * 60 * 60)
                    .exec();
            }

            await this.notify(false, EMAIL_DELIVERY_ERROR_NOTIFY, {
                queueId,
                envelope,

                messageId: data.messageId,

                error: err.message,
                errorCode: err.code,

                smtpResponse: err.response,
                smtpResponseCode: err.responseCode,
                smtpCommand: err.command,

                job: jobData
            });

            err.code = err.code || 'SubmitFail';
            err.statusCode = Number(err.responseCode) || null;

            throw err;
        }
    }

    render(template, data, key, renderFormat) {
        let format;

        switch (key) {
            case 'subject':
            case 'text': {
                format = 'plain';
                break;
            }

            case 'html': {
                format = renderFormat ? renderFormat : 'html';
                break;
            }

            case 'previewText':
            default: {
                format = 'html';
                break;
            }
        }

        try {
            const compiledTemplate = getTemplate({
                format,
                template
            });

            return compiledTemplate(data);
        } catch (err) {
            logger.error({ msg: `Failed rendering ${key} template`, err });
            let error = new Error(`Failed rendering ${key} template`);
            error.code = err.code || 'SubmitFail';
            error.statusCode = 422;
            throw error;
        }
    }

    async queueMessage(data, meta) {
        let accountData = await this.accountObject.loadAccountData();

        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let licenseInfo = await this.call({ cmd: 'license' });

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;

        // convert data uri images to attachments
        convertDataUrisToAtachments(data);

        if (data.template) {
            let templateData = await templates.get(data.template);
            if (!templateData || (templateData.account && templateData.account !== accountData.account)) {
                let err = new Error(`Requested template was not found [${data.template}]`);
                err.code = 'TemplateNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (templateData.content && templateData.content.html && templateData.format) {
                data.render = data.render || {};
                data.render.format = templateData.format;
            }

            for (let key of Object.keys(templateData.content || {})) {
                data[key] = templateData.content[key];
            }

            delete data.template;
        }

        if (!data.mailMerge || !data.mailMerge.length) {
            return this.queueMessageEntry(data, meta, licenseInfo);
        }

        let mailMergeList = data.mailMerge;
        delete data.mailMerge;
        delete data.messageId;
        delete data.to;

        let messageProcessors = [];

        for (let mailMergeEntry of mailMergeList) {
            let messageCopy = pfStructuredClone(data);
            if (messageCopy.sendAt) {
                // date values do not survive JSON based copying
                messageCopy.sendAt = new Date(messageCopy.sendAt);
            }

            messageCopy.to = [mailMergeEntry.to];

            for (let key of ['messageId', 'sendAt']) {
                if (mailMergeEntry[key]) {
                    messageCopy[key] = mailMergeEntry[key];
                }
            }

            if (mailMergeEntry.params) {
                messageCopy.render = messageCopy.render || {};
                messageCopy.render.params = mailMergeEntry.params;
            }

            messageProcessors.push(this.queueMessageEntry(messageCopy, meta, licenseInfo));
        }

        let response = {
            mailMerge: []
        };

        let results = await Promise.allSettled(messageProcessors);
        for (let i = 0; i < mailMergeList.length; i++) {
            let mailMergeEntry = mailMergeList[i];
            let resultEntry = results[i];

            let result = Object.assign(
                {
                    success: resultEntry.status === 'fulfilled',
                    to: mailMergeEntry.to
                },
                resultEntry.status === 'fulfilled'
                    ? resultEntry.value.responseValue || {
                          messageId: resultEntry.value.messageId,
                          queueId: resultEntry.value.queueId,
                          sendAt: resultEntry.value.sendAt
                      }
                    : {
                          error: (resultEntry.reason && resultEntry.reason.message) || resultEntry.status,
                          code: (resultEntry.reason && resultEntry.reason.code) || 'SubmitFail',
                          statusCode: (resultEntry.reason && Number(resultEntry.reason.statusCode)) || null
                      }
            );

            response.mailMerge.push(result);
        }

        return response;
    }

    async queueMessageEntry(data, meta, licenseInfo) {
        let accountData = await this.accountObject.loadAccountData();

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;

        let baseUrl = data.baseUrl || (await settings.get('serviceUrl')) || null;

        let context = {
            params: (data.render && data.render.params) || {},
            account: {
                name: accountData.name,
                email: accountData.email
            },
            service: {
                url: baseUrl
            }
        };

        if (!data.from) {
            data.from = {
                name: accountData.name,
                address: accountData.email
            };
        }

        if (baseUrl && data.listId && data.to && data.to.length === 1 && data.to[0].address) {
            // check if not already blocked

            let blockData;

            try {
                blockData = await redis.hget(`${REDIS_PREFIX}lists:unsub:entries:${data.listId}`, data.to[0].address.toLowerCase().trim());
                blockData = JSON.parse(blockData);
            } catch (err) {
                blockData = false;
            }

            if (blockData) {
                return {
                    responseValue: {
                        skipped: {
                            reason: blockData.reason,
                            listId: data.listId
                        }
                    }
                };
            }

            if (!data.headers) {
                data.headers = {};
            }

            let baseDomain;
            try {
                baseDomain = (new URL(baseUrl).hostname || '').toLowerCase().trim();
            } catch (err) {
                // ignore error
            }
            baseDomain = baseDomain || (os.hostname() || '').toLowerCase().trim() || 'localhost';

            if (baseDomain) {
                let unsubscribeUrlObj = new URL('/unsubscribe', baseUrl);

                const serviceSecret = await getServiceSecret();

                let fromDomain = ((data.from && data.from.address) || '').split('@').pop().trim().toLowerCase() || baseDomain;
                try {
                    fromDomain = punycode.toASCII(fromDomain);
                } catch (err) {
                    // ignore
                }

                data.headers['List-ID'] = `<${data.listId}.${baseDomain}>`;

                if (!data.messageId) {
                    data.messageId = `<${uuid.v4()}@${fromDomain}>`;
                }

                let { data: signedData, signature } = getSignedFormDataSync(
                    serviceSecret,
                    {
                        act: 'unsub',
                        acc: accountData.account,
                        list: data.listId,
                        rcpt: data.to[0].address,
                        msg: data.messageId
                    },
                    true
                );

                unsubscribeUrlObj.searchParams.append('data', signedData);
                if (signature) {
                    unsubscribeUrlObj.searchParams.append('sig', signature);
                }

                context.rcpt = Object.assign({}, data.to[0], { unsubscribeUrl: unsubscribeUrlObj.href });

                data.headers['List-Unsubscribe'] = `<${context.rcpt.unsubscribeUrl}>`;
                data.headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
            }
        }

        for (let key of ['subject', 'html', 'text', 'previewText']) {
            if (data.render || data.listId) {
                data[key] = this.render(data[key], context, key, data.render && data.render.format);
            }
        }

        delete data.render;

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        if (data.html && !data.text) {
            try {
                data.text = htmlToText(data.html);
            } catch (err) {
                this.logger.error({ msg: 'Failed to generate plaintext content from html', err });
            }
        }

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                this.checkIMAPConnection();

                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(data.reference.message, {
                    fields: !extendedData
                        ? {
                              uid: true,
                              flags: true,
                              envelope: true,
                              headers: ['references']
                          }
                        : false,
                    header: extendedData ? true : false,
                    textType: extendedData ? '*' : false
                });
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let error = new Error('Referenced message was not found');
                error.code = 'ReferenceNotFound';
                error.statusCode = 404;
                throw error;
            }

            if (referencedMessage) {
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

                let referenceFlags = ['\\Answered'].concat(data.reference.action === 'forward' ? '$Forwarded' : []);
                if (!referencedMessage.flags || !referencedMessage.flags.length || !referenceFlags.some(flag => referencedMessage.flags.includes(flag))) {
                    data.reference.update = true;
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

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            data.html = inlineHtml(data.reference.action, data.html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection();

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(attachment.id, {
                                chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                            });
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection();

                let content = await this.getAttachmentContent(attachment.reference, {
                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                });
                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        let { raw, hasBcc, envelope, subject, messageId, sendAt, deliveryAttempts, trackingEnabled, gateway } = await getRawEmail(data, licenseInfo);

        if (data.dryRun) {
            let response = {
                response: 'Dry run',
                messageId
            };

            if (data.reference && data.reference.message) {
                response.reference = {
                    message: data.reference.message,
                    documentStore: documentStoreUsed,
                    success: referencedMessage ? true : false
                };

                if (!referencedMessage) {
                    response.reference.error = 'Referenced message was not found';
                }
            }

            response.preview = raw.toString('base64');

            return response;
        }

        let gatewayData;
        if (gateway) {
            let gatewayObject = new Gateway({ gateway, redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', envelope, messageId, gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        if (typeof trackingEnabled !== 'boolean') {
            trackingEnabled = (await settings.get('trackSentMessages')) || false;
        }

        if (raw && trackingEnabled && baseUrl) {
            // add open and click tracking
            raw = await addTrackers(raw, accountData.account, messageId, baseUrl);
        }

        let now = new Date();

        //queue for later

        // Use timestamp in the ID to make sure that jobs are ordered by send time
        let timeBuf = Buffer.allocUnsafe(8);

        timeBuf.writeBigInt64BE(BigInt((sendAt && sendAt.getTime()) || Date.now()), 0);

        let queueId = Buffer.concat([timeBuf.subarray(2), crypto.randomBytes(4)])
            .toString('hex')
            .substr(1);

        let msgEntry = msgpack.encode({
            queueId,
            gateway: gatewayData && gatewayData.gateway,
            hasBcc,
            envelope,
            messageId,
            reference: data.reference || {},
            sendAt: (sendAt && sendAt.getTime()) || false,
            created: now.getTime(),
            copy: data.copy,
            sentMailPath: data.sentMailPath,
            feedbackKey: data.feedbackKey || null,
            dsn: data.dsn || null,
            raw
        });

        await this.redis.hsetBuffer(`${REDIS_PREFIX}iaq:${this.account}`, queueId, msgEntry);

        let queueKeep = (await settings.get('queueKeep')) || true;

        let defaultDeliveryAttempts = await settings.get('deliveryAttempts');
        if (typeof defaultDeliveryAttempts !== 'number') {
            defaultDeliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
        }

        let jobData = Object.assign({}, meta || {}, {
            account: this.account,
            queueId,
            gateway: (gatewayData && gatewayData.gateway) || null,
            messageId,
            envelope,
            subject,
            created: now.getTime()
        });

        let queueName = 'queued';
        let jobOpts = {
            jobId: queueId,
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: typeof deliveryAttempts === 'number' ? deliveryAttempts : defaultDeliveryAttempts,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        if (sendAt && sendAt > now) {
            queueName = 'delayed';
            jobOpts.delay = sendAt.getTime() - now.getTime();
        }

        let job = await this.submitQueue.add(queueName, jobData, jobOpts);

        try {
            await job.updateProgress({
                status: 'queued'
            });
        } catch (err) {
            // ignore
        }

        this.logger.info({ msg: 'Message queued for delivery', envelope, messageId, sendAt: (sendAt || now).toISOString(), queueId, job: job.id });

        let response = {
            response: 'Queued for delivery',
            messageId,
            sendAt: (sendAt || now).toISOString(),
            queueId
        };

        if (data.reference && data.reference.message) {
            response.reference = {
                message: data.reference.message,
                documentStore: documentStoreUsed,
                success: referencedMessage ? true : false
            };

            if (!referencedMessage) {
                response.reference.error = 'Referenced message was not found';
            }
        }

        return response;
    }

    async uploadMessage(data) {
        this.checkIMAPConnection();

        data.disableFileAccess = true;
        data.disableUrlAccess = true;

        // convert data uri images to attachments
        convertDataUrisToAtachments(data);

        let accountData = await this.accountObject.loadAccountData();

        if (!data.from && data.reference && data.reference.action) {
            data.from = {
                name: accountData.name,
                address: accountData.email
            };
        }

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        let referencedMessage;
        let documentStoreUsed = true;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(data.reference.message, {
                    fields: !extendedData
                        ? {
                              uid: true,
                              flags: true,
                              envelope: true,
                              headers: ['references']
                          }
                        : false,
                    header: extendedData ? true : false,
                    textType: extendedData ? '*' : false
                });
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let err = new Error('Referenced message was not found');
                err.code = 'MessageNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (referencedMessage) {
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

                let referenceFlags = ['\\Answered'].concat(data.reference.action === 'forward' ? '$Forwarded' : []);
                if (!referencedMessage.flags || referenceFlags.some(flag => referencedMessage.flags.includes(flag))) {
                    let update = {
                        flags: {
                            add: !referencedMessage.flags ? referenceFlags : referenceFlags.filter(flag => referencedMessage.flags.includes(flag))
                        }
                    };

                    try {
                        await this.updateMessage(data.reference.message, update);
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to update a message', message: data.reference.message, update, err });
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

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            data.html = inlineHtml(data.reference.action, data.html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection();

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(attachment.id, {
                                chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                            });
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection();

                let content = await this.getAttachmentContent(attachment.reference, {
                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                });
                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        data.disableUrlAccess = true;
        data.disableFileAccess = true;
        data.newline = '\r\n';

        if (data.internalDate && !data.date) {
            // Update Date: header as well
            data.date = new Date(data.internalDate);
        }

        let { raw, messageId } = await getRawEmail(data);

        // Upload message to selected folder
        try {
            const connectionClient = await this.getImapConnection(true);

            let response = {};

            let uploadResponse = await connectionClient.append(data.path, raw, data.flags, data.internalDate);

            if (connectionClient === this.imapClient && this.imapClient.mailbox && !this.imapClient.idling) {
                // force back to IDLE
                this.imapClient.idle().catch(err => {
                    this.logger.error({ msg: 'IDLE error', err });
                });
            }

            if (uploadResponse.uid) {
                response.id = await this.packUid(uploadResponse.path, uploadResponse.uid);
            }

            response.path = uploadResponse.path;

            if (uploadResponse.uid) {
                response.uid = uploadResponse.uid;
            }

            if (validUidValidity(uploadResponse.uidValidity)) {
                response.uidValidity = uploadResponse.uidValidity.toString();
            }

            if (uploadResponse.seq) {
                response.seq = uploadResponse.seq;
            }

            if (messageId) {
                response.messageId = messageId;
            }

            if (data.reference && data.reference.message) {
                response.reference = {
                    message: data.reference.message,
                    documentStore: documentStoreUsed,
                    success: referencedMessage ? true : false
                };

                if (!referencedMessage) {
                    response.reference.error = 'Referenced message was not found';
                }
            }

            return response;
        } catch (err) {
            if (err.mailboxMissing) {
                // this mailbox is missing, refresh listing
                try {
                    await this.connection.getCurrentListing();
                } catch (E) {
                    this.logger.error({ msg: 'Missing mailbox', err, E });
                }
            }

            err.code = 'UploadFail';
            err.statusCode = 502;
            throw err;
        }
    }

    // process untagged EXPUNGE and VANISHED notifications in order
    async expungeHandler(payload) {
        if (!payload || !payload.path || !this.mailboxes.has(normalizePath(payload.path))) {
            return; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(payload.path));
        try {
            await mailbox.onExpunge(payload);
        } catch (err) {
            this.logger.error({ msg: 'Expunge error', err });
        }
    }

    async setupSubConnections() {
        let accountData = await this.accountObject.loadAccountData();

        let mailboxes = [];

        let listing = await this.getCurrentListing();

        for (let path of accountData.subconnections || []) {
            let entry = listing.find(entry => path === entry.path || path === entry.specialUse);

            if (!entry) {
                continue;
            }

            if (accountData.path && entry.path === accountData.path) {
                continue;
            }

            if (this.isGmail && (!accountData.path || accountData.path === '*') && !['\\Trash', '\\Junk'].includes(entry.specialUse)) {
                // no need to check this folder, as \All already covers it
                continue;
            }

            if (!this.isGmail && (!accountData.path || accountData.path === '*') && entry.specialUse === '\\Inbox') {
                // already the default
                continue;
            }

            mailboxes.push(entry);
        }

        // remove unneeded
        for (let i = this.subconnections.length - 1; i >= 0; i--) {
            let subconnection = this.subconnections[i];
            if (!mailboxes.find(mailbox => mailbox.path === subconnection.path)) {
                // not listed anymore
                this.subconnections.splice(i, 1);
                try {
                    subconnection.removeAllListeners();
                    subconnection.close();
                } catch (err) {
                    this.logger.error({ msg: 'Failed to close unlisted subconnection', path: subconnection.path, err });
                }
            }
        }

        // create missing
        for (let mailbox of mailboxes) {
            if (this.subconnections.find(subconnection => mailbox.path === subconnection.path)) {
                // already exists
                continue;
            }
            // create new
            let subconnection = new Subconnection({
                account: this.account,
                mailbox,
                getImapConfig: async () => await this.getImapConfig(),
                logger: this.logger.child({
                    channel: 'subconnection',
                    subconnection: mailbox.path
                })
            });
            this.subconnections.push(subconnection);

            subconnection.on('changes', path => {
                let mailbox;

                if (this.mailboxes.has(normalizePath(path))) {
                    mailbox = this.mailboxes.get(normalizePath(path));
                    try {
                        mailbox
                            .sync()
                            .then(() => this.ensureMainMailbox())
                            .catch(err => {
                                this.logger.error({ msg: 'Failed to sync mailbox', path, err });
                            });
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to sync mailbox', path, err });
                    }
                }
            });

            await subconnection.init();
        }
    }

    closeSubconnections() {
        // remove unneeded
        for (let i = this.subconnections.length - 1; i >= 0; i--) {
            let subconnection = this.subconnections[i];

            // not listed anymore
            this.subconnections.splice(i, 1);
            try {
                subconnection.removeAllListeners();
                subconnection.close();
            } catch (err) {
                this.logger.error({ msg: 'Failed to close unlisted subconnection', path: subconnection.path, err });
            }
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

                if (this.accountLogger.enabled && args && args[0] && typeof args[0] === 'object') {
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

        synteticLogger.child = opts => this.mainLogger.child(opts);

        return synteticLogger;
    }

    async pause() {
        if (this.paused) {
            return false;
        }
        this.paused = true;
        this.logger.info({ msg: 'Closing connection', action: 'pause' });
        this.close();

        this.state = 'paused';
        await this.setStateVal();
        await emitChangeEvent(this.logger, this.account, 'state', this.state);
    }

    async resume() {
        if (!this.paused) {
            return false;
        }
        this.paused = false;
        if (this.isClosed) {
            this.isClosed = false;
        }

        this.logger.info({ msg: 'Creating connection', action: 'resume' });
        this.init();
    }
}

module.exports.Connection = Connection;
