'use strict';

const { parentPort } = require('worker_threads');
const { ImapFlow } = require('imapflow');
const { Mailbox } = require('./imap/mailbox');
const logger = require('../logger');
const packageData = require('../../package.json');
const { backOff } = require('exponential-backoff');
const msgpack = require('msgpack5')();
const nodemailer = require('nodemailer');
const util = require('util');
const { removeBcc } = require('../get-raw-email');
const socks = require('socks');
const { Gateway } = require('../gateway');
const { Account } = require('../account');

const { oauth2Apps, oauth2ProviderData } = require('../oauth2-apps');
const { BaseClient } = require('./base-client');

const { Subconnection } = require('./imap/subconnection');

const {
    getLocalAddress,
    normalizePath,
    resolveCredentials,
    emitChangeEvent,
    getByteSize,
    getBoolean,
    readEnvValue,
    validUidValidity,
    getDuration
} = require('../tools');

const RESYNC_DELAY = 15 * 60;
const ENSURE_MAIN_TTL = 5 * 1000;

const {
    AUTH_ERROR_NOTIFY,
    AUTH_SUCCESS_NOTIFY,
    CONNECT_ERROR_NOTIFY,
    EMAIL_SENT_NOTIFY,
    EMAIL_DELIVERY_ERROR_NOTIFY,
    DEFAULT_DOWNLOAD_CHUNK_SIZE,
    MAX_BACKOFF_DELAY,
    TLS_DEFAULTS
} = require('../consts');

const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;
const DISABLE_IMAP_COMPRESSION = getBoolean(readEnvValue('EENGINE_DISABLE_COMPRESSION'));
const IMAP_SOCKET_TIMEOUT = getDuration(readEnvValue('EENGINE_IMAP_SOCKET_TIMEOUT'));

logger.trace({ msg: 'Worker configuration', DOWNLOAD_CHUNK_SIZE, DISABLE_IMAP_COMPRESSION, IMAP_SOCKET_TIMEOUT });

const settings = require('../settings');
const { redis } = require('../db');

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

class IMAPClient extends BaseClient {
    constructor(account, options) {
        options = options || {};
        super(account, options);

        this.isClosing = false;
        this.isClosed = false;

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

        this.connectionCount = 0;
        this.connections = new Set();

        this.imapIndexer = null;

        this.state = 'connecting';
    }

    onTaskCompleted() {
        // check if we need to re-select main mailbox
        this.completedTimer = setTimeout(() => {
            clearTimeout(this.completedTimer);
            this.ensureMainMailbox().catch(err => this.logger.error({ msg: 'Failed to select main mailbox', err }));
        }, ENSURE_MAIN_TTL);
    }

    async getImapConnection(allowSecondary, reason) {
        let syncing = this.syncing || ['init', 'connecting', 'syncing'].includes(this.state);
        if (!syncing || !allowSecondary) {
            return this.imapClient;
        }

        try {
            const connectionClient = await this.getCommandConnection(reason);
            return connectionClient && connectionClient.usable ? connectionClient : this.imapClient;
        } catch (err) {
            this.logger.error({ msg: 'Failed to acquire command connection', reason, err });
            return this.imapClient;
        }
    }

    async getCommandConnection(reason) {
        if (this.commandClient && this.commandClient.usable) {
            // use existing command channel
            return this.commandClient;
        }

        let lock = this.accountObject.getLock();

        let connectLock;
        let lockKey = ['commandCient', this.account].join(':');

        try {
            this.logger.debug({ msg: 'Acquiring connection lock', lockKey });
            connectLock = await lock.waitAcquireLock(lockKey, 5 * 60 * 1000, 1 * 60 * 1000);
            if (!connectLock.success) {
                this.logger.error({ msg: 'Failed to get lock', lockKey });
                throw new Error('Failed to get connection lock');
            }
            this.logger.debug({ msg: 'Acquired connection lock', lockKey, index: connectLock.index });
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

            if (this.commandClient && this.commandClient.usable) {
                // use existing command channel created during the lock
                return this.commandClient;
            }

            const commandCid = `${this.cid}:c:${this.connectionCount++}`;

            let imapConfig = await this.getImapConfig(accountData);

            let commandClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    disableAutoIdle: true,
                    id: commandCid,
                    socketTimeout: 60 * 1000,
                    logger: this.logger.child({
                        cid: commandCid,
                        channel: 'command'
                    })
                })
            );
            this.connections.add(commandClient);
            await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());

            commandClient.log.debug({ msg: 'Created command client', reason });

            this.commandClient = commandClient;

            commandClient.secondaryConnection = true;

            try {
                await commandClient.connect();
                commandClient.log.info({ msg: 'Command channel connected', cid: commandCid, channel: 'command', account: this.account });
            } catch (err) {
                commandClient.log.error({ msg: 'Failed to connect command client', cid: commandCid, channel: 'command', account: this.account, err });
                throw err;
            }

            commandClient.on('error', err => {
                commandClient?.log.error({ msg: 'IMAP connection error', cid: commandCid, channel: 'command', account: this.account, err });
                commandClient.close(); // ensure the client is closed on error
                this.commandClient = null;
            });

            commandClient.on('close', async () => {
                this.connections.delete(commandClient);
                await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());
                commandClient.log.info({ msg: 'Connection closed', cid: commandCid, channel: 'command', account: this.account });

                this.commandClient = null;
                commandClient.removeAllListeners();
                commandClient = null;
            });

            return commandClient;
        } finally {
            this.logger.debug({ msg: 'Releasing connection lock', lockKey, index: connectLock.index });
            await lock.releaseLock(connectLock);
            this.logger.debug({ msg: 'Released connection lock', lockKey, index: connectLock.index });
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

    async getCurrentListing(options, allowSecondary) {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(allowSecondary, 'getCurrentListing');
        if (!connectionClient) {
            this.imapClient.close();
            let error = new Error('Failed to get connection');
            error.code = 'ConnectionError';
            throw error;
        }

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

        let listing = await connectionClient.list(options);
        if (!listing.length) {
            // server bug, the list can never be empty
            this.imapClient.close();
            let error = new Error('Server bug: empty mailbox listing');
            error.code = 'ServerBug';
            throw error;
        }

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
            const listingObject = {};
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

            const accountPaths = [].concat(accountData.path || '*');
            if (!accountPaths.length) {
                accountPaths.push('*');
            }

            let listing = await this.getCurrentListing();

            let syncNeeded = new Set();
            for (let entry of listing) {
                if (
                    // previously unseen
                    !this.mailboxes.has(normalizePath(entry.path))
                ) {
                    if (!accountPaths.includes('*')) {
                        if (!accountPaths.includes(entry.path) && !accountPaths.includes(entry.specialUse)) {
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

        const accountPaths = [].concat(accountData.path || '*');
        if (!accountPaths.length) {
            accountPaths.push('*');
        }

        // store synced folder entries
        const mainList = [];

        for (let entry of listing) {
            if (!accountPaths.includes('*')) {
                if (!accountPaths.includes(entry.path) && !accountPaths.includes(entry.specialUse)) {
                    entry.syncDisabled = true;
                } else {
                    // insert to stored list with the sorting index
                    let index = accountPaths.indexOf(entry.path) >= 0 ? accountPaths.indexOf(entry.path) : accountPaths.indexOf(entry.specialUse);
                    mainList.push({ index, entry });
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

        if (mainList.length) {
            // set the highest synced entry as the main folder
            this.main = mainList.sort((a, b) => a.index - b.index)[0].entry;
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
                imapClient.log.error({ msg: 'Exists error', err });
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
                imapClient.log.error({ msg: 'Open error', err });
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
                imapClient.log.error({ msg: 'Close error', err });
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
                imapClient.log.error({ msg: 'Flags error', err });
            }
        });

        return response;
    }

    async reconnect(force) {
        if (this._connecting) {
            // backoff reconnect already in progress
            return false;
        }
        if (this.paused || this.isClosing || (this.isClosed && !force)) {
            this.logger.debug({
                msg: 'Skipped establishing connection',
                paused: this.paused,
                hasClient: !!this.imapClient,
                usable: this.imapClient?.usable,
                closing: this.isClosing,
                closed: this.isClosed,
                force
            });
            return false;
        }
        this.logger.debug({ msg: 'Establishing connection', force });

        if (force) {
            this.closeSubconnections();
            if (this.commandClient) {
                this.commandClient.close();
            }
        }

        this._connecting = true;
        this.isClosed = false;

        let accountData = await this.accountObject.loadAccountData();
        this.imapIndexer = typeof accountData.imapIndexer === 'string' && accountData.imapIndexer ? accountData.imapIndexer : 'full';

        try {
            this.logger.debug({ msg: 'Initiating connection to IMAP' });
            await backOff(() => this.start(), {
                maxDelay: MAX_BACKOFF_DELAY,
                numOfAttempts: Infinity,
                retry: () => !this.isClosing && !this.isClosed,
                startingDelay: 2000
            });
            this.logger.debug({
                msg: 'Connection created',
                hasClient: !!this.imapClient,
                usable: this.imapClient && this.imapClient.usable,
                connected: this.isConnected()
            });
        } finally {
            this._connecting = false;
        }

        if (this.paused) {
            this.logger.debug({ msg: 'Skipped connection setup', reason: 'paused' });
            return;
        }

        if (this.state === 'unset') {
            this.logger.debug({ msg: 'Skipped connection setup', reason: 'unset' });
            return;
        }

        try {
            await this.checkIMAPConnection();
            this.logger.debug({ msg: 'Starting mailbox sync' });
            await this.syncMailboxes();
            this.logger.debug({ msg: 'Mailboxes synced', usable: this.imapClient?.usable });

            if (this.imapClient?.usable) {
                // was able to finish syncing, clear the failure flag
                try {
                    await this.connection.redis.hdel(this.connection.getAccountKey(), 'syncError');
                } catch (err) {
                    // ignore
                }
            }
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up connection, will retry', err });
            return setTimeout(() => {
                this.reconnect().catch(err => {
                    this.logger.error({ msg: 'Gave up setting up a connection', err });
                });
            }, 1000);
        }

        this.logger.debug({
            msg: 'Connection established',
            hasClient: !!this.imapClient,
            usable: this.imapClient && this.imapClient.usable,
            connected: this.isConnected()
        });
    }

    async syncMailboxes() {
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        if (!this.imapClient || !this.imapClient.usable) {
            this.logger.debug({ msg: 'Skipped syncing', reason: 'no imap client' });
            return;
        }

        let synced = await this.refreshFolderList();
        for (let mailbox of this.mailboxes.values()) {
            if (!synced || !synced.has(mailbox)) {
                await mailbox.sync();
            }
        }

        if (!this.imapClient || !this.imapClient.usable) {
            this.logger.debug({ msg: 'Syncing completed, skipping state change', reason: 'no imap client' });
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
        await this.redis.hdel(this.getAccountKey(), 'lastErrorState', 'lastError:errorCount', 'lastError:first');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        this.logger.debug({ msg: 'Syncing completed, selecting main path', path: mainPath });
        // start waiting for changes
        await this.select(mainPath);

        // schedule next sync
        let setSyncTimer = () => {
            clearTimeout(this.resyncTimer);
            this.resyncTimer = setTimeout(() => {
                this.syncMailboxes().catch(err => {
                    this.logger.error({ msg: 'Mailbox Sync Error', err });
                    setSyncTimer();
                });
            }, this.resyncDelay);
        };
        setSyncTimer();
    }

    async select(path) {
        if (!this.mailboxes.has(normalizePath(path))) {
            // nothing to do here, mailbox not found
            this.logger.debug({ msg: 'Can not select unlisted path', path });
            return;
        }

        let mailbox = this.mailboxes.get(normalizePath(path));
        await mailbox.select();
    }

    async loadOAuth2LoginCredentials(accountObject, accountData, ctx, target) {
        const now = Date.now();
        const oauth2User = accountData.oauth2.auth.delegatedUser || accountData.oauth2.auth.user;
        let accessToken;

        const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
        if (!oauth2App) {
            let error = new Error('Missing or disabled OAuth2 app');
            error.code = 'AppNotFound';
            throw error;
        }

        if (oauth2App.baseScopes && oauth2App.baseScopes !== 'imap') {
            let error = new Error('Invalid base scopes for references OAuth2 application');
            error.code = 'InvalidBaseScopes';
            throw error;
        }

        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
            // renew access token
            try {
                accountData = await accountObject.renewAccessToken({
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
                    account: accountObject.account,
                    err
                });
                ctx.state = 'authenticationError';
                throw err;
            }
        } else {
            this.logger.info({
                msg: 'Using cached OAuth2 access token',
                action: 'ensureAccessToken',
                target,
                error: null,
                user: accountData.oauth2.auth.user,
                expires: accountData.oauth2.expires,
                scopes: accountData.oauth2.scope,
                oauth2App: accountData.oauth2.provider
            });
            accessToken = accountData.oauth2.accessToken;
        }
        return { oauth2User, accessToken, oauth2App };
    }

    async loadOAuth2AccountCredentials(accountData, ctx, target) {
        let oauthCredentials;
        if (accountData.oauth2.auth.delegatedUser && accountData.oauth2.auth.delegatedAccount) {
            let redirect = 0;
            let providerAccountData = accountData;
            let delegatedAccountData;
            let seenAccounts = new Set();
            let hopsAllowed = 20;
            while (redirect++ < hopsAllowed) {
                if (!this.delegatedAcountObject || this.delegatedAcountObject.account !== providerAccountData.oauth2.auth.delegatedAccount) {
                    this.delegatedAcountObject = new Account({
                        account: accountData.oauth2.auth.delegatedAccount,
                        redis: this.accountObject.redis,
                        call: this.accountObject.call,
                        secret: this.accountObject.secret,
                        timeout: this.accountObject.timeout
                    });
                }
                delegatedAccountData = await this.delegatedAcountObject.loadAccountData();
                if (delegatedAccountData.oauth2.auth.delegatedUser && delegatedAccountData.oauth2.auth.delegatedAccount) {
                    if (seenAccounts.has(providerAccountData.account)) {
                        // loop detected
                        let error = new Error('Delegation looping detected');
                        throw error;
                    }
                    seenAccounts.add(providerAccountData.account);
                    providerAccountData = delegatedAccountData;
                    continue;
                }
                break;
            }

            if (redirect >= hopsAllowed) {
                let error = new Error('Too many delegation hops');
                throw error;
            }

            oauthCredentials = await this.loadOAuth2LoginCredentials(this.delegatedAcountObject, delegatedAccountData, ctx, target);
            if (target !== 'smtp') {
                oauthCredentials.oauth2User = accountData.oauth2.auth.delegatedUser || oauthCredentials.oauth2User;
            }
        } else {
            oauthCredentials = await this.loadOAuth2LoginCredentials(this.accountObject, accountData, ctx, target);
        }

        return oauthCredentials;
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
            const { oauth2User, accessToken, oauth2App } = await this.loadOAuth2AccountCredentials(accountData, ctx, 'imap');
            const providerData = oauth2ProviderData(oauth2App.provider);

            imapConnectionConfig = Object.assign(
                {
                    auth: {
                        user: oauth2User,
                        accessToken
                    },
                    resyncDelay: RESYNC_DELAY
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
        const localAddress = await getLocalAddress(redis, 'imap', this.account);
        imapConnectionConfig.tls.localAddress = localAddress.localAddress;
        this.logger.info({
            msg: 'Selected local address',
            account: this.account,
            proto: 'IMAP',
            address: localAddress.localAddress,
            name: localAddress.name,
            selector: localAddress.addressSelector
        });

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
            this.logger.debug({ msg: 'Skipped start', reason: 'paused' });
            return;
        }

        let initialState = this.state;

        if (this.imapClient) {
            this.logger.debug({ msg: 'Clearing previous connection' });
            let prevImapClient = this.imapClient;
            prevImapClient.disabled = true;
            try {
                prevImapClient.removeAllListeners();
                prevImapClient.once('error', err => {
                    this.logger.error({ msg: 'IMAP connection error', type: 'imapClient', previous: true, account: this.account, err });
                });
                prevImapClient.close();
                if (this.commandClient) {
                    this.logger.debug({ msg: 'Clearing previous command connection' });
                    this.commandClient.close();
                }
            } catch (err) {
                this.logger.error({ msg: 'IMAP close error', err });
            } finally {
                if (prevImapClient === this.imapClient) {
                    this.imapClient = null;
                }
                prevImapClient = null;
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

            imapConfig.id = `${imapConfig.id}:m:${this.connectionCount++}`;

            let imapClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    expungeHandler: async payload => await this.expungeHandler(payload)
                })
            );
            this.connections.add(imapClient);
            await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());

            imapClient.log.debug({ msg: 'Created primary client' });

            this.imapClient = imapClient;

            imapClient.primaryConnection = true;

            // if emitLogs option is true then separate log event is fired for every log entry
            imapClient.on('log', entry => {
                if (!entry) {
                    return false;
                }

                if (typeof entry === 'string') {
                    // should not happen
                    entry = { msg: entry };
                }

                this.accountLogger.log(entry);
            });

            imapClient.on('error', err => {
                imapClient?.log.error({ msg: 'IMAP connection error', type: 'imapClient', account: this.account, err });
                if (imapClient !== this.imapClient || this._connecting) {
                    return;
                }
                imapClient.close(); // ensure the client is closed on errors
                this.reconnect().catch(err => {
                    this.logger.error({ msg: 'IMAP reconnection error', account: this.account, err });
                });
            });

            imapClient.on('response', data => {
                metricsMeta({}, this.logger, 'imapResponses', 'inc', data);

                // update byte counters as well
                let imapStats = imapClient.stats(true);

                metricsMeta({}, this.logger, 'imapBytesSent', 'inc', imapStats.sent);
                metricsMeta({}, this.logger, 'imapBytesReceived', 'inc', imapStats.received);
            });

            imapClient.on('close', async () => {
                this.connections.delete(imapClient);
                await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());
                imapClient?.log.info({ msg: 'Connection closed', type: 'imapClient', account: this.account, disabled: imapClient.disabled });

                if (['init', 'connecting', 'syncing', 'connected'].includes(this.state)) {
                    this.state = 'disconnected';
                    await this.setStateVal();
                    await emitChangeEvent(this.logger, this.account, 'state', this.state);
                }

                try {
                    for (let [, mailbox] of this.mailboxes) {
                        if (mailbox.syncing) {
                            try {
                                // set failure flag
                                await this.redis.hSetNew(
                                    this.getAccountKey(),
                                    'syncError',
                                    JSON.stringify({
                                        path: mailbox.path,
                                        time: new Date().toISOString(),
                                        error: {
                                            error: 'Connection closed unexpectedly'
                                        }
                                    })
                                );
                            } catch (err) {
                                // ignore
                            }
                        }

                        if (mailbox.selected) {
                            // should be at most one though
                            await mailbox.onClose();
                        }
                    }
                } catch (err) {
                    imapClient.log.error({ msg: 'Connection close error', err });
                }

                try {
                    if (!imapClient.disabled && imapClient === this.imapClient && !this._connecting) {
                        imapClient.log.debug({ msg: 'Requesting reconnection due to unexpected close', type: 'imapClient', account: this.account });
                        await this.reconnect();
                    }
                } catch (err) {
                    imapClient.log.error({ msg: 'Reconnection error', err });
                }

                imapClient = null;
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

                this.setupSubConnections()
                    .then(result => {
                        this.logger.info({ msg: 'Set up subconnections', account: this.account, result });
                    })
                    .catch(err => {
                        this.logger.error({ msg: 'Failed to set up subconnections', account: this.account, err });
                    });
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

    async delete() {
        if (this.isClosed || this.isClosing) {
            return;
        }
        this.isClosing = true;

        if (this.imapClient) {
            this.imapClient.disabled = true;
            this.imapClient.close();
            if (this.commandClient) {
                this.commandClient.close();
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

    async currentState() {
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

        return await this.getCurrentListing(options, true);
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
     * @returns {Boolean|Stream} Attachment stream or `false` if not found
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
     * @returns {Boolean|Stream} Attachment stream or `false` if not found
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

        let path = normalizePath(options.path);
        if (['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts', '\\All'].includes(path)) {
            let resolvedPath = await this.getSpecialUseMailbox(path);
            if (resolvedPath) {
                path = resolvedPath.path;
            }
        }

        if (!this.mailboxes.has(path)) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(path);

        let listing = await mailbox.listMessages(options, true, true);
        return listing;
    }

    async deleteMailbox(path) {
        this.checkIMAPConnection();

        const connectionClient = await this.getImapConnection(true, 'deleteMailbox');

        let result = {
            path,
            deleted: false // set to true if mailbox is actually deleted
        };
        try {
            let lock = await connectionClient.getMailboxLock(path, { description: `Delete mailbox ${path}` });

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
        const accountPaths = [].concat(accountData.path || '*');
        if (!accountPaths.length) {
            accountPaths.push('*');
        }

        this.getCurrentListing()
            .then(listing => {
                let syncNeeded = new Set();
                for (let entry of listing) {
                    if (
                        // previously unseen
                        !this.mailboxes.has(normalizePath(entry.path))
                    ) {
                        if (!accountPaths.includes('*')) {
                            if (!accountPaths.includes(entry.path) && !accountPaths.includes(entry.specialUse)) {
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

        const connectionClient = await this.getImapConnection(true, 'getQuota');

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

        const connectionClient = await this.getImapConnection(true, 'createMailbox');

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

        const connectionClient = await this.getImapConnection(true, 'renameMailbox');

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
            const { oauth2User, accessToken, oauth2App } = await this.loadOAuth2AccountCredentials(accountData, this, 'smtp');
            const providerData = oauth2ProviderData(oauth2App.provider);

            smtpConnectionConfig = Object.assign(
                {
                    auth: {
                        user: oauth2User,
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

        let { localAddress: address, name, addressSelector: selector } = await getLocalAddress(redis, 'smtp', this.account, data.localAddress);
        this.logger.info({
            msg: 'Selected local address',
            account: this.account,
            proto: 'SMTP',
            address,
            name,
            selector,
            requestedLocalAddress: data.localAddress
        });

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
        if (data.proxy) {
            smtpSettings.proxy = data.proxy;
        } else if (accountData.proxy) {
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

        const networkRouting = smtpSettings.localAddress || smtpSettings.proxy ? {} : null;

        if (networkRouting && smtpSettings.localAddress) {
            networkRouting.localAddress = smtpSettings.localAddress;
        }

        if (networkRouting && smtpSettings.proxy) {
            networkRouting.proxy = smtpSettings.proxy;
        }

        if (networkRouting && smtpSettings.name) {
            networkRouting.name = smtpSettings.name;
        }

        if (networkRouting && data.localAddress && data.localAddress !== networkRouting.localAddress) {
            networkRouting.requestedLocalAddress = data.localAddress;
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
                // MessageId was overridden
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
                envelope,
                networkRouting
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

                        const connectionClient = await this.getImapConnection(true, 'submitMessage');

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
                        command: err.command,
                        networkRouting
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

                networkRouting,

                job: jobData
            });

            err.code = err.code || 'SubmitFail';
            err.statusCode = Number(err.responseCode) || null;

            err.info = { networkRouting };

            throw err;
        }
    }

    async uploadMessage(data) {
        this.checkIMAPConnection();

        let { raw, messageId, documentStoreUsed, referencedMessage } = await this.prepareRawMessage(data);

        // Upload message to selected folder
        try {
            const connectionClient = await this.getImapConnection(true, 'uploadMessage');

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
                    await this.getCurrentListing(false, true);
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
        const accountData = await this.accountObject.loadAccountData();

        if (!accountData.subconnections?.length && !this.subconnections.length) {
            // Nothing to do here
            return null;
        }

        const mailboxes = [];

        const listing = await this.getCurrentListing(false, true);

        for (const path of accountData.subconnections || []) {
            const entry = listing.find(entry => path === entry.path || path === entry.specialUse);

            if (!entry) {
                mailboxes.push({
                    path,
                    disabled: true,
                    state: 'disabled',
                    disabledReason: 'Mailbox folder not found'
                });
                continue;
            }

            const accountPaths = [].concat(accountData.path || '*');
            if (!accountPaths.length) {
                accountPaths.push('*');
            }

            if (accountPaths[0] === entry.path) {
                mailboxes.push({
                    path: entry.path,
                    disabled: true,
                    state: 'disabled',
                    disabledReason: 'Covered by the primary connection'
                });
                continue;
            }

            if (this.isGmail && accountPaths.includes('*') && !['\\Trash', '\\Junk'].includes(entry.specialUse)) {
                // no need to check this folder, as \All already covers it
                this.logger.info({ msg: 'Skip subconnection', path, reason: 'Covered by the All Mail folder' });
                mailboxes.push({
                    path: entry.path,
                    disabled: true,
                    state: 'disabled',
                    disabledReason: 'Covered by the "All Mail" folder'
                });
                continue;
            }

            if (!this.isGmail && accountPaths.includes('*') && entry.specialUse === '\\Inbox') {
                // already the default
                this.logger.info({ msg: 'Skip subconnection', path, reason: 'Trying to use the default folder' });
                mailboxes.push({
                    path: entry.path,
                    disabled: true,
                    state: 'disabled',
                    disabledReason: 'Can not use the default folder'
                });
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

                if (!subconnection.disabled) {
                    try {
                        subconnection.removeAllListeners();
                        subconnection.close();
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to close unlisted subconnection', path: subconnection.path, err });
                    }
                }
            }
        }

        // create missing
        for (const mailbox of mailboxes) {
            if (this.subconnections.find(subconnection => mailbox.path === subconnection.path)) {
                // already exists
                continue;
            }

            if (mailbox.disabled) {
                this.subconnections.push(mailbox);
                continue;
            }

            // create new
            const subconnection = new Subconnection({
                parent: this,
                account: this.account,
                mailbox,
                getImapConfig: async () => await this.getImapConfig(),
                logger: this.logger.child({
                    cid: `${this.cid}:s:${this.connectionCount++}`,
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

        return this.subconnections.length;
    }

    closeSubconnections() {
        // remove unneeded
        for (let i = this.subconnections.length - 1; i >= 0; i--) {
            let subconnection = this.subconnections[i];

            // not listed anymore
            this.subconnections.splice(i, 1);
            if (!subconnection.disabled) {
                try {
                    subconnection.removeAllListeners();
                    subconnection.close();
                } catch (err) {
                    this.logger.error({ msg: 'Failed to close unlisted subconnection', path: subconnection.path, err });
                }
            }
        }
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

module.exports = { IMAPClient };
