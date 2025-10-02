'use strict';

const { parentPort } = require('worker_threads');
const { ImapFlow } = require('imapflow');
const { Mailbox } = require('./imap/mailbox');
const logger = require('../logger');
const packageData = require('../../package.json');
const { backOff } = require('exponential-backoff');
const msgpack = require('msgpack5')();

const { oauth2ProviderData } = require('../oauth2-apps');
const { BaseClient } = require('./base-client');
const { oauth2Apps } = require('../oauth2-apps');

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
    getDuration,
    LRUCache
} = require('../tools');

// Time to wait between mailbox resync operations (15 minutes)
const RESYNC_DELAY = 15 * 60;
// TTL for ensuring main mailbox selection after operations (5 seconds)
const ENSURE_MAIN_TTL = 5 * 1000;

const { AUTH_ERROR_NOTIFY, AUTH_SUCCESS_NOTIFY, CONNECT_ERROR_NOTIFY, DEFAULT_DOWNLOAD_CHUNK_SIZE, MAX_BACKOFF_DELAY, TLS_DEFAULTS } = require('../consts');

// Configuration for download operations - chunk size for streaming attachments/messages
const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;
// Flag to disable IMAP compression (COMPRESS extension) if needed for debugging or compatibility
const DISABLE_IMAP_COMPRESSION = getBoolean(readEnvValue('EENGINE_DISABLE_COMPRESSION'));
// Custom socket timeout for IMAP connections
const IMAP_SOCKET_TIMEOUT = getDuration(readEnvValue('EENGINE_IMAP_SOCKET_TIMEOUT'));

// Gmail API configuration
const GMAIL_API_BASE = 'https://gmail.googleapis.com';

logger.trace({ msg: 'Worker configuration', DOWNLOAD_CHUNK_SIZE, DISABLE_IMAP_COMPRESSION, IMAP_SOCKET_TIMEOUT });

const settings = require('../settings');
const { redis } = require('../db');

/**
 * Sends metrics data to the parent process for monitoring and analytics
 * @param {Object} meta - Metadata object
 * @param {Object} logger - Logger instance
 * @param {string} key - Metric key
 * @param {string} method - Metric method (e.g., 'inc', 'dec')
 * @param {...any} args - Additional arguments for the metric
 */
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

/**
 * Main IMAP client class that handles all IMAP operations for an email account
 * Extends BaseClient for common email client functionality
 */
class IMAPClient extends BaseClient {
    constructor(account, options) {
        options = options || {};
        super(account, options);

        // Connection state flags
        this.isClosing = false;
        this.isClosed = false;

        // Base IMAP configuration that will be merged with account-specific settings
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

        // Map of normalized mailbox paths to Mailbox instances
        this.mailboxes = new Map();

        // Timer for handling untagged EXPUNGE responses
        this.untaggedExpungeTimer = false;

        // Timer for periodic mailbox listing refresh
        this.refreshListingTimer = false;
        // Timer for periodic mailbox resynchronization
        this.resyncTimer = false;

        // Timer to ensure we return to the main mailbox after operations
        this.completedTimer = false;

        // LRU caches for efficient UID packing/unpacking operations
        this.pathCache = new LRUCache();
        this.idCache = new LRUCache();

        // Default folder delimiter (usually '/' or '.')
        this.defaultDelimiter = '/';

        // Array of subconnection instances for monitoring multiple folders simultaneously
        this.subconnections = [];

        // Flag indicating if the connection is paused
        this.paused = false;

        // Primary IMAP connection instance
        this.imapClient = null;
        // Secondary connection for commands that shouldn't interrupt IDLE
        this.commandClient = null;

        // Flag indicating if mailbox synchronization is in progress
        this.syncing = false;

        // Counter for generating unique connection IDs
        this.connectionCount = 0;
        // Set of all active connections for tracking
        this.connections = new Set();

        // Indexing strategy for this account ('full' or other modes)
        this.imapIndexer = null;

        // Current connection state
        this.state = 'connecting';

        // Reconnection tracking for capped exponential backoff
        this.reconnectRetries = 0;
        this.reconnectMaxDelay = 30000; // 30 seconds max delay

        // Error reconnection tracking
        this.errorReconnectDelay = 2000;
        this.errorReconnectMaxDelay = 30000;
        this.reconnectTimer = null;
    }

    /**
     * Called when a task is completed - ensures we return to the main mailbox
     * This prevents the connection from staying in a rarely-used mailbox
     */
    onTaskCompleted() {
        // check if we need to re-select main mailbox
        this.completedTimer = setTimeout(() => {
            clearTimeout(this.completedTimer);
            this.ensureMainMailbox().catch(err => this.logger.error({ msg: 'Failed to select main mailbox', err }));
        }, ENSURE_MAIN_TTL);
    }

    /**
     * Gets an IMAP connection for executing commands
     * @param {Object} connectionOptions - Connection options
     * @param {boolean} connectionOptions.allowSecondary - Whether to allow using secondary connections
     * @param {boolean} connectionOptions.noPool - Force creation of new connection
     * @param {Object} connectionOptions.connectionClient - Existing connection to reuse
     * @param {string} reason - Reason for requesting the connection (for logging)
     * @returns {Object} IMAP connection instance
     */
    async getImapConnection(connectionOptions, reason) {
        connectionOptions = connectionOptions || {};

        let { allowSecondary, noPool, connectionClient: existingConnectionClient } = connectionOptions || {};

        // If an existing connection was provided and it's usable, return it
        if (existingConnectionClient && existingConnectionClient.usable) {
            return existingConnectionClient;
        }

        // Determine if we're in a syncing state where secondary connections might be needed
        let syncing = this.syncing || ['init', 'connecting', 'syncing'].includes(this.state);
        if (!noPool && (!syncing || !allowSecondary)) {
            // Return the primary connection for most operations
            return this.imapClient;
        }

        // TODO: if noPool is true, then always create a new connection

        try {
            // Try to get or create a command connection for operations that shouldn't interrupt IDLE
            const connectionClient = await this.getCommandConnection(reason);
            if (connectionClient && connectionClient.usable) {
                connectionOptions.connectionClient = connectionClient;
                return connectionClient;
            } else {
                // fall back to default connection
                return this.imapClient;
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to acquire command connection', reason, err });
            return this.imapClient;
        }
    }

    /**
     * Gets or creates a command connection (secondary connection for non-IDLE operations)
     * This allows running IMAP commands without interrupting the primary connection's IDLE state
     * @param {string} reason - Reason for requesting the connection
     * @returns {Object} Command connection instance
     */
    async getCommandConnection(reason) {
        // Return existing command connection if available
        if (this.commandClient && this.commandClient.usable) {
            // use existing command channel
            return this.commandClient;
        }

        // Acquire a lock to prevent multiple simultaneous connection attempts
        let lock = this.accountObject.getLock();

        let connectLock;
        let lockKey = ['commandClient', this.account].join(':');

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

            // Check if IMAP is configured and enabled
            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                return null;
            }

            // Check again if command client was created while waiting for lock
            if (this.commandClient && this.commandClient.usable) {
                // use existing command channel created during the lock
                return this.commandClient;
            }

            // Generate unique connection ID for tracking
            const commandCid = `${this.cid}:c:${this.connectionCount++}`;

            let imapConfig = await this.getImapConfig(accountData);

            // Create new IMAP connection with specific settings for command operations
            let commandClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    disableAutoIdle: true, // Don't automatically IDLE on this connection
                    id: commandCid,
                    socketTimeout: 60 * 1000, // 60 second timeout for command operations
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

            // Mark this as a secondary connection for identification
            commandClient.secondaryConnection = true;

            // Set up error handling for the command connection
            const onErr = err => {
                commandClient?.log.error({ msg: 'IMAP connection error', cid: commandCid, channel: 'command', account: this.account, err });
                commandClient.close();
                this.commandClient = null;
            };
            commandClient.on('error', onErr);

            try {
                await commandClient.connect();
                commandClient.log.info({ msg: 'Command channel connected', cid: commandCid, channel: 'command', account: this.account });
            } catch (err) {
                if (this.connections.delete(commandClient)) {
                    await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());
                }
                commandClient.log.error({ msg: 'Failed to connect command client', cid: commandCid, channel: 'command', account: this.account, err });
                throw err;
            }

            // Clean up when connection closes
            commandClient.on('close', async () => {
                if (this.connections.delete(commandClient)) {
                    await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());
                }
                commandClient.log.info({ msg: 'Connection closed', cid: commandCid, channel: 'command', account: this.account });

                this.commandClient = null;
                commandClient.removeAllListeners();
                commandClient = null;
            });

            return commandClient;
        } finally {
            // Always release the lock
            this.logger.debug({ msg: 'Releasing connection lock', lockKey, index: connectLock.index });
            await lock.releaseLock(connectLock);
            this.logger.debug({ msg: 'Released connection lock', lockKey, index: connectLock.index });
        }
    }

    /**
     * Ensures the main mailbox is selected on the primary connection
     * This is called after operations to return to the monitored mailbox
     */
    async ensureMainMailbox() {
        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        // start waiting for changes
        await this.select(mainPath);
    }

    /**
     * Packs a mailbox path and UID into a compact base64url string for use as message IDs
     * This creates a unique identifier that can be unpacked later to retrieve the message
     * @param {Object|string} mailbox - Mailbox object or path
     * @param {number} uid - Message UID
     * @returns {string|false} Base64url encoded ID or false on error
     */
    async packUid(mailbox, uid) {
        if (isNaN(uid) || !mailbox) {
            return false;
        }

        if (typeof uid !== 'number') {
            uid = Number(uid);
        }

        // Convert mailbox path to mailbox object if needed
        if (typeof mailbox === 'string') {
            if (this.mailboxes.has(normalizePath(mailbox))) {
                mailbox = this.mailboxes.get(normalizePath(mailbox));
            } else {
                return false;
            }
        }

        // Get stored mailbox status including UID validity
        const storedStatus = await mailbox.getStoredStatus();
        if (!validUidValidity(storedStatus.uidValidity) || !storedStatus.path) {
            return false;
        }

        // Pack UID validity and mailbox path into a buffer
        let uidValBuf = Buffer.alloc(8);
        uidValBuf.writeBigUInt64BE(storedStatus.uidValidity, 0);
        let mailboxBuf = Buffer.concat([uidValBuf, Buffer.from(storedStatus.path)]);

        // Get or create a numeric mailbox ID for efficient storage
        let mailboxId;
        if (this.pathCache.has(mailboxBuf.toString('hex'))) {
            mailboxId = this.pathCache.get(mailboxBuf.toString('hex'));
        } else {
            mailboxId = await this.redis.zGetMailboxId(this.getAccountKey(), this.getMailboxHashKey(), mailboxBuf);
            if (isNaN(mailboxId) || typeof mailboxId !== 'number') {
                return false;
            }

            // Cache for future use
            this.pathCache.set(mailboxBuf.toString('hex'), mailboxId);
            this.idCache.set(mailboxId, mailboxBuf);
        }

        // Pack mailbox ID and UID into final buffer
        let uidBuf = Buffer.alloc(4 + 4);
        uidBuf.writeUInt32BE(mailboxId, 0);
        uidBuf.writeUInt32BE(uid, 4);

        let res = uidBuf.toString('base64url');

        return res;
    }

    /**
     * Unpacks a base64url encoded ID back into mailbox path and UID
     * @param {string|Buffer} id - Packed message ID
     * @returns {Object|false} Object with path, uidValidity, and uid or false on error
     */
    async unpackUid(id) {
        const packed = Buffer.isBuffer(id) ? id : Buffer.from(id, 'base64url');

        let mailboxId = packed.readUInt32BE(0);
        let uid = packed.readUInt32BE(4);

        // Look up mailbox path from ID
        let mailboxBuf;
        if (this.idCache.has(mailboxId)) {
            mailboxBuf = this.idCache.get(mailboxId);
        } else {
            mailboxBuf = await this.redis.zGetMailboxPathBuffer(this.getMailboxHashKey(), mailboxId);
            if (!mailboxBuf) {
                return false;
            }

            // Cache for future use
            this.pathCache.set(mailboxBuf.toString('hex'), mailboxId);
            this.idCache.set(mailboxId, mailboxBuf);
        }

        if (!mailboxBuf) {
            return false;
        }

        // Extract path and UID validity from buffer
        let path = mailboxBuf.subarray(8).toString();
        return {
            path,
            uidValidity: mailboxBuf.readBigUInt64BE(0).toString(),
            uid
        };
    }

    /**
     * Unpacks a text content ID to get message location and text part paths
     * @param {string} textId - Base64url encoded text ID
     * @returns {Object} Object with message info and text parts array
     */
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

    /**
     * Clears all cached data for a specific mailbox
     * Used when a mailbox is deleted or needs to be reset
     * @param {Object} entry - Mailbox entry with path
     */
    async clearMailboxEntry(entry) {
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

    /**
     * Retrieves the current mailbox listing from the IMAP server
     * Compares with stored listing to detect new/deleted/renamed folders
     * @param {Object} options - Listing options
     * @param {Object} connectionOptions - Connection options
     * @returns {Array} Array of mailbox objects
     */
    async getCurrentListing(options, connectionOptions) {
        options = options || {};

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'getCurrentListing');
        if (!connectionClient) {
            this.imapClient.close();
            let error = new Error('Failed to get connection');
            error.code = 'ConnectionError';
            throw error;
        }

        let accountData = await this.accountObject.loadAccountData();

        // Build hints for special-use folders from account configuration
        let specialUseHints = {};
        for (let type of ['sent', 'drafts', 'junk', 'trash', 'archive']) {
            if (accountData.imap && accountData.imap[`${type}MailPath`]) {
                specialUseHints[type] = accountData.imap[`${type}MailPath`];
            }
        }

        options = Object.assign({}, options, {
            specialUseHints
        });

        // Get mailbox listing from server
        let listing = await connectionClient.list(options);
        if (!listing.length) {
            // server bug, the list can never be empty
            this.imapClient.close();
            let error = new Error('Server bug: empty mailbox listing');
            error.code = 'ServerBug';
            throw error;
        }

        // Extract delimiter from INBOX (most reliable source)
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

        // compare listings to detect changes
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

        // Check for deleted mailboxes
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

            // Atomic update of the mailbox listing
            await this.redis.multi().del(this.getMailboxListKey()).hmset(this.getMailboxListKey(), listingObject).exec();
        }

        return listing;
    }

    /**
     * Refreshes the folder list and creates Mailbox instances for new folders
     * @returns {Set} Set of newly created mailbox instances that need syncing
     */
    async refreshFolderList() {
        if (this.refreshingList) {
            return;
        }
        this.refreshingList = true;

        try {
            let accountData = await this.accountObject.loadAccountData();

            // Get configured paths to monitor (default to all)
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
                    // Apply filtering rules based on account configuration
                    if (!accountPaths.includes('*')) {
                        if (!accountPaths.includes(entry.path) && !accountPaths.includes(entry.specialUse)) {
                            // ignore changes
                            entry.syncDisabled = true;
                        }
                    } else if (this.isGmail && !['\\All', '\\Junk', '\\Trash'].includes(entry.specialUse)) {
                        // For Gmail, only monitor All Mail, Spam, and Trash folders
                        // Other folders are just labels and covered by All Mail
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

    /**
     * Establishes initial IMAP connection and performs setup
     * Sets up event handlers and determines account type (Gmail, Outlook, etc.)
     * @returns {Object} Connection response
     */
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

        // Detect email provider type based on capabilities and folder structure
        // User might have disabled All Mail folder access and in that case we should treat it as a regular mailbox
        this.isGmail = imapClient.capabilities.has('X-GM-EXT-1') && listing.some(entry => entry.specialUse === '\\All');
        this.isOutlook = /\boffice365\.com$/i.test(imapClient.host); // || /The Microsoft Exchange IMAP4 service is ready/.test(imapClient.greeting);
        this.isLarkSuite = /\blarksuite\.com$/i.test(imapClient.host);

        const accountPaths = [].concat(accountData.path || '*');
        if (!accountPaths.length) {
            accountPaths.push('*');
        }

        // store synced folder entries
        const mainList = [];

        // Process mailbox listing and determine which folders to monitor
        for (let entry of listing) {
            if (!accountPaths.includes('*')) {
                // Limited path monitoring - only specific folders
                if (!accountPaths.includes(entry.path) && !accountPaths.includes(entry.specialUse)) {
                    entry.syncDisabled = true;
                } else {
                    // insert to stored list with the sorting index
                    let index = accountPaths.indexOf(entry.path) >= 0 ? accountPaths.indexOf(entry.path) : accountPaths.indexOf(entry.specialUse);
                    mainList.push({ index, entry });
                }
            } else {
                // Monitor all folders - determine main folder for IDLE
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

        // Set up event handlers for IMAP notifications

        // Process untagged EXISTS responses (new messages)
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

        // Handle mailbox open events
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

        // Handle mailbox close events
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

        // Handle flag changes
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

    /**
     * Handles reconnection with exponential backoff
     * @param {boolean} force - Force reconnection even if paused/closed
     * @returns {boolean} Success status
     */
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
            // Close all subconnections and command client when forcing reconnection
            this.closeSubconnections();
            if (this.commandClient) {
                this.commandClient.close();
            }
        }

        this._connecting = true;
        this.isClosed = false;

        let accountData = await this.accountObject.loadAccountData();
        // Get indexing strategy for this account
        this.imapIndexer = typeof accountData.imapIndexer === 'string' && accountData.imapIndexer ? accountData.imapIndexer : 'full';

        try {
            this.logger.debug({ msg: 'Initiating connection to IMAP' });
            // Use exponential backoff for connection attempts
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
                    await this.redis.hdel(this.getAccountKey(), 'syncError');
                } catch (err) {
                    // ignore
                }
            }
        } catch (err) {
            // ended in an unconncted state
            this.logger.error({ msg: 'Failed to set up connection, will retry', err });

            // Calculate delay with capped exponential backoff
            const retryDelay = Math.min(this.reconnectMaxDelay, 1000 * Math.pow(1.5, Math.min(this.reconnectRetries, 10)));
            this.reconnectRetries++;

            this.logger.info({
                msg: 'Scheduling reconnection attempt',
                attempt: this.reconnectRetries,
                delay: retryDelay
            });

            return setTimeout(() => {
                this.reconnect()
                    .then(() => {
                        // Reset counter on successful reconnect
                        this.reconnectRetries = 0;
                    })
                    .catch(err => {
                        this.logger.error({
                            msg: 'Connection retry failed',
                            err,
                            attempt: this.reconnectRetries
                        });
                    });
            }, retryDelay);
        }

        this.logger.debug({
            msg: 'Connection established',
            hasClient: !!this.imapClient,
            usable: this.imapClient && this.imapClient.usable,
            connected: this.isConnected()
        });
    }

    /**
     * Synchronizes all mailboxes and schedules periodic resync
     * Handles the main synchronization loop for the account
     */
    async syncMailboxes() {
        // Clear any pending timers
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        if (!this.imapClient || !this.imapClient.usable) {
            this.logger.debug({ msg: 'Skipped syncing', reason: 'no imap client' });
            return;
        }

        // Refresh folder list and sync new folders
        let synced = await this.refreshFolderList();

        // Sync existing folders that weren't just synced
        for (let mailbox of this.mailboxes.values()) {
            if (!synced || !synced.has(mailbox)) {
                await mailbox.sync();
            }
        }

        if (!this.imapClient || !this.imapClient.usable) {
            this.logger.debug({ msg: 'Syncing completed, skipping state change', reason: 'no imap client' });
            return;
        }

        // Update state to connected
        this.state = 'connected';

        await this.setStateVal();

        // Store IMAP server capabilities for reference
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
        // Clear error state on successful connection
        await this.redis.hdel(this.getAccountKey(), 'lastErrorState', 'lastError:errorCount', 'lastError:first');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        // Select main mailbox for IDLE monitoring
        let mainPath = this.main ? this.main.path : 'INBOX';
        if (this.mailbox && normalizePath(this.mailbox.path) === normalizePath(mainPath)) {
            // already selected
            return;
        }

        this.logger.debug({ msg: 'Syncing completed, selecting main path', path: mainPath });
        // start waiting for changes
        await this.select(mainPath);

        // Schedule next sync cycle
        let retryCount = 0;
        let setSyncTimer = () => {
            clearTimeout(this.resyncTimer);
            this.resyncTimer = setTimeout(() => {
                this.syncMailboxes()
                    .then(() => {
                        // Reset retry count on successful sync
                        retryCount = 0;
                    })
                    .catch(err => {
                        this.logger.error({ msg: 'Mailbox Sync Error', err, retryCount });
                        retryCount++;
                        // Exponential backoff with max delay of 30 seconds
                        const retryDelay = Math.min(30000, 2000 * Math.pow(2, retryCount));
                        this.logger.warn({ msg: 'Scheduling sync retry with backoff', retryDelay, retryCount });
                        setTimeout(setSyncTimer, retryDelay);
                    });
            }, this.resyncDelay);
        };
        setSyncTimer();
    }

    /**
     * Selects a mailbox on the IMAP connection
     * @param {string} path - Mailbox path to select
     */
    async select(path) {
        if (!this.mailboxes.has(normalizePath(path))) {
            // nothing to do here, mailbox not found
            this.logger.debug({ msg: 'Can not select unlisted path', path });
            return;
        }

        let mailbox = this.mailboxes.get(normalizePath(path));
        await mailbox.select();
    }

    /**
     * Builds IMAP configuration from account data
     * Handles both OAuth2 and regular authentication
     * @param {Object} accountData - Account configuration data
     * @param {Object} ctx - Context object (defaults to this)
     * @returns {Object} Complete IMAP configuration
     */
    async getImapConfig(accountData, ctx) {
        if (!accountData) {
            accountData = await this.accountObject.loadAccountData();
        }

        // the same method is also called by subconnections, so do not mark the primary connection as failing if something happens
        ctx = ctx || this;
        let imapConnectionConfig;

        if (accountData.oauth2 && accountData.oauth2.auth) {
            // OAuth2 authentication configuration
            const { oauth2User, accessToken, oauth2App } = await this.loadOAuth2AccountCredentials(accountData, ctx, 'imap');
            const providerData = oauth2ProviderData(oauth2App.provider, oauth2App.cloud);

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
            // Regular password authentication
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

        // Configure TLS settings
        if (!imapConnectionConfig.tls) {
            imapConnectionConfig.tls = {};
        }

        // Set local address for outgoing connections (for IP rotation)
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

        // Apply default TLS settings
        for (let key of Object.keys(TLS_DEFAULTS)) {
            if (!(key in imapConnectionConfig.tls)) {
                imapConnectionConfig.tls[key] = TLS_DEFAULTS[key];
            }
        }

        // reload log config
        await this.accountLogger.reload();

        // Build final IMAP configuration
        let imapConfig = Object.assign(
            {
                resyncDelay: RESYNC_DELAY,
                id: this.cid,
                emitLogs: this.accountLogger.enabled
            },
            imapConnectionConfig,
            this.imapConfig,
            {
                // Allow customization of client identification
                clientInfo: {
                    name: (await settings.get('imapClientName')) || this.imapConfig.clientInfo.name,
                    version: (await settings.get('imapClientVersion')) || this.imapConfig.clientInfo.version,
                    vendor: (await settings.get('imapClientVendor')) || this.imapConfig.clientInfo.vendor,
                    'support-url': (await settings.get('imapClientSupportUrl')) || this.imapConfig.clientInfo['support-url']
                }
            }
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

        // Provider-specific workarounds
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

        // Apply global settings
        if (DISABLE_IMAP_COMPRESSION) {
            imapConfig.disableCompression = true;
        }

        if (IMAP_SOCKET_TIMEOUT) {
            imapConfig.socketTimeout = IMAP_SOCKET_TIMEOUT;
        }

        // Handle certificate validation settings
        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
        if (ignoreMailCertErrors && imapConfig?.tls?.rejectUnauthorized !== false) {
            imapConfig.tls = imapConfig.tls || {};
            imapConfig.tls.rejectUnauthorized = false;
        }

        return imapConfig;
    }

    /**
     * Initializes a new IMAP connection and sets up event handlers
     * This is the main connection setup method
     */
    async start() {
        if (this.paused) {
            this.logger.debug({ msg: 'Skipped start', reason: 'paused' });
            return;
        }

        let initialState = this.state;

        // Clean up existing connection if any
        if (this.imapClient) {
            this.logger.debug({ msg: 'Clearing previous connection' });
            let prevImapClient = this.imapClient;
            prevImapClient.disabled = true;
            try {
                prevImapClient.removeAllListeners();

                const prevImapErrorHandler = err => {
                    this.logger.error({ msg: 'IMAP connection error', type: 'imapClient', previous: true, account: this.account, err });
                };

                prevImapClient.once('error', prevImapErrorHandler);
                prevImapClient.close();
                prevImapClient.removeListener('error', prevImapErrorHandler);

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

            // Load notification settings
            this.notifyFrom = accountData.notifyFrom;
            this.syncFrom = accountData.syncFrom;

            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                // can not make a connection
                this.state = 'unset';
                return;
            }

            let imapConfig = await this.getImapConfig(accountData);

            // Generate unique connection ID
            imapConfig.id = `${imapConfig.id}:m:${this.connectionCount++}`;

            // Create new IMAP connection instance
            let imapClient = new ImapFlow(
                Object.assign({}, imapConfig, {
                    expungeHandler: async payload => await this.expungeHandler(payload)
                })
            );
            this.connections.add(imapClient);
            await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());

            imapClient.log.debug({ msg: 'Created primary client' });

            this.imapClient = imapClient;

            // Mark as primary connection
            imapClient.primaryConnection = true;

            // Forward IMAP logs to account logger
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

            // Handle connection errors
            imapClient.on('error', err => {
                imapClient?.log.error({ msg: 'IMAP connection error', type: 'imapClient', account: this.account, err });
                if (imapClient !== this.imapClient || this._connecting) {
                    return;
                }
                imapClient.close(); // ensure the client is closed on errors

                // Debounced reconnection with exponential backoff
                if (!this.reconnectTimer) {
                    // Calculate delay with cap
                    this.errorReconnectDelay = Math.min(this.errorReconnectMaxDelay, this.errorReconnectDelay * 1.5);

                    this.logger.info({
                        msg: 'Scheduling error-triggered reconnection',
                        delay: this.errorReconnectDelay
                    });

                    this.reconnectTimer = setTimeout(() => {
                        this.reconnectTimer = null;
                        this.reconnect()
                            .then(() => {
                                // Reset delay on success
                                this.errorReconnectDelay = 2000;
                            })
                            .catch(err => {
                                this.logger.error({
                                    msg: 'IMAP reconnection error',
                                    account: this.account,
                                    err,
                                    nextDelay: this.errorReconnectDelay
                                });
                            });
                    }, this.errorReconnectDelay);
                }
            });

            // Track IMAP command/response metrics
            imapClient.on('response', data => {
                metricsMeta({}, this.logger, 'imapResponses', 'inc', data);

                // update byte counters as well
                let imapStats = imapClient.stats(true);

                metricsMeta({}, this.logger, 'imapBytesSent', 'inc', imapStats.sent);
                metricsMeta({}, this.logger, 'imapBytesReceived', 'inc', imapStats.received);
            });

            // Handle connection close events
            imapClient.on('close', async () => {
                const wasDeleted = this.connections.delete(imapClient);

                if (wasDeleted) {
                    try {
                        await this.redis.hSetExists(this.getAccountKey(), 'connections', this.connections.size.toString());
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to update connection count in Redis', err });
                    }
                }
                imapClient?.log.info({ msg: 'Connection closed', type: 'imapClient', account: this.account, disabled: imapClient.disabled });

                // Update state on unexpected disconnect
                if (['init', 'connecting', 'syncing', 'connected'].includes(this.state)) {
                    this.state = 'disconnected';
                    await this.setStateVal();
                    await emitChangeEvent(this.logger, this.account, 'state', this.state);
                }

                try {
                    // Handle cleanup for all mailboxes
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
                    // Attempt reconnection if this was an unexpected close
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
                // Establish connection and perform initial sync
                await this.connect();

                // Check if this is the first successful connection
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

                // Send appropriate notifications based on connection history
                if (isFirstSuccessfulConnection) {
                    this.logger.info({ msg: 'Successful login without a previous active session', account: this.account, isiInitial, prevActive: false });
                    await this.notify(false, AUTH_SUCCESS_NOTIFY, {
                        user: imapConfig.auth.user
                    });
                } else {
                    this.logger.info({ msg: 'Successful login with a previous active session', account: this.account, isiInitial, prevActive: true });
                }

                // Set up subconnections for monitoring multiple folders
                this.setupSubConnections()
                    .then(result => {
                        this.logger.info({ msg: 'Set up subconnections', account: this.account, result });
                    })
                    .catch(err => {
                        this.logger.error({ msg: 'Failed to set up subconnections', account: this.account, err });
                    });
            } catch (err) {
                // Handle various authentication and connection errors
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
            // Update state if it changed during connection
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

    /**
     * Initializes the IMAP client and starts the connection
     */
    async init() {
        await this.reconnect();
    }

    /**
     * Deletes the account and cleans up all resources
     * This permanently removes all cached data
     */
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

        // Clear all timers
        clearTimeout(this.refreshListingTimer);
        clearTimeout(this.untaggedExpungeTimer);
        clearTimeout(this.resyncTimer);
        clearTimeout(this.completedTimer);

        try {
            // Clean up all mailboxes
            for (let [, mailbox] of this.mailboxes) {
                if (mailbox.selected) {
                    await mailbox.onClose();
                }
                await mailbox.clear({ skipNotify: true });
                mailbox = false;
            }

            // Remove mailbox listing from Redis
            await this.redis.del(this.getMailboxListKey());
        } finally {
            this.isClosing = false;
            this.isClosed = true;
        }

        this.logger.info({ msg: 'Closed account', account: this.account });
    }

    /**
     * Closes the IMAP connection without deleting account data
     * Can be reopened later
     */
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

    /**
     * Checks if the IMAP connection is active and usable
     * @returns {boolean} Connection status
     */
    isConnected() {
        return this.imapClient && this.imapClient.usable && !this.isClosing && !this.isClosed;
    }

    /**
     * Gets the current connection state
     * @returns {string} Current state
     */
    async currentState() {
        if (this.state === 'connected' && !this.isConnected()) {
            this.state = 'disconnected';
        }
        return this.state;
    }

    /**
     * Validates that IMAP connection is available
     * @param {Object} connectionOptions - Connection options
     * @throws {Error} If connection is not available
     */
    checkIMAPConnection(connectionOptions) {
        connectionOptions = connectionOptions || {};

        if (
            !this.isConnected() &&
            !connectionOptions.noPool &&
            !connectionOptions.allowSecondary &&
            (!connectionOptions.connectionClient || !connectionOptions.connectionClient.usable)
        ) {
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
    async getText(textId, options, connectionOptions) {
        options = options || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let { message, textParts } = await this.getMessageTextPaths(textId);
        if (!message || !textParts || !textParts.length) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        let textType = (options.textType || '').toLowerCase().trim();

        // Process text parts based on requested type
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

        let result = await mailbox.getText(message, textParts, options, connectionOptions);

        // Filter result based on requested type
        if (textType && textType !== '*') {
            result = {
                [textType]: result[textType] || '',
                hasMore: result.hasMore
            };
        }

        return result;
    }

    /**
     * Retrieves a complete message by ID
     * @param {string} id - Message ID
     * @param {Object} options - Retrieval options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Message object or false if not found
     */
    async getMessage(id, options, connectionOptions) {
        options = options || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.getMessage(message, options, connectionOptions);
    }

    /**
     * Updates message flags/labels
     * @param {string} id - Message ID
     * @param {Object} updates - Update operations (e.g., flags to add/remove)
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Update result or false if failed
     */
    async updateMessage(id, updates, connectionOptions) {
        updates = updates || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.updateMessage(message, updates, connectionOptions);
    }

    /**
     * Updates multiple messages matching search criteria
     * @param {string} path - Mailbox path
     * @param {Object} search - Search criteria
     * @param {Object} updates - Update operations
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Update result or false if failed
     */
    async updateMessages(path, search, updates, connectionOptions) {
        updates = updates || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        if (!this.mailboxes.has(normalizePath(path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(path));

        return await mailbox.updateMessages(search, updates, connectionOptions);
    }

    /**
     * Lists all mailboxes/folders
     * @param {Object} options - Listing options
     * @param {Object} connectionOptions - Connection options
     * @returns {Array} Array of mailbox objects
     */
    async listMailboxes(options, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        return await this.getCurrentListing(options, connectionOptions);
    }

    /**
     * Moves a message to another mailbox
     * @param {string} id - Message ID
     * @param {Object} target - Target mailbox info
     * @param {Object} options - Move options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Move result or false if failed
     */
    async moveMessage(id, target, options, connectionOptions) {
        target = target || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));

        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));
        return await mailbox.moveMessage(message, target, options, connectionOptions);
    }

    /**
     * Moves multiple messages to another mailbox
     * @param {string} source - Source mailbox path
     * @param {Object} search - Search criteria
     * @param {Object} target - Target mailbox info
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Move result or false if failed
     */
    async moveMessages(source, search, target, connectionOptions) {
        target = target || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        if (!this.mailboxes.has(normalizePath(source))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(source));

        let res = await mailbox.moveMessages(search, target, connectionOptions);

        // force sync target mailbox to show moved messages
        let targetMailbox = this.mailboxes.get(normalizePath(target.path));
        if (targetMailbox) {
            targetMailbox.sync().catch(err => this.logger.error({ msg: 'Mailbox sync error', path: target.path, err }));
        }

        return res;
    }

    /**
     * Deletes a message
     * @param {string} id - Message ID
     * @param {boolean} force - Force permanent deletion
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Delete result or false if failed
     */
    async deleteMessage(id, force, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        return await mailbox.deleteMessage(message, force, connectionOptions);
    }

    /**
     * Deletes multiple messages matching search criteria
     * @param {string} path - Mailbox path
     * @param {Object} search - Search criteria
     * @param {boolean} force - Force permanent deletion
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Delete result or false if failed
     */
    async deleteMessages(path, search, force, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        if (!this.mailboxes.has(normalizePath(path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(path));
        let res = await mailbox.deleteMessages(search, force, connectionOptions);

        // force sync target mailbox if messages were moved to trash
        if (res && res.moved && res.moved.destination) {
            let targetMailbox = this.mailboxes.get(normalizePath(res.moved.destination));
            if (targetMailbox) {
                targetMailbox.sync().catch(err => this.logger.error({ msg: 'Mailbox sync error', path: res && res.moved && res.moved.destination, err }));
            }
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
    async getAttachment(attachmentId, options, connectionOptions) {
        options = Object.assign(
            {
                chunkSize: DOWNLOAD_CHUNK_SIZE
            },
            options || {}
        );
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        // Unpack attachment ID to get message location and part number
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

        return mailbox.getAttachment(message, part, options, connectionOptions);
    }

    /**
     * Downloads attachment content as a buffer
     * @param {string} attachmentId - Attachment ID
     * @param {Object} options - Download options
     * @param {Object} connectionOptions - Connection options
     * @returns {Buffer|false} Attachment content or false if not found
     */
    async getAttachmentContent(attachmentId, options, connectionOptions) {
        let stream = await this.getAttachment(attachmentId, options, connectionOptions);
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
    async getRawMessage(id, options, connectionOptions) {
        options = Object.assign(
            {
                chunkSize: DOWNLOAD_CHUNK_SIZE
            },
            options || {}
        );
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let buf = Buffer.from(id, 'base64url');
        let message = await this.unpackUid(buf.subarray(0, 8));
        if (!message) {
            return false;
        }

        if (!this.mailboxes.has(normalizePath(message.path))) {
            return false; //?
        }

        let mailbox = this.mailboxes.get(normalizePath(message.path));

        // Use false as part to get the entire message
        return mailbox.getAttachment(message, false, options, connectionOptions);
    }

    /**
     * Lists messages in a mailbox with pagination and search
     * @param {Object} options - Listing options including path, search criteria, pagination
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Message listing or false if failed
     */
    async listMessages(options, connectionOptions) {
        options = options || {};
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        let path = normalizePath(options.path);

        // Handle special-use folder aliases
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

        let listing = await mailbox.listMessages(options, connectionOptions);
        return listing;
    }

    /**
     * Deletes a mailbox/folder
     * @param {string} path - Mailbox path to delete
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Delete result
     */
    async deleteMailbox(path, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'deleteMailbox');

        let result = {
            path,
            deleted: false // set to true if mailbox is actually deleted
        };

        try {
            // Acquire lock to prevent concurrent operations on the mailbox
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

        // Clean up local cache
        if (this.mailboxes.has(normalizePath(path))) {
            let mailbox = this.mailboxes.get(normalizePath(path));
            await mailbox.clear();
            mailbox = false;
        }

        return result;
    }

    /**
     * Refreshes mailbox listing after account configuration changes
     * @param {Object} accountData - Account data with path configuration
     */
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
                        // Apply filtering based on account configuration
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

    /**
     * Gets IMAP quota information
     * @param {Object} connectionOptions - Connection options
     * @returns {Object|false} Quota info or false if not supported
     */
    async getQuota(connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'getQuota');

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

    /**
     * Creates a new mailbox/folder
     * @param {string} path - Mailbox path to create
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Create result
     */
    async createMailbox(path, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'createMailbox');

        try {
            let result = await connectionClient.mailboxCreate(path);
            if (result) {
                result.created = !!result.created;
            }

            // Refresh listing to include new mailbox
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

    /**
     * Modifies a mailbox (rename and/or change subscription status)
     * @param {string} path - Current mailbox path
     * @param {string|Array<string>} newPath - New mailbox path (optional)
     * @param {boolean} subscribed - Subscription status (optional)
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Modify result
     */
    async modifyMailbox(path, newPath, subscribed, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'modifyMailbox');

        let result = {};

        // Handle rename if newPath is provided and different from path
        if (newPath) {
            let normalizedNewPath = [].concat(newPath || []).join('/');
            let normalizedPath = [].concat(path || []).join('/');

            if (normalizedNewPath !== normalizedPath) {
                try {
                    let renameResult = await connectionClient.mailboxRename(path, newPath);
                    if (renameResult) {
                        result.path = renameResult.path;
                        result.newPath = renameResult.newPath;
                        result.renamed = !!renameResult.newPath;
                        path = renameResult.newPath;

                        // Subscribe to renamed mailbox if not explicitly managing subscription
                        if (subscribed === undefined) {
                            try {
                                await connectionClient.mailboxSubscribe(renameResult.newPath);
                            } catch (err) {
                                this.logger.debug({ msg: 'Failed to subscribe mailbox', path: renameResult.newPath, err });
                            }
                        }
                    }
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
            } else {
                result.path = normalizedPath;
                result.renamed = false;
            }
        } else {
            result.path = [].concat(path || []).join('/');
        }

        // Handle subscription change if explicitly specified
        if (subscribed !== undefined) {
            try {
                if (subscribed) {
                    await connectionClient.mailboxSubscribe(path);
                } else {
                    await connectionClient.mailboxUnsubscribe(path);
                }
                result.subscribed = subscribed;
            } catch (err) {
                this.logger.debug({ msg: 'Failed to change subscription status', path, subscribed, err });
            }
        }

        // Refresh listing to update mailbox paths
        let accountData = await this.accountObject.loadAccountData();
        setImmediate(() => this.runPostListing(accountData));

        return result;
    }

    /**
     * Gets a mailbox by its special-use flag
     * @param {string} specialUse - Special-use flag (e.g., '\\Sent', '\\Drafts')
     * @returns {Object|undefined} Mailbox info if found
     */
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

    /**
     * Uploads a message to a mailbox
     * @param {Object} data - Message data including path, flags, content
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Upload result with message ID
     */
    async uploadMessage(data, connectionOptions) {
        connectionOptions = connectionOptions || { allowSecondary: true };

        this.checkIMAPConnection(connectionOptions);

        const connectionClient = await this.getImapConnection(connectionOptions, 'uploadMessage');

        // Prepare raw message for upload
        let { raw, messageId, documentStoreUsed, referencedMessage } = await this.prepareRawMessage(data, null, { connectionClient });

        // Upload message to selected folder
        try {
            let response = {};

            let uploadResponse = await connectionClient.append(data.path, raw, data.flags, data.internalDate);

            // Return to IDLE if using primary connection
            if (connectionClient === this.imapClient && this.imapClient.mailbox && !this.imapClient.idling) {
                // force back to IDLE
                this.imapClient.idle().catch(err => {
                    this.logger.error({ msg: 'IDLE error', err });
                });
            }

            // Pack response data
            if (uploadResponse.uid) {
                response.id = await this.packUid(uploadResponse.path || data.path, uploadResponse.uid);
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

            // Include reference information if provided
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
                    await this.getCurrentListing(false, { connectionClient });
                } catch (E) {
                    this.logger.error({ msg: 'Missing mailbox', err, E });
                }
            }

            err.code = 'UploadFail';
            err.statusCode = 502;
            throw err;
        }
    }

    /**
     * Handles EXPUNGE and VANISHED notifications in order
     * @param {Object} payload - Expunge event data
     */
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

    /**
     * Sets up subconnections for monitoring multiple folders simultaneously
     * @returns {number|null} Number of subconnections created
     */
    async setupSubConnections() {
        const accountData = await this.accountObject.loadAccountData();

        if (!accountData.subconnections?.length && !this.subconnections.length) {
            // Nothing to do here
            return null;
        }

        const mailboxes = [];

        const listing = await this.getCurrentListing(false, { allowSecondary: true });

        // Process each configured subconnection
        for (const path of accountData.subconnections || []) {
            const entry = listing.find(entry => path === entry.path || path === entry.specialUse);

            if (!entry) {
                // Mailbox not found - mark as disabled
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

            // Check if already covered by primary connection
            if (accountPaths[0] === entry.path) {
                mailboxes.push({
                    path: entry.path,
                    disabled: true,
                    state: 'disabled',
                    disabledReason: 'Covered by the primary connection'
                });
                continue;
            }

            // Gmail-specific checks
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

            // Non-Gmail checks
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

        // remove unneeded subconnections
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

        // create missing subconnections
        for (const mailbox of mailboxes) {
            if (this.subconnections.find(subconnection => mailbox.path === subconnection.path)) {
                // already exists
                continue;
            }

            if (mailbox.disabled) {
                this.subconnections.push(mailbox);
                continue;
            }

            // create new subconnection
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

            // Handle change notifications from subconnection
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

    /**
     * Closes all subconnections
     */
    closeSubconnections() {
        const subconnections = [...this.subconnections];
        this.subconnections = [];

        for (let subconnection of subconnections) {
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

    /**
     * Pauses the IMAP connection
     * @returns {boolean} Success status
     */
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

    /**
     * Resumes a paused IMAP connection
     * @returns {boolean} Success status
     */
    async resume() {
        if (!this.paused) {
            return false;
        }
        this.paused = false;
        if (this.isClosed) {
            this.isClosed = false;
        }

        this.logger.info({ msg: 'Creating connection', action: 'resume' });
        // do not wait
        this.init().catch(err => this.logger.error({ msg: 'Resuming failed', action: 'resume', err }));
    }

    /**
     * Lists email signatures (Gmail only via API)
     * @returns {Object} Signatures list with support status
     */
    async listSignatures() {
        const emptyResponse = { signatures: [], signaturesSupported: false };
        let accountData = await this.accountObject.loadAccountData();

        if (!accountData.oauth2.provider) {
            // Not an OAuth2 account
            return emptyResponse;
        }

        if (accountData?._app?.provider && !['gmail'].includes(accountData?._app?.provider)) {
            // Signatures not supported for this provider
            return emptyResponse;
        }

        const { accessToken, oauth2App } = await this.loadOAuth2AccountCredentials(accountData, this, 'api');

        if (oauth2App && !this.oAuth2Client) {
            this.oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, {
                logger: this.logger,
                logRaw: this.options.logRaw
            });
        }

        if (!oauth2App || !this.oAuth2Client) {
            return emptyResponse;
        }

        switch (oauth2App.provider) {
            case 'gmail': {
                // Fetch Gmail signatures via API
                const signatureListRes = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/settings/sendAs`, 'get');

                let signatures = signatureListRes?.sendAs
                    ?.map(entry => ({ address: entry.sendAsEmail, signature: entry.signature }))
                    .filter(entry => entry.signature);

                return { signatures, signaturesSupported: true };
            }
        }

        return emptyResponse;
    }
}

module.exports = { IMAPClient };
