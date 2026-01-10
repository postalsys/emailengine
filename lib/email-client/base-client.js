'use strict';

const { threadId: workerThreadId } = require('worker_threads');
const crypto = require('crypto');
const logger = require('../logger');
const settings = require('../settings');
const msgpack = require('msgpack5')();
const { templates } = require('../templates');
const { Gateway } = require('../gateway');
const os = require('os');
const punycode = require('punycode.js');
const { inlineHtml, inlineText, htmlToText, textToHtml, mimeHtml } = require('@postalsys/email-text-tools');
const { randomUUID: uuid } = require('crypto');
const { addTrackers } = require('../add-trackers');
const { getRawEmail } = require('../get-raw-email');
const { getTemplate } = require('@postalsys/templates');
const { deepEqual } = require('assert');
const { arfDetect } = require('../arf-detect');
const { createTransaction } = require('../redis-operations');
const simpleParser = require('mailparser').simpleParser;
const libmime = require('libmime');
const { bounceDetect } = require('../bounce-detect');
const ical = require('ical.js');
const { llmPreProcess } = require('../llm-pre-process');
const { oauth2Apps } = require('../oauth2-apps');
const { Account } = require('../account');
const { removeBcc } = require('../get-raw-email');
const {
    SmtpConfigBuilder,
    NetworkRoutingBuilder,
    NotificationBuilder,
    ProviderMessageIdHandler,
    SmtpErrorBuilder,
    SentMailCopyDecider
} = require('./message-builder');
const { NotificationHandler, postMetrics } = require('./notification-handler');
const { getMailTransport } = require('./smtp-pool-manager');

// Import various utility functions and constants
const {
    getSignedFormDataSync,
    getServiceSecret,
    convertDataUrisToAttachments,
    genBaseBoundary,
    getDuration,
    getByteSize,
    readEnvValue,
    emitChangeEvent,
    filterEmptyObjectValues,
    getDateBuckets
} = require('../tools');

// Import application constants
const {
    AUTH_ERROR_NOTIFY,
    ACCOUNT_INITIALIZED_NOTIFY,
    REDIS_PREFIX,
    MESSAGE_NEW_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    DEFAULT_DELIVERY_ATTEMPTS,
    MIME_BOUNDARY_PREFIX,
    DEFAULT_DOWNLOAD_CHUNK_SIZE,
    EMAIL_COMPLAINT_NOTIFY,
    MAX_INLINE_ATTACHMENT_SIZE,
    DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME,
    EMAIL_DELIVERY_ERROR_NOTIFY,
    EMAIL_SENT_NOTIFY
} = require('../consts');

// Configure download chunk size from environment or use default
const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;

// Configure maximum time to wait before disabling IMAP on authentication failures
const MAX_IMAP_AUTH_FAILURE_TIME = getDuration(readEnvValue('EENGINE_MAX_IMAP_AUTH_FAILURE_TIME')) || DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME;

// Map to track pending idempotency operations to prevent duplicate processing
const pendingIdempotencyOperations = new Map();

/**
 * Check if an error is a transient error that should be retried
 * @param {Error} err - The error to check
 * @returns {boolean} True if the error is transient
 */
function isTransientError(err) {
    if (!err) {
        return false;
    }

    // Check for specific OAuth2 request failures (like Gmail 500 errors)
    if (err.oauthRequest) {
        const status = err.oauthRequest.status;
        // 500, 502, 503, 504 are transient server errors
        if (status >= 500 && status < 600) {
            return true;
        }
    }

    // Check for network errors
    if (err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET' || err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
        return true;
    }

    // Check for specific error codes that indicate temporary issues
    if (err.statusCode >= 500 && err.statusCode < 600) {
        return true;
    }

    return false;
}

/**
 * Retry a function with exponential backoff for transient errors
 * @param {Function} fn - Async function to retry
 * @param {Object} options - Retry options
 * @returns {Promise} Result of the function
 */
async function retryOnTransientError(fn, options = {}) {
    const maxAttempts = options.maxAttempts || 3;
    const baseDelay = options.baseDelay || 1000; // 1 second
    const logger = options.logger;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await fn();
        } catch (err) {
            const isLastAttempt = attempt === maxAttempts;
            const isTransient = isTransientError(err);

            if (isTransient && !isLastAttempt) {
                const delay = baseDelay * Math.pow(2, attempt - 1); // Exponential backoff
                if (logger) {
                    logger.warn({
                        msg: 'Transient error occurred, retrying',
                        attempt,
                        maxAttempts,
                        delay,
                        err: err.message,
                        statusCode: err.statusCode || err.oauthRequest?.status
                    });
                }
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                // Either non-transient error or last attempt - rethrow
                throw err;
            }
        }
    }
}

/**
 * Base class for email client implementations
 * Provides common functionality for IMAP/SMTP operations
 * Subclasses should implement protocol-specific behavior
 */
class BaseClient {
    constructor(account, options) {
        this.account = account;
        this.options = options || {};

        // Generate unique connection ID for tracking
        this.cid = this.getRandomId();

        this.runIndex = this.options.runIndex;

        // Core service dependencies
        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;
        this.redis = this.options.redis;

        // Message queue connections
        this.notifyQueue = this.options.notifyQueue;
        this.submitQueue = this.options.submitQueue;
        this.documentsQueue = this.options.documentsQueue;
        this.flowProducer = this.options.flowProducer;

        // Inter-process communication handler
        this.call = this.options.call;

        this.logger = this.getLogger();

        this.secret = this.options.secret;

        // Track sub-connections (e.g., for IMAP IDLE)
        this.subconnections = [];

        // Initialize notification handler for webhook and event delivery
        this.notificationHandler = new NotificationHandler({
            account: this.account,
            logger: this.logger,
            flowProducer: this.flowProducer,
            documentsQueue: this.documentsQueue
        });
    }

    // Stub methods to be implemented by subclasses

    async init() {
        return null;
    }

    close() {
        return null;
    }

    async syncMailboxes() {
        return null;
    }

    async delete() {
        return null;
    }

    async resume() {
        return null;
    }

    async reconnect() {
        return null;
    }

    async subconnections() {
        return [];
    }

    async getQuota() {
        return false;
    }

    /**
     * Generates a random 20-character ID for connection tracking
     * @returns {string} Random ID string
     */
    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substring(0, 20);
        }
        return rid;
    }

    // Redis key generators for different data types

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getSeenMessagesKey() {
        return `${REDIS_PREFIX}iar:s:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    async currentState() {
        return 'connected';
    }

    /**
     * Creates a logger instance that logs to both main logger and account logger
     * @returns {Object} Synthetic logger that duplicates logs to account storage
     */
    getLogger() {
        this.mainLogger =
            this.options.logger ||
            logger.child({
                component: 'connection-client',
                account: this.account,
                cid: this.cid
            });

        let syntheticLogger = {};
        let levels = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];

        // Create wrapper methods for each log level
        for (let level of levels) {
            syntheticLogger[level] = (...args) => {
                // Log to main logger
                this.mainLogger[level](...args);

                // Also log to account-specific logger if enabled
                if (this.accountLogger.enabled && args && args[0] && typeof args[0] === 'object') {
                    let entry = Object.assign({ level, t: Date.now(), cid: this.cid }, args[0]);

                    // Serialize error objects properly
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

        syntheticLogger.child = opts => this.mainLogger.child(opts);

        return syntheticLogger;
    }

    /**
     * Updates the connection state in Redis and tracks state changes
     * Sends notification on first successful connection
     */
    async setStateVal() {
        const txn = createTransaction(this.redis, { logger: this.logger });
        txn.add('hSetExists', this.getAccountKey(), 'state', this.state);
        txn.add('hSetBigger', this.getAccountKey(), 'runIndex', this.runIndex.toString());
        txn.add('hget', this.getAccountKey(), `state:count:${this.state}`);
        txn.add('hIncrbyExists', this.getAccountKey(), `state:count:${this.state}`, 1);
        txn.add('hget', this.getAccountKey(), 'state');

        const values = await txn.execOrThrow();
        const prevVal = values[2];
        const incrVal = values[3];
        const stateVal = values[4];

        // Detect first successful connection
        if (stateVal === 'connected' && incrVal === 1 && prevVal === '0') {
            // first connected event!
            await this.notify(false, ACCOUNT_INITIALIZED_NOTIFY, {
                initialized: true
            });
        }
    }

    /**
     * Sets error state and manages error tracking/notifications
     * Implements logic to disable IMAP after repeated authentication failures
     * @param {string} event - Error event type
     * @param {Object} data - Error details
     * @returns {boolean} Whether this is the first occurrence of this error
     */
    async setErrorState(event, data) {
        // Retrieve previous error state for comparison
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

        let isFirstOccurrence = true;

        // Store current error state
        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', JSON.stringify(data));
        await emitChangeEvent(this.logger, this.account, 'state', event, { error: data });

        // Check if this is a repeat of the same error
        if (data && Object.keys(data).length && prevLastErrorState) {
            // we have an error object, let's see if the error hasn't changed

            if (data.serverResponseCode && data.serverResponseCode === prevLastErrorState.serverResponseCode) {
                // error code did not change, assume it is the same error
                isFirstOccurrence = false;
            } else {
                try {
                    deepEqual(data, prevLastErrorState);
                    // nothing changed
                    isFirstOccurrence = false;
                } catch (err) {
                    // seems different
                }
            }
        }

        // Track error occurrences
        if (isFirstOccurrence) {
            const txn = createTransaction(this.redis, { logger: this.logger });
            txn.add('hSetExists', this.getAccountKey(), 'lastError:errorCount', 1);
            txn.add('hSetExists', this.getAccountKey(), 'lastError:first', new Date().toISOString());
            await txn.exec();
        } else {
            let errorCount;
            let firstError;

            const txn = createTransaction(this.redis, { logger: this.logger });
            txn.add('hIncrbyExists', this.getAccountKey(), 'lastError:errorCount', 1);
            txn.add('hget', this.getAccountKey(), 'lastError:first');
            const { error, values } = await txn.exec();

            if (!error) {
                errorCount = values[0] || 0;
                const fe = values[1];
                if (fe) {
                    const parsedDate = new Date(fe);
                    if (parsedDate.toString() !== 'Invalid Date') {
                        firstError = parsedDate;
                    }
                }
            } else {
                this.logger.error({ msg: 'Redis error while checking error state counters', error });
            }

            // Handle repeated authentication errors by disabling IMAP
            switch (event) {
                case 'authenticationError':
                    if (errorCount > 0 && firstError && Date.now() - firstError.getTime() > MAX_IMAP_AUTH_FAILURE_TIME) {
                        // disable IMAP
                        let imapData;
                        let imapInfo = await this.redis.hget(this.getAccountKey(), 'imap');
                        if (imapInfo) {
                            try {
                                imapData = JSON.parse(imapInfo);
                            } catch (err) {
                                this.logger.error({ msg: 'Failed parsing IMAP data', err });
                            }
                        }
                        if (imapData && !imapData.disabled) {
                            imapData.disabled = true;

                            // Disable IMAP and reset error counters
                            const disableTxn = createTransaction(this.redis, { logger: this.logger });
                            disableTxn.add('hSetExists', this.getAccountKey(), 'imap', JSON.stringify(imapData));
                            disableTxn.add('hdel', this.getAccountKey(), 'lastError:errorCount', 'lastError:first');
                            disableTxn.add(
                                'hSetExists',
                                this.getAccountKey(),
                                'lastErrorState',
                                JSON.stringify({
                                    description: 'IMAP was disabled for the account due to exceeding the authentication error threshold',
                                    response: data.response
                                })
                            );
                            await disableTxn.exec();

                            this.logger.info({
                                msg: 'IMAP was disabled for the account due to exceeding the authentication error threshold',
                                errorEvent: event,
                                firstError: firstError.toISOString(),
                                timeThreshold: MAX_IMAP_AUTH_FAILURE_TIME,
                                errorCount
                            });

                            // Close the connection after disabling
                            setImmediate(() => {
                                this.close();
                            });
                        }
                    }
                    break;
            }
        }

        return isFirstOccurrence;
    }

    /**
     * Sends notifications for various email events through webhooks and queues
     * Handles error state tracking for connection/auth errors before delegating
     * to the notification handler for actual delivery
     * @param {Object} mailbox - Mailbox information
     * @param {string} event - Event type constant
     * @param {Object} data - Event data payload
     * @param {Object} extraOpts - Additional options
     */
    async notify(mailbox, event, data, extraOpts) {
        // Handle error state tracking for connection/auth errors
        // This is BaseClient-specific logic that must run before notification
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

        // Delegate to notification handler for webhook and document store delivery
        await this.notificationHandler.notify(mailbox, event, data, extraOpts);
    }

    /**
     * Loads OAuth2 credentials for login, handling token refresh if needed
     * @param {Object} accountObject - Account instance
     * @param {Object} accountData - Account configuration data
     * @param {Object} ctx - Context object (usually 'this')
     * @param {string} target - Target service ('imap' or 'smtp')
     * @returns {Object} OAuth2 credentials including access token
     */
    async loadOAuth2LoginCredentials(accountObject, accountData, ctx, target) {
        const now = Date.now();
        const oauth2User = accountData.oauth2.auth.delegatedUser || accountData.oauth2.auth.user;
        let accessToken;

        // Load OAuth2 app configuration
        const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
        if (!oauth2App) {
            let error = new Error('Missing or disabled OAuth2 app');
            error.code = 'AppNotFound';
            throw error;
        }

        // Verify app is configured for IMAP
        if (oauth2App.baseScopes && oauth2App.baseScopes !== 'imap') {
            let error = new Error('Invalid base scopes for references OAuth2 application');
            error.code = 'InvalidBaseScopes';
            throw error;
        }

        // Check if token needs refresh (with 30 second buffer)
        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now + 30 * 1000)) {
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
            // Use cached token
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

    /**
     * Resolves delegated account chain for OAuth2 authentication
     * Follows delegation chain up to 20 hops, detecting loops
     * @param {Object} accountData - Initial account data
     * @returns {Object} Final delegated account data
     */
    async getDelegatedAccount(accountData) {
        let redirect = 0;
        let providerAccountData = accountData;
        let delegatedAccountData;
        let seenAccounts = new Set();
        let hopsAllowed = 20;

        // Follow delegation chain
        while (redirect++ < hopsAllowed) {
            // Load delegated account if not cached
            if (!this.delegatedAccountObject || this.delegatedAccountObject.account !== providerAccountData.oauth2.auth.delegatedAccount) {
                this.delegatedAccountObject = new Account({
                    account: accountData.oauth2.auth.delegatedAccount,
                    redis: this.accountObject.redis,
                    call: this.accountObject.call,
                    secret: this.accountObject.secret,
                    timeout: this.accountObject.timeout
                });
            }
            delegatedAccountData = await this.delegatedAccountObject.loadAccountData();

            // Check if this account also delegates to another
            if (delegatedAccountData.oauth2.auth.delegatedUser && delegatedAccountData.oauth2.auth.delegatedAccount) {
                // Detect delegation loops
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

        return delegatedAccountData;
    }

    /**
     * Loads OAuth2 credentials handling delegated accounts
     * @param {Object} accountData - Account configuration
     * @param {Object} ctx - Context object
     * @param {string} target - Target service ('imap' or 'smtp')
     * @returns {Object} OAuth2 credentials
     */
    async loadOAuth2AccountCredentials(accountData, ctx, target) {
        let oauthCredentials;

        // Handle delegated accounts (shared mailboxes)
        if (accountData.oauth2.auth.delegatedUser && accountData.oauth2.auth.delegatedAccount) {
            const delegatedAccountData = await this.getDelegatedAccount(accountData);
            oauthCredentials = await this.loadOAuth2LoginCredentials(this.delegatedAccountObject, delegatedAccountData, ctx, target);
            if (target !== 'smtp') {
                // Use delegated user for IMAP
                oauthCredentials.oauth2User = accountData.oauth2.auth.delegatedUser || oauthCredentials.oauth2User;
            }
        } else {
            // Direct OAuth2 authentication
            oauthCredentials = await this.loadOAuth2LoginCredentials(this.accountObject, accountData, ctx, target);
            if (accountData.oauth2.auth.delegatedUser && target === 'smtp') {
                // override SMTP username, do not use the shared user
                oauthCredentials.oauth2User = accountData.oauth2.auth.user;
            }
        }

        return oauthCredentials;
    }

    /**
     * Checks and manages idempotency for operations to prevent duplicates
     * Uses Redis to track operation status across workers
     * @param {string} objName - Object type name for namespacing
     * @param {string} idempotencyKey - Unique key for the operation
     * @returns {Object|null} Idempotency data if exists
     */
    async checkIdempotencyKey(objName, idempotencyKey) {
        if (!idempotencyKey) {
            return null;
        }

        const idempotencyKeyName = objName ? `${objName}/${idempotencyKey}` : idempotencyKey;

        // check last 24-48 hours, so probably will return 2 keys, at rare cases 1
        const { bucketKeys } = getDateBuckets(1 * 24 * 3600);

        // Use custom Redis command to check idempotency atomically
        let idempotencyResultStr = await this.redis.eeGetIdempotency(
            `${REDIS_PREFIX}idempotency:bucket:`,
            idempotencyKeyName,
            this.runIndex,
            workerThreadId,
            bucketKeys.join(',')
        );

        let idempotencyData;
        try {
            idempotencyData = JSON.parse(idempotencyResultStr);
            idempotencyData.idempotencyKey = idempotencyKey;
            idempotencyData.idempotencyKeyName = idempotencyKeyName;
        } catch (err) {
            this.logger.error({ msg: 'Failed to parse idempotency data', idempotencyKey, cachedValue: idempotencyResultStr, err });
        }

        // Track pending operations to handle concurrent requests
        if (idempotencyData?.status === 'new') {
            if (pendingIdempotencyOperations.has(idempotencyKeyName)) {
                let error = new Error('Cancelling pending operation');
                for (let promise of pendingIdempotencyOperations.get(idempotencyKeyName)) {
                    promise.reject(error);
                }
                pendingIdempotencyOperations.delete(idempotencyKeyName);
            }
            pendingIdempotencyOperations.set(idempotencyKeyName, []);
        }

        // use existing response
        switch (idempotencyData.status) {
            case 'completed':
                // Return cached result
                idempotencyData.returnValue = Object.assign({}, idempotencyData.result, {
                    idempotency: { key: idempotencyData.idempotencyKey, status: 'HIT' }
                });
                break;
            case 'pending': {
                // Wait for operation to complete
                let queueResult = await new Promise((resolve, reject) => {
                    if (!pendingIdempotencyOperations.has(idempotencyData.idempotencyKeyName)) {
                        pendingIdempotencyOperations.set(idempotencyData.idempotencyKeyName, []);
                    }
                    pendingIdempotencyOperations.get(idempotencyData.idempotencyKeyName).push({ resolve, reject });
                });
                idempotencyData.returnValue = Object.assign({}, queueResult, { idempotency: { key: idempotencyData.idempotencyKey, status: 'HIT' } });
                break;
            }
        }

        return idempotencyData || null;
    }

    /**
     * Updates idempotency cache with operation result
     * @param {Object} idempotencyData - Idempotency tracking data
     * @param {Object} result - Operation result to cache
     */
    async updateIdempotencyData(idempotencyData, result) {
        if (idempotencyData?.bucketKey && idempotencyData?.idempotencyKeyName) {
            // update status and result
            try {
                await this.redis.hset(
                    idempotencyData?.bucketKey,
                    idempotencyData.idempotencyKeyName,
                    JSON.stringify({
                        status: 'completed',
                        runIndex: idempotencyData.runIndex,
                        threadId: idempotencyData.threadId,
                        result
                    })
                );
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to update idempotency data',
                    idempotencyKey: idempotencyData.idempotencyKey,
                    err
                });
            }

            // Resolve any waiting promises
            for (let promise of pendingIdempotencyOperations.get(idempotencyData.idempotencyKeyName)) {
                promise.resolve(result);
            }
            pendingIdempotencyOperations.delete(idempotencyData.idempotencyKeyName);
        }
    }

    /**
     * Clears idempotency data on operation failure
     * @param {Object} idempotencyData - Idempotency tracking data
     * @param {Error} error - Error that caused the failure
     */
    async clearIdempotencyData(idempotencyData, error) {
        if (idempotencyData?.status === 'new' && idempotencyData?.bucketKey && idempotencyData?.idempotencyKeyName) {
            // delete failed attempt information
            try {
                await this.redis.hdel(idempotencyData?.bucketKey, idempotencyData.idempotencyKeyName);
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to clear idempotency data',
                    idempotencyKey: idempotencyData.idempotencyKey,
                    err
                });
            }

            // Reject any waiting promises
            if (pendingIdempotencyOperations.has(idempotencyData.idempotencyKeyName)) {
                for (let promise of pendingIdempotencyOperations.get(idempotencyData.idempotencyKeyName)) {
                    promise.reject(error);
                }
                pendingIdempotencyOperations.delete(idempotencyData.idempotencyKeyName);
            }
        }
    }

    /**
     * Queues a message for sending with idempotency support
     * @param {Object} data - Message data
     * @param {Object} meta - Metadata
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Queue result
     */
    async queueMessage(data, meta, connectionOptions) {
        let idempotencyData;

        // Check for duplicate operations
        if (meta.idempotencyKey) {
            idempotencyData = await this.checkIdempotencyKey(`mq/${this.account}`, meta.idempotencyKey);
            if (idempotencyData?.returnValue) {
                return idempotencyData?.returnValue;
            }
        }

        let queueResult;
        try {
            queueResult = await this.queueMessageHandler(data, meta, connectionOptions);
            await this.updateIdempotencyData(idempotencyData, queueResult);
        } catch (err) {
            await this.clearIdempotencyData(idempotencyData, err);
            throw err;
        }

        if (idempotencyData?.status === 'new') {
            return Object.assign({}, queueResult, { idempotency: { key: idempotencyData.idempotencyKey, status: 'MISS' } });
        }

        return queueResult;
    }

    /**
     * Main handler for queuing messages for delivery
     * Processes templates, handles mail merge, and schedules delivery
     * @param {Object} data - Message data
     * @param {Object} meta - Metadata
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Queue result or mail merge results
     */
    async queueMessageHandler(data, meta, connectionOptions) {
        let accountData = await this.accountObject.loadAccountData();

        // Load gateway configuration if specified
        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        // Verify SMTP capability
        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let licenseInfo = await this.call({ cmd: 'license' });

        // Configure message defaults
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAttachments(data);

        // Process template if specified
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

            // Merge template content into message
            for (let key of Object.keys(templateData.content || {})) {
                data[key] = templateData.content[key];
            }

            delete data.template;
        }

        // Handle single message or mail merge
        if (!data.mailMerge || !data.mailMerge.length) {
            return this.queueMessageEntry(data, meta, licenseInfo, connectionOptions);
        }

        // Process mail merge batch
        let mailMergeList = data.mailMerge;
        delete data.mailMerge;
        delete data.messageId;
        delete data.to;

        let messageProcessors = [];

        // Create individual messages for each recipient
        for (let mailMergeEntry of mailMergeList) {
            let messageCopy = structuredClone(data);
            if (messageCopy.sendAt) {
                // date values do not survive JSON based copying
                messageCopy.sendAt = new Date(messageCopy.sendAt);
            }

            messageCopy.to = [mailMergeEntry.to];

            // Apply recipient-specific overrides
            for (let key of ['messageId', 'sendAt']) {
                if (mailMergeEntry[key]) {
                    messageCopy[key] = mailMergeEntry[key];
                }
            }

            // Apply recipient-specific template parameters
            if (mailMergeEntry.params) {
                messageCopy.render = messageCopy.render || {};
                messageCopy.render.params = mailMergeEntry.params;
            }

            messageProcessors.push(this.queueMessageEntry(messageCopy, meta, licenseInfo, connectionOptions));
        }

        let response = {
            mailMerge: []
        };

        // Process all messages in parallel
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

    // placeholder - to be implemented by subclasses
    async checkIMAPConnection() {
        return true;
    }

    /**
     * Prepares raw email message for sending/storing
     * Handles references, inline content, and attachments
     * @param {Object} data - Message data
     * @param {Object} options - Processing options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Raw message and metadata
     */
    async prepareRawMessage(data, options, connectionOptions) {
        options = options || {};

        // Configure message defaults
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAttachments(data);

        let accountData = await this.accountObject.loadAccountData();

        // Check if send-only account is trying to use reference.action
        if (data.reference && data.reference.message && data.reference.action) {
            let app;
            if (accountData.oauth2 && accountData.oauth2.provider) {
                try {
                    app = await this.accountObject.getOauth2App();
                } catch (err) {
                    // ignore
                }
            }

            if (this.accountObject.isSendOnlyAccount(accountData, app)) {
                let err = new Error('Reference actions (reply, forward) are not supported for send-only accounts');
                err.code = 'ReferenceNotSupported';
                err.statusCode = 400;
                throw err;
            }
        }

        // Set default from address for reference actions
        if (!data.from && data.reference?.action) {
            data.from = {
                name: accountData.name,
                address: accountData.email
            };
        }

        // Configure locale and timezone for inline content
        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            // Try document store first if enabled
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
                // Fetch from IMAP/API with retry logic for transient errors
                let extendedData = data.reference.inline || data.reference.forwardAttachments;

                try {
                    referencedMessage = await retryOnTransientError(
                        async () => {
                            return await this.getMessage(
                                data.reference.message,
                                {
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
                                },
                                connectionOptions
                            );
                        },
                        {
                            maxAttempts: 3,
                            baseDelay: 1000,
                            logger: this.logger
                        }
                    );
                } catch (err) {
                    // Check if this is a transient error that exhausted retries
                    const isTransient = isTransientError(err);

                    if (isTransient && data.reference.ignoreMissing) {
                        // Transient error but ignoreMissing is true - log and continue without reference
                        this.logger.warn({
                            msg: 'Failed to fetch referenced message due to transient error, continuing without reference',
                            messageId: data.reference.message,
                            err: err.message,
                            statusCode: err.statusCode || (err.oauthRequest && err.oauthRequest.status)
                        });
                        referencedMessage = null;
                    } else if (!isTransient && err.statusCode === 404) {
                        // Permanent 404 error - respect ignoreMissing
                        if (!data.reference.ignoreMissing) {
                            let error = new Error('Referenced message was not found');
                            error.code = 'MessageNotFound';
                            error.statusCode = 404;
                            throw error;
                        }
                        referencedMessage = null;
                    } else {
                        // Either transient error with ignoreMissing=false, or other permanent error
                        throw err;
                    }
                }
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let err = new Error('Referenced message was not found');
                err.code = 'MessageNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (referencedMessage) {
                // Verify Message-ID if specified
                if (data.reference.messageId && data.reference.messageId !== referencedMessage.messageId) {
                    let err = new Error('The referenced message was found, but its Message-ID does not match the expected value');
                    err.code = 'MessageNotFound';
                    err.statusCode = 404;
                    throw err;
                }

                // Build references header chain
                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        // Ensure proper Message-ID format
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

                // Set In-Reply-To header for replies
                if (['reply', 'reply-all'].includes(data.reference.action) && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                // Generate subject with appropriate prefix
                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                        case 'reply-all':
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

                // Process inline content for replies/forwards
                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        // Find inline attachments referenced in HTML
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            let html = data.html;
                            if (!(html || '').toString().trim() && data.text) {
                                html = textToHtml(data.text); // convert text to html
                            }

                            data.html = inlineHtml(data.reference.action, html, inlineMessageData, inlineOptions);
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

                // Set recipient for reply
                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                              ? referencedMessage.from
                              : false;
                }

                // Handle reply-all recipients
                if (data.reference.action === 'reply-all') {
                    let envelope = {
                        to: [].concat(
                            referencedMessage.replyTo && referencedMessage.replyTo.length
                                ? referencedMessage.replyTo
                                : referencedMessage.from
                                  ? referencedMessage.from
                                  : []
                        ),
                        cc: [],
                        bcc: []
                    };

                    // Deduplicate recipients
                    let addressesSeen = new Set([].concat(data.from?.address || []).concat(envelope.to.map(addr => addr.address)));
                    for (let rcpt of ['to', 'cc', 'bcc']) {
                        for (let addr of referencedMessage[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        for (let addr of data[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        if (envelope[rcpt].length) {
                            data[rcpt] = envelope[rcpt];
                        }
                    }
                }

                // Determine which attachments to include
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

                // Download and attach referenced attachments
                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection(connectionOptions);

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
                            content = await this.getAttachmentContent(
                                attachment.id,
                                {
                                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                                    contentOnly: true
                                },
                                connectionOptions
                            );
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
                this.checkIMAPConnection(connectionOptions);

                let content = await this.getAttachmentContent(
                    attachment.reference,
                    {
                        chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                        contentOnly: true
                    },
                    connectionOptions
                );
                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        // Final message configuration
        data.disableUrlAccess = true;
        data.disableFileAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();
        data.newline = '\r\n';

        if (data.internalDate && !data.date) {
            // Update Date: header as well
            data.date = new Date(data.internalDate);
        }

        // Generate raw MIME message
        let { raw, emailObject, messageId } = await getRawEmail(data, null, options);

        return { raw, emailObject, messageId, documentStoreUsed, referencedMessage };
    }

    /**
     * Processes a single message for queuing
     * Handles templates, references, tracking, and scheduling
     * @param {Object} data - Message data
     * @param {Object} meta - Metadata
     * @param {Object} licenseInfo - License information
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Queue result
     */
    async queueMessageEntry(data, meta, licenseInfo, connectionOptions) {
        let accountData = await this.accountObject.loadAccountData();

        // Configure message defaults
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        let baseUrl = data.baseUrl || (await settings.get('serviceUrl')) || null;

        // Build template context
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

        // Set default from address
        if (!data.from) {
            data.from = {
                name: accountData.name,
                address: accountData.email,
                _default: true
            };
        }

        // Handle list unsubscribe headers
        if (baseUrl && data.listId && data.to && data.to.length === 1 && data.to[0].address) {
            // check if not already blocked

            let blockData;

            try {
                blockData = await this.redis.hget(`${REDIS_PREFIX}lists:unsub:entries:${data.listId}`, data.to[0].address.toLowerCase().trim());
                blockData = JSON.parse(blockData);
            } catch (err) {
                blockData = false;
            }

            // Skip if recipient has unsubscribed
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

            // Generate List headers
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
                    data.messageId = `<${uuid()}@${fromDomain}>`;
                }

                // Create signed unsubscribe URL
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

                // Add RFC 8058 compliant unsubscribe headers
                data.headers['List-Unsubscribe'] = `<${context.rcpt.unsubscribeUrl}>`;
                data.headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
            }
        }

        // Render templates
        for (let key of ['subject', 'html', 'text', 'previewText']) {
            if (data.render || data.listId) {
                data[key] = this.render(data[key], context, key, data.render && data.render.format);
            }
        }

        delete data.render;

        // Configure locale and timezone for inline content
        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        // Generate plain text from HTML if needed
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
            // Try document store first if enabled
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
                // Fetch from IMAP/API with retry logic for transient errors
                this.checkIMAPConnection(connectionOptions);

                let extendedData = data.reference.inline || data.reference.forwardAttachments;

                try {
                    referencedMessage = await retryOnTransientError(
                        async () => {
                            return await this.getMessage(
                                data.reference.message,
                                {
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
                                },
                                connectionOptions
                            );
                        },
                        {
                            maxAttempts: 3,
                            baseDelay: 1000,
                            logger: this.logger
                        }
                    );
                } catch (err) {
                    // Check if this is a transient error that exhausted retries
                    const isTransient = isTransientError(err);

                    if (isTransient && data.reference.ignoreMissing) {
                        // Transient error but ignoreMissing is true - log and continue without reference
                        this.logger.warn({
                            msg: 'Failed to fetch referenced message due to transient error, continuing without reference',
                            messageId: data.reference.message,
                            err: err.message,
                            statusCode: err.statusCode || (err.oauthRequest && err.oauthRequest.status)
                        });
                        referencedMessage = null;
                    } else if (!isTransient && err.statusCode === 404) {
                        // Permanent 404 error - respect ignoreMissing
                        if (!data.reference.ignoreMissing) {
                            let error = new Error('Referenced message was not found');
                            error.code = 'ReferenceNotFound';
                            error.statusCode = 404;
                            throw error;
                        }
                        referencedMessage = null;
                    } else {
                        // Either transient error with ignoreMissing=false, or other permanent error
                        throw err;
                    }
                }
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let error = new Error('Referenced message was not found');
                error.code = 'ReferenceNotFound';
                error.statusCode = 404;
                throw error;
            }

            if (referencedMessage) {
                // Verify Message-ID if specified
                if (data.reference.messageId && data.reference.messageId !== referencedMessage.messageId) {
                    let err = new Error('The referenced message was found, but its Message-ID does not match the expected value');
                    err.code = 'MessageNotFound';
                    err.statusCode = 404;
                    throw err;
                }

                // Build references header chain
                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        // Ensure proper Message-ID format
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

                // Set In-Reply-To header for replies
                if (['reply', 'reply-all'].includes(data.reference.action) && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                // Check if we need to update flags on referenced message
                let referenceFlags = ['\\Answered'].concat(data.reference.action === 'forward' ? '$Forwarded' : []);
                if (!referencedMessage.flags || !referencedMessage.flags.length || !referenceFlags.some(flag => referencedMessage.flags.includes(flag))) {
                    data.reference.update = true;
                }

                // Preserve thread ID
                if (referencedMessage.threadId) {
                    data.reference.threadId = referencedMessage.threadId;
                }

                // Generate subject with appropriate prefix
                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                        case 'reply-all':
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

                // Process inline content for replies/forwards
                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        // Find inline attachments referenced in HTML
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            let html = data.html;
                            if (!(html || '').toString().trim() && data.text) {
                                html = textToHtml(data.text); // convert text to html
                            }

                            data.html = inlineHtml(data.reference.action, html, inlineMessageData, inlineOptions);
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

                // Set recipient for reply
                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                              ? referencedMessage.from
                              : false;
                }

                // Handle reply-all recipients
                if (data.reference.action === 'reply-all') {
                    let envelope = {
                        to: [].concat(
                            referencedMessage.replyTo && referencedMessage.replyTo.length
                                ? referencedMessage.replyTo
                                : referencedMessage.from
                                  ? referencedMessage.from
                                  : []
                        ),
                        cc: [],
                        bcc: []
                    };

                    // Deduplicate recipients
                    let addressesSeen = new Set([].concat(data.from?.address || []).concat(envelope.to.map(addr => addr.address)));
                    for (let rcpt of ['to', 'cc', 'bcc']) {
                        for (let addr of referencedMessage[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        for (let addr of data[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        if (envelope[rcpt].length) {
                            data[rcpt] = envelope[rcpt];
                        }
                    }
                }

                // Determine which attachments to include
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

                // Download and attach referenced attachments
                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection(connectionOptions);

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
                            content = await this.getAttachmentContent(
                                attachment.id,
                                {
                                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                                    contentOnly: true
                                },
                                connectionOptions
                            );
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

        // resolve referenced attachments by ID
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection(connectionOptions);

                let content = await this.getAttachmentContent(
                    attachment.reference,
                    {
                        chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                        contentOnly: true
                    },
                    connectionOptions
                );

                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        // Generate raw MIME message
        let { raw, hasBcc, envelope, subject, messageId, sendAt, deliveryAttempts, trackClicks, trackOpens, trackingEnabled, gateway } = await getRawEmail(
            data,
            licenseInfo
        );

        // Handle dry run mode
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

        // Load gateway configuration if specified
        let gatewayData;
        if (gateway) {
            let gatewayObject = new Gateway({ gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', envelope, messageId, gateway, err });
            }
        }

        // Verify SMTP capability
        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        // Configure tracking settings
        if (typeof trackingEnabled !== 'boolean') {
            trackingEnabled = (await settings.get('trackSentMessages')) || false;
        }

        if (typeof trackClicks !== 'boolean') {
            trackClicks = await settings.get('trackClicks');
            if (typeof trackClicks !== 'boolean') {
                trackClicks = trackingEnabled;
            }
        }

        if (typeof trackOpens !== 'boolean') {
            trackOpens = await settings.get('trackOpens');
            if (typeof trackOpens !== 'boolean') {
                trackOpens = trackingEnabled;
            }
        }

        // Add tracking pixels and link tracking
        if (raw && (trackClicks || trackOpens) && baseUrl) {
            // add open and click tracking
            raw = await addTrackers(raw, accountData.account, messageId, baseUrl, {
                trackClicks,
                trackOpens
            });
        }

        let now = new Date();

        //queue for later

        // Use timestamp in the ID to make sure that jobs are ordered by send time
        let timeBuf = Buffer.allocUnsafe(8);

        timeBuf.writeBigInt64BE(BigInt((sendAt && sendAt.getTime()) || Date.now()), 0);

        let queueId = Buffer.concat([timeBuf.subarray(2), crypto.randomBytes(4)])
            .toString('hex')
            .substring(1); // first char is always 0

        // Serialize message data for storage
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
            proxy: data.proxy || null,
            localAddress: data.localAddress || null,
            raw
        });

        // Store message in Redis
        await this.redis.hsetBuffer(`${REDIS_PREFIX}iaq:${this.account}`, queueId, msgEntry);

        let queueKeep = (await settings.get('queueKeep')) || true;

        // Configure delivery retry settings
        let defaultDeliveryAttempts = await settings.get('deliveryAttempts');
        if (typeof defaultDeliveryAttempts !== 'number') {
            defaultDeliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
        }

        // Prepare job data for queue
        let jobData = Object.assign({}, meta || {}, {
            account: this.account,
            queueId,
            gateway: (gatewayData && gatewayData.gateway) || null,
            messageId,
            envelope,
            subject,
            proxy: data.proxy,
            localAddress: data.localAddress,
            created: now.getTime()
        });

        // Configure queue job options
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

        // Schedule delayed sending
        if (sendAt && sendAt > now) {
            queueName = 'delayed';
            jobOpts.delay = sendAt.getTime() - now.getTime();
        }

        // Add job to queue
        let job = await this.submitQueue.add(queueName, jobData, jobOpts);

        try {
            await job.updateProgress({
                status: 'queued'
            });
        } catch (err) {
            // ignore
        }

        this.logger.info({ msg: 'Message queued for delivery', envelope, messageId, sendAt: (sendAt || now).toISOString(), queueId, job: job.id });

        // Build response
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

    /**
     * Renders template strings with context data
     * @param {string} template - Template string
     * @param {Object} data - Context data
     * @param {string} key - Template key (subject, text, html, previewText)
     * @param {string} renderFormat - Override format for rendering
     * @returns {string} Rendered template
     */
    render(template, data, key, renderFormat) {
        let format;

        // Determine format based on key
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

    /**
     * Detects if a message is an auto-reply based on headers and subject
     * @param {Object} messageData - Message data
     * @returns {boolean} True if message appears to be an auto-reply
     */
    isAutoreply(messageData) {
        // Check subject patterns - these are strong autoreply indicators
        // Note: "Automatic reply:" and "Auto reply:" (with space) are common variants
        // "Out of the Office" is also valid (with "the")
        if (/^(auto(matic)?\s*(reply|response)|Out of(?: the)? Office|OOF:|OOO:)/i.test(messageData.subject)) {
            return true;
        }

        // Weaker subject patterns require inReplyTo as confirmation
        if (/^auto:/i.test(messageData.subject) && messageData.inReplyTo) {
            return true;
        }

        if (!messageData.headers) {
            return false;
        }

        // Check Precedence header
        if (messageData.headers.precedence && messageData.headers.precedence.some(e => /auto[_-]?reply/.test(e))) {
            return true;
        }

        // Check Auto-Submitted header (RFC 3834)
        if (messageData.headers['auto-submitted'] && messageData.headers['auto-submitted'].some(e => /auto[_-]?replied/.test(e))) {
            return true;
        }

        // Check X-Auto-Response-Suppress header (Microsoft Exchange)
        // Values like "All", "OOF", "AutoReply" indicate this is an autoreply
        if (messageData.headers['x-auto-response-suppress'] && messageData.headers['x-auto-response-suppress'].length) {
            return true;
        }

        // Check various vendor-specific headers
        for (let headerKey of ['x-autoresponder', 'x-autorespond', 'x-autoreply']) {
            if (messageData.headers[headerKey] && messageData.headers[headerKey].length) {
                return true;
            }
        }

        return false;
    }

    /**
     * Gets message fetch options based on settings
     * @returns {Object} Fetch options for IMAP message retrieval
     */
    async getMessageFetchOptions() {
        let messageFetchOptions = {};

        // Configure text content fetching
        let notifyText = await settings.get('notifyText');
        if (notifyText) {
            messageFetchOptions.textType = '*';
            let notifyTextSize = await settings.get('notifyTextSize');

            if (notifyTextSize) {
                messageFetchOptions.maxBytes = notifyTextSize;
            }
        }

        // Configure header fetching
        let notifyHeaders = (await settings.get('notifyHeaders')) || [];
        if (notifyHeaders.length) {
            messageFetchOptions.headers = notifyHeaders.includes('*') ? true : notifyHeaders.length ? notifyHeaders : false;
        }

        // also request autoresponse headers
        if (messageFetchOptions.headers !== true) {
            let fetchHeaders = new Set(messageFetchOptions.headers || []);

            // Headers for auto-reply detection
            fetchHeaders.add('x-autoreply');
            fetchHeaders.add('x-autorespond');
            fetchHeaders.add('auto-submitted');
            fetchHeaders.add('precedence');

            // Headers for threading
            fetchHeaders.add('in-reply-to');
            fetchHeaders.add('references');

            // Content type for detecting multipart/report
            fetchHeaders.add('content-type');

            messageFetchOptions.fetchHeaders = Array.from(fetchHeaders);
        }

        return messageFetchOptions;
    }

    /**
     * Main processor for new messages
     * Handles bounce detection, complaint processing, attachments,
     * calendar events, and AI-powered features
     * @param {Object} messageData - Message data
     * @param {Object} options - Processing options
     */
    async processNew(messageData, options) {
        let requestedHeaders = options.headers;

        let bounceNotifyInfo;
        let complaintNotifyInfo;
        let content;

        // Check for abuse report format (ARF) complaints
        if (this.mightBeAComplaint(messageData)) {
            try {
                // Download attachments needed for complaint detection
                for (let attachment of messageData.attachments) {
                    if (!['message/feedback-report', 'message/rfc822-headers', 'message/rfc822'].includes(attachment.contentType)) {
                        continue;
                    }

                    Object.defineProperty(attachment, 'content', {
                        value: (await this.getAttachment(attachment.id))?.data?.toString(),
                        enumerable: false
                    });
                }

                // Parse ARF report
                const report = await arfDetect(messageData);

                if (report && report.arf && report.arf['original-rcpt-to'] && report.arf['original-rcpt-to'].length) {
                    // can send report
                    let complaint = {};

                    // Convert headers to camelCase
                    for (let subKey of ['arf', 'headers']) {
                        for (let key of Object.keys(report[subKey])) {
                            if (!complaint[subKey]) {
                                complaint[subKey] = {};
                            }
                            complaint[subKey][key.replace(/-(.)/g, (o, c) => c.toUpperCase())] = report[subKey][key];
                        }
                    }

                    complaintNotifyInfo = Object.assign({ complaintMessage: messageData.id }, complaint);

                    messageData.isComplaint = true;

                    // Link to original message
                    if (complaint.headers && complaint.headers.messageId) {
                        messageData.relatedMessageId = complaint.headers.messageId;
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process ARF',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        // Check for delivery status notifications (DSN)
        if (this.mightBeDSNResponse(messageData)) {
            try {
                let raw = await this.getRawMessage(messageData.id);

                let parsed = await simpleParser(raw, { keepDeliveryStatus: true });
                if (parsed) {
                    content = { parsed };

                    // Extract delivery status attachment
                    let deliveryStatus = parsed.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
                    if (deliveryStatus) {
                        let deliveryEntries = libmime.decodeHeaders((deliveryStatus.content || '').toString().trim());
                        let structured = {};

                        // Parse delivery status fields
                        for (let key of Object.keys(deliveryEntries)) {
                            if (!key) {
                                continue;
                            }
                            let displayKey = key.replace(/-(.)/g, (m, c) => c.toUpperCase());
                            let value = deliveryEntries[key].at(-1);
                            if (typeof value === 'string') {
                                // Parse structured fields
                                let m = value.match(/^([^\s;]+);/);
                                if (m) {
                                    value = {
                                        label: m[1],
                                        value: value.substring(m[0].length).trim()
                                    };
                                } else {
                                    switch (key) {
                                        case 'arrival-date': {
                                            value.trim();
                                            let date = new Date(value);
                                            if (date.toString() !== 'Invalid Date') {
                                                value = date.toISOString();
                                            }
                                            structured[displayKey] = value;
                                            break;
                                        }
                                        default:
                                            structured[displayKey] = value.trim();
                                    }
                                }
                            } else {
                                // ???
                                structured[displayKey] = value;
                            }
                        }

                        // Check if this is a delivery or delay notification
                        if (/^delivered|^delayed/i.test(structured.action)) {
                            this.logger.debug({
                                msg: 'Detected delivery report',
                                id: messageData.id,
                                uid: messageData.uid,
                                messageId: messageData.messageId,
                                report: structured
                            });

                            messageData.deliveryReport = structured;
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process DSN',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        // Check if this could be a bounce
        if (this.mightBeABounce(messageData)) {
            // parse for bounce
            try {
                if (!content) {
                    content = await this.getRawMessage(messageData.id);
                }

                if (content) {
                    let bounce = await bounceDetect(content);

                    if (bounce?.response?.message) {
                        try {
                            let bounceType = await this.call({
                                cmd: 'bounceClassify',
                                data: {
                                    message: bounce?.response?.message
                                },
                                timeout: 2 * 60 * 1000
                            });
                            if (bounceType?.label) {
                                bounce.response.category = bounceType.label;
                            }
                            if (bounceType?.action) {
                                bounce.response.recommendedAction = bounceType.action;
                            }
                            if (bounceType?.blocklist) {
                                bounce.response.blocklist = bounceType.blocklist;
                            }
                            if (bounceType?.retryAfter) {
                                bounce.response.retryAfter = bounceType.retryAfter;
                            }
                        } catch (err) {
                            // ignore, just do not include this information
                            this.logger.error({
                                msg: 'Failed to classify bounce response',
                                bounceResponse: bounce?.response?.message,
                                err
                            });
                        }
                    }

                    let stored = 0;
                    if (bounce.action && bounce.recipient && bounce.messageId) {
                        bounceNotifyInfo = Object.assign({ bounceMessage: messageData.id }, bounce);

                        messageData.isBounce = true;
                        messageData.relatedMessageId = bounce.messageId;
                    }

                    this.logger.debug({
                        msg: 'Detected bounce message',
                        id: messageData.id,
                        uid: messageData.uid,
                        messageId: messageData.messageId,
                        bounce,
                        stored
                    });
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process potential bounce',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        // Download attachment content if configured
        let notifyAttachments = await settings.get('notifyAttachments');
        let notifyAttachmentSize = await settings.get('notifyAttachmentSize');
        if (notifyAttachments && messageData.attachments?.length) {
            for (let attachment of messageData.attachments || []) {
                if (notifyAttachmentSize && attachment.encodedSize && attachment.encodedSize > notifyAttachmentSize) {
                    // skip large attachments
                    continue;
                }
                if (!attachment.content) {
                    try {
                        attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        // Fetch inline attachments referenced in HTML
        if (messageData.attachments && messageData.attachments.length && messageData.text && messageData.text.html) {
            // fetch inline attachments
            for (let attachment of messageData.attachments) {
                if (attachment.encodedSize && attachment.encodedSize > MAX_INLINE_ATTACHMENT_SIZE) {
                    // skip large attachments
                    continue;
                }

                if (!attachment.content && attachment.contentId && messageData.text.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                    try {
                        attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        // Fetch and process calendar events if needed
        let notifyCalendarEvents = await settings.get('notifyCalendarEvents');
        if (notifyCalendarEvents && messageData.attachments && messageData.attachments.length) {
            let calendarEventMap = new Map();

            // when iterating the attachment array, process text/calendar before application/ics
            let sortCalendarAttachments = (a, b) => {
                if (a.contentType !== b.contentType) {
                    if (a.contentType === 'text/calendar') {
                        return -1;
                    }
                    if (b.contentType === 'text/calendar') {
                        return 1;
                    }
                }
                return a.contentType.localeCompare(b.contentType);
            };

            // Process calendar attachments
            for (let attachment of [...messageData.attachments].sort(sortCalendarAttachments)) {
                if (['text/calendar', 'application/ics'].includes(attachment.contentType)) {
                    if (!attachment.content) {
                        try {
                            let calendarBuf = (await this.getAttachment(attachment.id))?.data;
                            attachment.content = calendarBuf.toString('base64');
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                        }
                    }
                    if (attachment.content) {
                        let contentBuf = Buffer.from(attachment.content, 'base64');
                        try {
                            // Parse iCalendar data
                            const jcalData = ical.parse(contentBuf.toString());

                            const comp = new ical.Component(jcalData);
                            if (!comp) {
                                continue;
                            }

                            const vevent = comp.getFirstSubcomponent('vevent');
                            if (!vevent) {
                                continue;
                            }

                            // Extract method (REQUEST, CANCEL, etc.)
                            let eventMethodProp = comp.getFirstProperty('method');
                            let eventMethodValue = eventMethodProp ? eventMethodProp.getFirstValue() : null;

                            const event = new ical.Event(vevent);

                            if (!event || !event.uid) {
                                continue;
                            }

                            // Skip if we already processed this event
                            if (calendarEventMap.has(event.uid)) {
                                if (attachment.filename) {
                                    let existingEntry = calendarEventMap.get(event.uid);
                                    if (!existingEntry.filename) {
                                        // inject filename
                                        existingEntry.filename = attachment.filename;
                                    }
                                }
                                continue;
                            }

                            // Extract timezone information
                            let timezone;
                            const vtz = comp.getFirstSubcomponent('vtimezone');
                            if (vtz) {
                                const tz = new ical.Timezone(vtz);
                                timezone = tz && tz.tzid;
                            }

                            let startDate = event.startDate && event.startDate.toJSDate();
                            let endDate = event.endDate && event.endDate.toJSDate();

                            // Store calendar event data
                            calendarEventMap.set(
                                event.uid,
                                filterEmptyObjectValues({
                                    eventId: event.uid,
                                    attachment: attachment.id,
                                    method: attachment.method || eventMethodValue || null,

                                    summary: event.summary || null,
                                    description: event.description || null,
                                    timezone: timezone || null,
                                    startDate: startDate ? startDate.toISOString() : null,
                                    endDate: endDate ? endDate.toISOString() : null,
                                    organizer: event.organizer && typeof event.organizer === 'string' ? event.organizer : null,

                                    filename: attachment.filename,
                                    contentType: attachment.contentType,
                                    encoding: 'base64',
                                    content: attachment.content
                                })
                            );
                        } catch (err) {
                            this.logger.error({
                                msg: 'Failed to parse calendar event',
                                attachment: Object.assign({}, attachment, { content: `${contentBuf.length} bytes` }),
                                err
                            });
                        }
                    }
                }
            }

            if (calendarEventMap && calendarEventMap.size) {
                // Convert map to array and set default filenames
                messageData.calendarEvents = Array.from(calendarEventMap.values()).map(calendarEvent => {
                    if (!calendarEvent.filename) {
                        switch (calendarEvent.method && calendarEvent.method.toUpperCase()) {
                            case 'CANCEL':
                            case 'REQUEST':
                                calendarEvent.filename = 'invite.ics';
                                break;
                            default:
                                calendarEvent.filename = 'event.ics';
                                break;
                        }
                    }
                    return calendarEvent;
                });
            }
        }

        // Process with AI features for inbox messages
        if (messageData.messageSpecialUse === '\\Inbox') {
            let llmMessageData = Object.assign({ account: this.account }, messageData);

            // Check if LLM processing is enabled
            let canUseLLM = await llmPreProcess.run(llmMessageData);

            if (canUseLLM && (messageData.text.plain || messageData.text.html)) {
                // Generate email summary using AI
                if (canUseLLM.generateEmailSummary) {
                    try {
                        messageData.summary = await this.call({
                            cmd: 'generateSummary',
                            data: {
                                message: {
                                    headers: Object.keys(messageData.headers || {}).map(key => ({ key, value: [].concat(messageData.headers[key] || []) })),
                                    attachments: messageData.attachments,
                                    from: messageData.from,
                                    subject: messageData.subject,
                                    text: messageData.text.plain,
                                    html: messageData.text.html
                                },
                                account: this.account
                            },
                            timeout: 2 * 60 * 1000
                        });

                        if (messageData.summary) {
                            // Clean up summary output
                            for (let key of Object.keys(messageData.summary)) {
                                // remove meta keys from output
                                if (key.charAt(0) === '_' || messageData.summary[key] === '') {
                                    delete messageData.summary[key];
                                }
                                if (key === 'riskAssessment') {
                                    messageData.riskAssessment = messageData.summary.riskAssessment;
                                    delete messageData.summary.riskAssessment;
                                }
                            }

                            this.logger.trace({ msg: 'Fetched summary from OpenAI', summary: messageData.summary });
                        }

                        await this.redis.del(`${REDIS_PREFIX}:openai:error`);
                    } catch (err) {
                        // Track OpenAI errors
                        await this.redis.set(
                            `${REDIS_PREFIX}:openai:error`,
                            JSON.stringify({
                                message: err.message,
                                code: err.code,
                                statusCode: err.statusCode,
                                created: Date.now()
                            })
                        );
                        this.logger.error({ msg: 'Failed to fetch summary from OpenAI', err });
                    }
                }

                // Generate embeddings for semantic search
                if (canUseLLM.generateEmbeddings) {
                    try {
                        messageData.embeddings = await this.call({
                            cmd: 'generateEmbeddings',
                            data: {
                                message: {
                                    headers: Object.keys(messageData.headers || {}).map(key => ({ key, value: [].concat(messageData.headers[key] || []) })),
                                    attachments: messageData.attachments,
                                    from: messageData.from,
                                    subject: messageData.subject,
                                    text: messageData.text.plain,
                                    html: messageData.text.html
                                },
                                account: this.account
                            },
                            timeout: 2 * 60 * 1000
                        });
                    } catch (err) {
                        await this.redis.set(
                            `${REDIS_PREFIX}:openai:error`,
                            JSON.stringify({
                                message: err.message,
                                code: err.code,
                                statusCode: err.statusCode,
                                time: Date.now()
                            })
                        );
                        this.logger.error({ msg: 'Failed to fetch embeddings OpenAI', err });
                    }
                }
            }
        }

        // Convert message HTML to web safe HTML
        let notifyWebSafeHtml = await settings.get('notifyWebSafeHtml');
        if (notifyWebSafeHtml && messageData.text && (messageData.text.html || messageData.text.plain)) {
            // convert to web safe
            messageData.text._generatedHtml = mimeHtml({
                html: messageData.text.html,
                text: messageData.text.plain
            });

            // embed inline images as data URIs
            if (messageData.text.html && messageData.attachments) {
                let attachmentList = new Map();

                // Find CID references in HTML
                for (let attachment of messageData.attachments) {
                    let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                    if (contentId && messageData.text.html.indexOf(contentId) >= 0) {
                        if (attachment.content) {
                            // already downloaded in a previous step
                            continue;
                        } else {
                            attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                        }

                        attachmentList.set(contentId, {
                            attachment,
                            content: attachment.content || null
                        });
                    }
                }

                // Replace CID references with data URIs
                if (attachmentList.size) {
                    messageData.text.html = messageData.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                        if (attachmentList.has(cidMatch)) {
                            let { attachment, content } = attachmentList.get(cidMatch);
                            if (content) {
                                return `data:${attachment.contentType || 'application/octet-stream'};base64,${content}`;
                            }
                        }
                        return fullMatch;
                    });
                }
            }

            messageData.text.webSafe = true;
        }

        // Filter headers based on request
        // we might have fetched more headers than was asked for, so filter out all the unneeded ones
        if (options.headers && Array.isArray(requestedHeaders)) {
            let filteredHeaders = {};
            for (let key of Object.keys(messageData.headers || {})) {
                if (requestedHeaders.includes(key)) {
                    filteredHeaders[key] = messageData.headers[key];
                }
            }
            messageData.headers = filteredHeaders;
        } else if (options.headers && requestedHeaders === false) {
            delete messageData.headers;
        }

        let path = messageData.path || this.path;
        let specialUse = messageData.path ? messageData.messageSpecialUse : this.listingEntry.specialUse;

        if (messageData.path) {
            // unset path from the message level
            messageData.path = undefined;
        }

        // Send new message notification
        await this.notify(
            {
                path,
                specialUse
            },
            MESSAGE_NEW_NOTIFY,
            messageData
        );

        // Send additional notifications for bounces and complaints
        if (bounceNotifyInfo) {
            // send bounce notification _after_ bounce email notification
            await this.notify(false, EMAIL_BOUNCE_NOTIFY, bounceNotifyInfo);
        }

        if (complaintNotifyInfo) {
            // send complaint notification _after_ complaint email notification
            await this.notify(false, EMAIL_COMPLAINT_NOTIFY, complaintNotifyInfo);
        }
    }

    /**
     * Checks if message might be an abuse complaint based on headers and content
     * @param {Object} messageData - Message data
     * @returns {boolean} True if message might be a complaint
     */
    mightBeAComplaint(messageData) {
        if (messageData.messageSpecialUse !== '\\Inbox') {
            return false;
        }

        let hasEmbeddedMessage = false;
        for (let attachment of messageData.attachments || []) {
            // ARF format indicator
            if (attachment.contentType === 'message/feedback-report') {
                return true;
            }

            if (['message/rfc822', 'message/rfc822-headers'].includes(attachment.contentType)) {
                hasEmbeddedMessage = true;
            }
        }

        let fromAddress = (messageData.from && messageData.from.address) || '';

        // Hotmail-specific complaint format
        if (hasEmbeddedMessage && fromAddress === 'staff@hotmail.com' && /complaint/i.test(messageData.subject)) {
            return true;
        }

        return false;
    }

    /**
     * Checks if message is a delivery status notification
     * @param {Object} messageData - Message data
     * @returns {boolean} True if message is a DSN
     */
    mightBeDSNResponse(messageData) {
        if (messageData.messageSpecialUse !== '\\Inbox') {
            return false;
        }

        // Check for multipart/report with delivery-status
        if (messageData.headers && messageData.headers['content-type'] && messageData.headers['content-type'].length) {
            let parsedContentType = libmime.parseHeaderValue(messageData.headers['content-type'].at(-1));
            if (
                parsedContentType &&
                parsedContentType.value &&
                parsedContentType.value.toLowerCase().trim() === 'multipart/report' &&
                parsedContentType.params['report-type'] === 'delivery-status'
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if message might be a bounce based on various heuristics
     * @param {Object} messageData - Message data
     * @returns {boolean} True if message might be a bounce
     */
    mightBeABounce(messageData) {
        if (!['\\Inbox', '\\Junk'].includes(messageData.messageSpecialUse)) {
            return false;
        }

        if (messageData.deliveryReport) {
            // already processed
            return false;
        }

        let name = (messageData.from && messageData.from.name) || '';
        let address = (messageData.from && messageData.from.address) || '';

        // Common bounce sender names
        if (/Mail Delivery System|Mail Delivery Subsystem|Internet Mail Delivery|Mailer[- ]?Daemon|NDR Administrator/i.test(name)) {
            return true;
        }

        // Common bounce addresses (including mailer-daemon without @)
        // Note: Some MTAs use "mailerdaemon" without hyphen (e.g., ZoneMTA)
        if (/mailer-?daemon@|postmaster@|^mailer-?daemon$/i.test(address)) {
            return true;
        }

        // Exchange-style bounce
        if (/^Undeliverable:/.test(messageData.subject) && messageData.headers?.['auto-submitted']) {
            return true;
        }

        // Check for delivery-status attachment with undeliverable subject
        let hasDeliveryStatus = false;
        let hasOriginalMessage = false;
        for (let attachment of messageData.attachments || []) {
            if (attachment.contentType === 'message/delivery-status') {
                hasDeliveryStatus = true;
            }
            if (attachment.contentType === 'message/rfc822') {
                hasOriginalMessage = true;
            }
        }

        if (hasDeliveryStatus && /Undeliver(able|ed)/i.test(messageData.subject)) {
            return true;
        }

        // Has delivery-status attachment (strong indicator)
        if (hasDeliveryStatus) {
            return true;
        }

        // Has original message attachment with bounce-like subject
        if (hasOriginalMessage && /Undeliver|Failed|Returned|Failure|Error/i.test(messageData.subject)) {
            return true;
        }

        // Additional subject patterns for various bounce formats
        // Includes Japanese carrier patterns and generic NDR subjects
        if (
            /^Undeliverable\s+Message$|Mail delivery failed|Delivery Status Notification|Returned mail|Failure Notice|error sending your mail/i.test(
                messageData.subject
            )
        ) {
            return true;
        }

        return false;
    }

    /**
     * Submits a message for SMTP delivery
     * Handles authentication, connection pooling, and error tracking
     * @param {Object} data - Message data with raw content and metadata
     * @returns {Object} Delivery result with response and messageId
     */
    async submitMessage(data) {
        const accountData = await this.accountObject.loadAccountData();

        // Verify SMTP capability
        if (!accountData.smtp && !accountData.oauth2 && !data.gateway) {
            const err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        // Build SMTP configuration using SmtpConfigBuilder
        const smtpConfigBuilder = new SmtpConfigBuilder({
            redis: this.redis,
            secret: this.secret,
            logger: this.logger,
            account: this.account
        });

        // Load gateway if specified
        const { gatewayData, gatewayObject } = await smtpConfigBuilder.loadGateway(data.gateway, data.messageId);

        // Build connection configuration
        const smtpConnectionConfig = await smtpConfigBuilder.buildConnectionConfig({
            gatewayData,
            accountData,
            loadOAuth2Credentials: this.loadOAuth2AccountCredentials.bind(this),
            context: this
        });

        // Resolve auth server credentials if configured
        const smtpAuth = await smtpConfigBuilder.resolveAuthServer(smtpConnectionConfig);

        // Build complete SMTP settings
        const smtpSettings = await smtpConfigBuilder.buildSmtpSettings({
            smtpConnectionConfig,
            smtpAuth,
            accountData,
            data
        });

        // Build network routing info for notifications
        const networkRouting = NetworkRoutingBuilder.build(smtpSettings, data);

        // Extract message data
        let { raw, hasBcc, envelope, messageId, queueId, reference, job: jobData } = data;

        // Verify job still exists
        const submitJobEntry = await this.submitQueue.getJob(jobData.id);
        if (!submitJobEntry) {
            this.logger.error({ msg: 'Submit job was not found', job: jobData.id });
            return false;
        }

        // Get SMTP transport from pool
        const transporter = getMailTransport(smtpSettings);

        try {
            // Update job progress
            try {
                await submitJobEntry.updateProgress({ status: 'smtp-starting' });
            } catch (err) {
                // ignore
            }

            // Send the message
            const info = await transporter.sendMail({
                envelope,
                messageId,
                raw: !hasBcc ? raw : await removeBcc(raw),
                dsn: data.dsn || null
            });

            // Store EHLO response for debugging
            if (info.ehlo) {
                await this.redis.hSetExists(this.getAccountKey(), 'smtpServerEhlo', JSON.stringify(info.ehlo));
            }

            // Handle provider-specific message ID extraction
            const originalMessageId = ProviderMessageIdHandler.processResponse(info, smtpSettings.host);

            // Update job progress
            try {
                await submitJobEntry.updateProgress({
                    status: 'smtp-completed',
                    response: info.response,
                    messageId: info.messageId,
                    originalMessageId
                });
            } catch (err) {
                // ignore
            }

            // Send success notification
            await this.notify(
                false,
                EMAIL_SENT_NOTIFY,
                NotificationBuilder.buildSuccessPayload({ info, originalMessageId, queueId, envelope, networkRouting })
            );

            // Clear cached SMTP error
            try {
                await this.redis.hset(this.getAccountKey(), 'smtpStatus', JSON.stringify({ created: Date.now(), status: 'ok', response: info.response }));
            } catch (err) {
                // ignore
            }

            // Handle sent mail copy to folder
            const shouldCopy = SentMailCopyDecider.shouldCopy({
                accountData,
                data,
                isGmail: this.isGmail,
                isOutlook: this.isOutlook,
                gatewayData
            });

            const connectionOptions = { allowSecondary: true };

            if (shouldCopy) {
                await this.uploadToSentFolder(raw, data, queueId, messageId, connectionOptions);
            }

            // Update reference flags if needed
            if (reference && reference.update) {
                await this.updateReferenceFlags(reference, queueId, messageId, connectionOptions);
            }

            // Update feedback key if provided
            if (data.feedbackKey) {
                await this.updateFeedbackKey(data.feedbackKey, true);
            }

            // Update gateway usage stats
            if (gatewayData) {
                await this.updateGatewayStats(gatewayObject, queueId, messageId, reference);
            }

            return { response: info.response, messageId: info.messageId };
        } catch (err) {
            await this.handleSubmitError(err, {
                smtpSettings,
                networkRouting,
                gatewayData,
                gatewayObject,
                data,
                jobData,
                queueId,
                envelope
            });
            throw err;
        }
    }

    /**
     * Uploads sent message to the Sent folder via IMAP
     * @param {Buffer} raw - Raw message content
     * @param {Object} data - Message data
     * @param {string} queueId - Queue ID for logging
     * @param {string} messageId - Message ID for logging
     * @param {Object} connectionOptions - IMAP connection options
     */
    async uploadToSentFolder(raw, data, queueId, messageId, connectionOptions) {
        try {
            this.checkIMAPConnection(connectionOptions);

            const sentMailbox =
                data.sentMailPath && typeof data.sentMailPath === 'string' ? { path: data.sentMailPath } : await this.getSpecialUseMailbox('\\Sent');

            if (sentMailbox) {
                if (raw.buffer) {
                    raw = Buffer.from(raw);
                }

                const connectionClient = await this.getImapConnection(connectionOptions, 'submitMessage');
                await connectionClient.append(sentMailbox.path, raw, ['\\Seen']);

                if (connectionClient === this.imapClient && this.imapClient.mailbox && !this.imapClient.idling) {
                    this.imapClient.idle().catch(err => {
                        this.logger.error({ msg: 'IDLE error', err });
                    });
                }
            }
        } catch (err) {
            this.logger.error({ msg: 'Failed to upload Sent mail', queueId, messageId, err });
        }
    }

    /**
     * Updates flags on the referenced message (for replies/forwards)
     * @param {Object} reference - Reference message info
     * @param {string} queueId - Queue ID for logging
     * @param {string} messageId - Message ID for logging
     * @param {Object} connectionOptions - IMAP connection options
     */
    async updateReferenceFlags(reference, queueId, messageId, connectionOptions) {
        try {
            this.checkIMAPConnection(connectionOptions);
            await this.updateMessage(
                reference.message,
                {
                    flags: {
                        add: ['\\Answered'].concat(reference.action === 'forward' ? '$Forwarded' : [])
                    }
                },
                connectionOptions
            );
        } catch (err) {
            this.logger.error({ msg: 'Failed to update reference flags', queueId, messageId, reference, err });
        }
    }

    /**
     * Updates feedback key with success/failure status
     * @param {string} feedbackKey - Redis key for feedback
     * @param {boolean} success - Whether the operation succeeded
     * @param {string} [errorMessage] - Error message if failed
     */
    async updateFeedbackKey(feedbackKey, success, errorMessage) {
        const feedbackTxn = createTransaction(this.redis, { logger: this.logger });
        feedbackTxn.add('hset', feedbackKey, 'success', success ? 'true' : 'false');
        if (!success && errorMessage) {
            feedbackTxn.add('hset', feedbackKey, 'error', errorMessage);
        }
        feedbackTxn.add('expire', feedbackKey, 1 * 60 * 60);
        await feedbackTxn.exec();
    }

    /**
     * Updates gateway usage statistics after successful send
     * @param {Object} gatewayObject - Gateway object
     * @param {string} queueId - Queue ID for logging
     * @param {string} messageId - Message ID for logging
     * @param {Object} reference - Reference message info
     */
    async updateGatewayStats(gatewayObject, queueId, messageId, reference) {
        try {
            await gatewayObject.update({
                lastError: null,
                lastUse: new Date(),
                deliveries: { inc: 1 }
            });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to update gateway',
                queueId,
                messageId,
                reference,
                gateway: gatewayObject.gateway,
                err
            });
        }
    }

    /**
     * Handles errors during message submission
     * @param {Error} err - The error that occurred
     * @param {Object} context - Error handling context
     */
    async handleSubmitError(err, context) {
        const { smtpSettings, networkRouting, gatewayData, gatewayObject, data, jobData, queueId, envelope } = context;

        // Handle permanent failures
        if (err.responseCode >= 500 && jobData.opts?.attempts <= jobData.attemptsMade) {
            jobData.nextAttempt = false;
        }

        // Build SMTP status from error
        const smtpStatus = SmtpErrorBuilder.buildStatus(err, smtpSettings, networkRouting);

        if (smtpStatus) {
            // Store SMTP error for the account
            try {
                await this.redis.hset(this.getAccountKey(), 'smtpStatus', JSON.stringify(smtpStatus));
            } catch (storeErr) {
                // ignore
            }

            // Update gateway error status
            if (gatewayData) {
                try {
                    await gatewayObject.update({ lastError: smtpStatus, lastUse: new Date() });
                } catch (updateErr) {
                    // ignore
                }
            }
        }

        // Update feedback key with failure status
        if (data.feedbackKey && !jobData.nextAttempt) {
            const errorMessage = (smtpStatus && smtpStatus.description) || 'Failed to send email';
            await this.updateFeedbackKey(data.feedbackKey, false, errorMessage);
        }

        // Send delivery error notification
        await this.notify(
            false,
            EMAIL_DELIVERY_ERROR_NOTIFY,
            NotificationBuilder.buildErrorPayload({
                error: err,
                queueId,
                envelope,
                messageId: data.messageId,
                networkRouting,
                jobData
            })
        );

        // Enhance error with additional context
        err.code = err.code || 'SubmitFail';
        err.statusCode = Number(err.responseCode) || null;
        err.info = { networkRouting };
    }

    // stub - to be implemented by subclasses
    async listSignatures() {
        return { signatures: [], signaturesSupported: false };
    }
}

// Re-export postMetrics from notification-handler for backward compatibility
module.exports = { BaseClient, metricsMeta: postMetrics };
