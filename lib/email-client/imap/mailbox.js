'use strict';

const crypto = require('crypto');
const {
    serialize,
    unserialize,
    compareExisting,
    normalizePath,
    download,
    filterEmptyObjectValues,
    validUidValidity,
    calculateFetchBackoff,
    readEnvValue
} = require('../../tools');
const msgpack = require('msgpack5')();
const he = require('he');
const libmime = require('libmime');
const settings = require('../../settings');
const config = require('@zone-eu/wild-config');
const { bounceDetect } = require('../../bounce-detect');
const { arfDetect } = require('../../arf-detect');
const appendList = require('../../append-list');
const { mimeHtml } = require('@postalsys/email-text-tools');
const simpleParser = require('mailparser').simpleParser;
const ical = require('ical.js');
const addressparser = require('nodemailer/lib/addressparser');
const { llmPreProcess } = require('../../llm-pre-process');

const { getESClient } = require('../../document-store');

const {
    MESSAGE_NEW_NOTIFY,
    MAILBOX_DELETED_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    MESSAGE_MISSING_NOTIFY,
    MAILBOX_RESET_NOTIFY,
    MAILBOX_NEW_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    EMAIL_COMPLAINT_NOTIFY,
    REDIS_PREFIX,
    MAX_INLINE_ATTACHMENT_SIZE,
    MAX_ALLOWED_DOWNLOAD_SIZE,
    DEFAULT_FETCH_BATCH_SIZE,
    MAILBOX_HASH
} = require('../../consts');

// Configurable batch size for fetching messages (default: 250)
const FETCH_BATCH_SIZE = Number(readEnvValue('EENGINE_FETCH_BATCH_SIZE') || config.service.fetchBatchSize) || DEFAULT_FETCH_BATCH_SIZE;

// Do not check for flag updates using full sync more often than this value (30 minutes)
const FULL_SYNC_DELAY = 30 * 60 * 1000;

/**
 * Calculates the next range of sequence numbers to fetch based on the last fetched range
 * @param {Number} totalMessages - Total number of messages in the mailbox
 * @param {String} lastRange - Last fetched range in format "start:end" or "start:*"
 * @returns {String|false} Next range to fetch or false if no more messages
 */
function getFetchRange(totalMessages, lastRange) {
    let lastEndMarker = lastRange ? lastRange.split(':').pop() : false;
    if (lastEndMarker === '*') {
        // Already fetched to the end
        return false;
    }
    let lastSeq = lastRange ? Number(lastEndMarker) : 0;
    let startSeq = lastSeq + 1;
    if (startSeq > totalMessages) {
        // No more messages to fetch
        return false;
    }
    let endMarker = startSeq + FETCH_BATCH_SIZE - 1;
    if (endMarker >= totalMessages) {
        // Use * to fetch to the end
        endMarker = '*';
    }
    return `${startSeq}:${endMarker}`;
}

/**
 * Represents a single IMAP mailbox/folder and handles all operations on it
 */
class Mailbox {
    constructor(connection, entry) {
        this.status = false;
        this.connection = connection; // Parent connection object
        this.path = entry.path; // Mailbox path (e.g., "INBOX", "Sent Mail")
        this.listingEntry = entry; // Mailbox metadata from LIST command
        this.syncDisabled = entry.syncDisabled; // Whether syncing is disabled for this mailbox

        // Child logger with mailbox context
        this.logger = this.connection.mainLogger.child({
            sub: 'mailbox',
            path: this.path
        });

        // Indexing strategy: 'full' maintains complete message list, 'fast' only tracks new messages
        this.imapIndexer = connection.imapIndexer;

        // Gmail-specific flags
        this.isGmail = connection.isGmail;
        this.isAllMail = this.isGmail && this.listingEntry.specialUse === '\\All';

        // LarkSuite mail has unreliable ENVELOPE responses, needs special handling
        this.isLarkSuite = connection.isLarkSuite;

        this.selected = false; // Whether this mailbox is currently selected
        // Does the mailbox open happen before or after initial syncing
        this.previouslyConnected = false;

        // Generate unique Redis key for this mailbox based on path hash
        this.redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(this.path)).digest('hex')).toString(36);

        this.runPartialSyncTimer = false; // Timer for delayed partial sync after EXISTS

        this.synced = false; // Whether initial sync is complete
        this.syncing = false; // Whether currently syncing
    }

    /**
     * Gets current mailbox status from IMAP connection
     * @param {Object} connectionClient - IMAP client to use (defaults to main connection)
     * @returns {Object} Status object with path, highestModseq, uidValidity, uidNext, messages
     */
    getMailboxStatus(connectionClient) {
        connectionClient = connectionClient || this.connection.imapClient;
        if (!connectionClient) {
            throw new Error('IMAP connection not available');
        }

        let mailboxInfo = connectionClient.mailbox;

        let status = {
            path: this.path
        };

        // MODSEQ for CONDSTORE extension (change tracking)
        status.highestModseq = mailboxInfo.highestModseq ? mailboxInfo.highestModseq : false;
        // UIDVALIDITY changes when mailbox is recreated
        status.uidValidity = validUidValidity(mailboxInfo.uidValidity) ? mailboxInfo.uidValidity : false;
        // Next UID to be assigned
        status.uidNext = mailboxInfo.uidNext ? mailboxInfo.uidNext : false;
        // Total message count
        status.messages = mailboxInfo.exists ? mailboxInfo.exists : 0;

        return status;
    }

    /**
     * Loads last known mailbox state from Redis
     * @returns {Object} mailbox state with stored metadata
     */
    async getStoredStatus() {
        let data = await this.connection.redis.hgetall(this.getMailboxKey());
        data = data || {};
        return {
            path: data.path || this.path,
            uidValidity: validUidValidity(data.uidValidity) ? BigInt(data.uidValidity) : false,
            highestModseq: data.highestModseq && !isNaN(data.highestModseq) ? BigInt(data.highestModseq) : false,
            messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
            uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false,
            // First UID when mailbox was initially synced (used to detect old messages)
            initialUidNext: data.initialUidNext && !isNaN(data.initialUidNext) ? Number(data.initialUidNext) : false,
            noInferiors: !!data.noInferiors,
            lastFullSync: data.lastFullSync ? new Date(data.lastFullSync) : false
        };
    }

    /**
     * Updates known mailbox state in Redis
     * @param {Object} data - Status data to store
     */
    async updateStoredStatus(data) {
        if (!data || typeof data !== 'object') {
            return false;
        }

        // Convert all values to strings for Redis storage
        let list = Object.keys(data)
            .map(key => {
                switch (key) {
                    case 'path':
                    case 'uidValidity':
                    case 'highestModseq':
                    case 'messages':
                    case 'uidNext':
                        return [key, data[key].toString()];

                    case 'lastFullSync':
                        return [key, data[key].toISOString()];
                }
            })
            .filter(entry => entry);

        if (!list.length) {
            return;
        }

        let op = this.connection.redis.multi();

        // Store initial UID on first sync
        if (data.uidNext) {
            op = op.hSetNew(this.getMailboxKey(), 'initialUidNext', data.uidNext.toString());
        }

        await op.hmset(this.getMailboxKey(), Object.fromEntries(list)).exec();
    }

    /**
     * Sets message entry object in Redis sorted set. Entries are ordered by `uid` property
     * @param {Object} data - Message data with uid, flags, etc.
     * @returns {Number} Sequence number for the added entry
     */
    async entryListSet(data) {
        if (isNaN(data.uid)) {
            return null;
        }

        // Store in sorted set with UID as score for efficient range queries
        return await this.connection.redis.zSet(this.getMessagesKey(), Number(data.uid), serialize(data));
    }

    /**
     * Retrieves message entry object for the provided sequence value or UID
     * @param {Number} seq - Sequence number or UID
     * @param {Object} options - Options object
     * @param {Boolean} options.uid - If true, seq is treated as UID
     * @returns {Object|null} Message entry object with uid, entry, and seq
     */
    async entryListGet(seq, options) {
        let range = Number(seq);
        options = options || {};
        // Use UID-based or sequence-based retrieval
        let command = options.uid ? 'zGetByUidBuffer' : 'zGetBuffer';
        let response = await this.connection.redis[command](this.getMessagesKey(), range);
        if (response) {
            try {
                return {
                    uid: Number(response[0]),
                    entry: unserialize(response[1]),
                    seq: Number(response[2])
                };
            } catch (err) {
                return null;
            }
        }
        return null;
    }

    /**
     * Deletes entry from message list for the provided sequence value or UID
     * @param {Number} seq - Sequence number (0 if using UID)
     * @param {Number} uid - UID number (0 if using sequence)
     * @returns {Object|null} Message entry object that was deleted
     */
    async entryListExpunge(seq, uid) {
        // Custom Redis command that removes and returns the entry
        let response = await this.connection.redis.zExpungeBuffer(this.getMessagesKey(), this.getMailboxKey(), seq || 0, uid || 0);
        if (response) {
            try {
                return unserialize(response[1]);
            } catch (err) {
                return null;
            }
        }
        return null;
    }

    /**
     * Checks if this mailbox is currently selected in the IMAP connection
     * @returns {Boolean} True if selected
     */
    isSelected() {
        return (
            this.selected &&
            this.connection.imapClient &&
            this.connection.imapClient.mailbox &&
            normalizePath(this.connection.imapClient.mailbox.path) === normalizePath(this.path)
        );
    }

    // Redis key generators for different data types

    /**
     * Gets Redis key for storing message list (sorted set)
     */
    getMessagesKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:l:${this.redisKey}`;
    }

    /**
     * Gets Redis key for storing mailbox metadata (hash)
     */
    getMailboxKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:h:${this.redisKey}`;
    }

    /**
     * Gets Redis key for storing bounce information
     */
    getBounceKey() {
        return `${REDIS_PREFIX}iar:b:${this.connection.account}`;
    }

    /**
     * Gets Redis key for tracking seen messages (HyperLogLog)
     */
    getSeenMessagesKey() {
        return `${REDIS_PREFIX}iar:s:${this.connection.account}`;
    }

    /**
     * Gets Redis key for queued notifications (sorted set)
     */
    getNotificationsKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:n:${this.redisKey}`;
    }

    /**
     * Starts IDLE mode to receive real-time updates
     */
    startIdle() {
        if (!this.isSelected() || !this.connection.imapClient || this.connection.imapClient.idling) {
            return;
        }
        this.connection.imapClient.idle().catch(err => {
            this.logger.error({ msg: 'IDLE error', err });
        });
    }

    /**
     * Clears all mailbox records from Redis and notifies about deletion
     * @param {Object} opts - Options
     * @param {Boolean} opts.skipNotify - Skip sending deletion notification
     */
    async clear(opts) {
        opts = opts || {};

        clearTimeout(this.runPartialSyncTimer);

        // Delete all Redis keys for this mailbox
        await this.connection.redis.del(this.getMailboxKey());
        await this.connection.redis.del(this.getMessagesKey());
        await this.connection.redis.del(this.getNotificationsKey());

        // Remove from connection's mailbox cache
        this.connection.mailboxes.delete(normalizePath(this.path));

        this.logger.debug({ msg: 'Deleted mailbox', path: this.listingEntry.path });

        if (!opts.skipNotify) {
            this.connection.notify(this, MAILBOX_DELETED_NOTIFY, {
                path: this.listingEntry.path,
                name: this.listingEntry.name,
                specialUse: this.listingEntry.specialUse || false
            });
        }
    }

    /**
     * Syncs mailbox without selecting it (using STATUS command)
     * @param {Boolean} forceEmpty - Force sync even if mailbox appears unchanged
     * @returns {Boolean} True if synced
     */
    async sync(forceEmpty) {
        if (this.selected || !this.connection.imapClient) {
            // expect current folder to be already synced
            return false;
        }

        let status;
        try {
            // Get status without selecting the mailbox
            status = await this.connection.imapClient.status(this.path, {
                uidNext: true,
                messages: true,
                highestModseq: true,
                uidValidity: true
            });
        } catch (err) {
            if (err.code === 'NotFound') {
                // folder is missing, refresh folder listing
                await this.connection.getCurrentListing();
                return;
            } else {
                throw err;
            }
        }

        if (!status) {
            // nothing to do here
            return;
        }

        status.highestModseq = status.highestModseq || false;

        if (this.syncDisabled) {
            // only update counters, don't fetch messages
            await this.updateStoredStatus(status);
            return true;
        }

        // Check if we have unprocessed notifications that need to be sent
        let hasQueuedNotifications = await this.connection.redis.exists(this.getNotificationsKey());

        // Determine if we need to sync based on various conditions
        if (!hasQueuedNotifications && !forceEmpty) {
            let storedStatus = await this.getStoredStatus();
            if (status.uidValidity === storedStatus.uidValidity) {
                // Check if nothing has changed
                if (
                    status.uidNext === storedStatus.uidNext &&
                    status.messages === storedStatus.messages &&
                    storedStatus.lastFullSync > new Date(Date.now() - FULL_SYNC_DELAY)
                ) {
                    // no reason to sync - no new messages and recent full sync
                    return true;
                }

                // Check MODSEQ for CONDSTORE-enabled servers
                if ((!status.messages && !storedStatus.messages) || (status.highestModseq && status.highestModseq === storedStatus.highestModseq)) {
                    // no reason to sync - empty or no changes
                    return true;
                }
            }
        }

        // Need to sync - create promise that resolves when sync is complete
        let syncedPromise = new Promise((resolve, reject) => {
            this.synced = resolve;
            this.select(true).catch(err => reject(err));
        });

        await syncedPromise;
    }

    /**
     * Selects mailbox and optionally starts IDLE
     * @param {Boolean} skipIdle - Don't start IDLE after selecting
     */
    async select(skipIdle) {
        const currentLock = this.connection.imapClient.currentLock;
        // Avoid interfering with any active operations
        if (currentLock) {
            if (this.path === currentLock.path) {
                // Already on the correct mailbox with an active lock
                this.logger.trace({
                    msg: 'Skip extra lock on active mailbox',
                    activeLock: {
                        lockId: currentLock.lockId,
                        path: currentLock.path,
                        ...(currentLock.options?.description && { description: currentLock.options?.description })
                    }
                });
                return;
            }
            // Different mailbox is locked - queue this select to run after lock is released
            // This ensures we don't interfere with ongoing operations
            this.logger.trace({
                msg: 'Queueing select - another mailbox is locked',
                requestedPath: this.path,
                lockedPath: currentLock.path,
                activeLock: currentLock.lockId
            });
        }

        // Get lock and wait our turn - this will queue if another operation is active
        let lock = await this.getMailboxLock(null, { description: `Select mailbox: ${this.path}` });

        // Check if we still need to select after getting the lock
        // Another operation might have already selected this mailbox while we were waiting
        if (this.connection.imapClient.mailbox && this.connection.imapClient.mailbox.path === this.path) {
            this.logger.trace({
                msg: 'Mailbox already selected after lock acquired',
                path: this.path
            });
            lock.release();
            return;
        }

        // Keep the lock briefly to ensure IDLE can start without interference
        // Release after a short delay to allow IDLE to initialize
        setTimeout(() => {
            lock.release();
        }, 100);

        if (!skipIdle) {
            // Do not wait until command finishes before proceeding
            this.startIdle();
        }
    }

    /**
     * Acquires exclusive lock on mailbox to prevent concurrent operations
     * @param {Object} connectionClient - IMAP client to use
     * @param {Object} options - Lock options
     * @returns {Object} Lock object with release() method
     */
    async getMailboxLock(connectionClient, options) {
        connectionClient = connectionClient || this.connection.imapClient;

        if (!connectionClient) {
            throw new Error('IMAP connection not available');
        }

        let lock = await connectionClient.getMailboxLock(this.path, options || {});

        // Reset idle timer when using main connection
        if (connectionClient === this.connection.imapClient) {
            clearTimeout(this.connection.completedTimer);
        }

        return lock;
    }

    /**
     * Marks task as completed and potentially starts idle timer
     * @param {Object} connectionClient - IMAP client that completed the task
     */
    onTaskCompleted(connectionClient) {
        connectionClient = connectionClient || this.connection.imapClient;
        if (connectionClient === this.connection.imapClient) {
            this.connection.onTaskCompleted();
        }
    }

    /**
     * Helper to log IMAP events with proper formatting
     * @param {String} msg - Log message
     * @param {Object} event - Event data to log
     */
    logEvent(msg, event) {
        const logObj = Object.assign({ msg }, event);
        // Convert BigInts and Sets to loggable formats
        Object.keys(logObj).forEach(key => {
            if (typeof logObj[key] === 'bigint') {
                logObj[key] = logObj[key].toString();
            }
            if (typeof logObj[key].has === 'function') {
                logObj[key] = Array.from(logObj[key]);
            }
        });
        this.logger.trace(logObj);
    }

    /**
     * Handles untagged EXISTS response indicating new messages
     * @param {Object} event - EXISTS event data
     */
    async onExists(event) {
        this.logEvent('Untagged EXISTS', event);

        // Debounce partial sync to avoid multiple syncs for rapid changes
        clearTimeout(this.runPartialSyncTimer);
        this.runPartialSyncTimer = setTimeout(() => {
            this.runPartialSyncTimer = null;
            this.shouldRunPartialSyncAfterExists()
                .then(shouldRun => {
                    if (shouldRun) {
                        return this.partialSync();
                    }
                    return false;
                })
                .then(() => this.select())
                .catch(err => this.logger.error({ msg: 'Sync error', err }));
        }, 1000);
    }

    /**
     * Handles untagged EXPUNGE/VANISHED response indicating deleted messages
     * @param {Object} event - EXPUNGE event data
     */
    async onExpunge(event) {
        const imapIndexer = this.imapIndexer;
        event.imapIndexer = imapIndexer;
        this.logEvent('Untagged EXPUNGE', event);

        if (imapIndexer !== 'full') {
            // ignore as we can not compare this value against the index
            return null;
        }

        let deletedEntry;

        if (event.seq) {
            // * 123 EXPUNGE - sequence-based expunge
            deletedEntry = await this.entryListExpunge(event.seq);
        } else if (event.uid) {
            // * VANISHED 123 - UID-based expunge (QRESYNC)
            deletedEntry = await this.entryListExpunge(false, event.uid);
        }

        if (deletedEntry) {
            await this.processDeleted(deletedEntry);
            await this.markUpdated();
        }
    }

    /**
     * Handles untagged FETCH response indicating flag changes
     * @param {Object} event - FETCH event data with flags
     */
    async onFlags(event) {
        const imapIndexer = this.imapIndexer;
        event.imapIndexer = imapIndexer;
        this.logEvent('Untagged FETCH', event);

        if (imapIndexer !== 'full') {
            // ignore as we can not compare this value against the index
            return null;
        }

        let storedMessage = await this.entryListGet(event.uid || event.seq, { uid: !!event.uid });
        let changes;

        // ignore Recent flag as it's session-specific
        event.flags.delete('\\Recent');

        if (!storedMessage) {
            // New! There should not be new messages in a flags update.
            // What should we do? Currently triggering partial sync.
            return await this.onExists();
        } else if ((changes = compareExisting(storedMessage.entry, event, ['flags']))) {
            // Update stored flags
            let messageData = storedMessage.entry;
            messageData.flags = event.flags;
            let seq = await this.entryListSet(messageData);

            if (seq) {
                await this.processChanges(storedMessage, changes);
            }
        }
    }

    /**
     * Checks if partial sync should run after EXISTS event
     * @returns {Boolean} True if message count differs from stored count
     */
    async shouldRunPartialSyncAfterExists() {
        let storedStatus = await this.getStoredStatus();
        let mailboxStatus = this.getMailboxStatus();
        return mailboxStatus.messages !== storedStatus.messages;
    }

    /**
     * Processes a deleted message - clears bounces and sends notification
     * @param {Object} messageData - Deleted message data
     */
    async processDeleted(messageData) {
        this.logger.debug({ msg: 'Deleted', uid: messageData.uid });

        //FIXME: does not work as there is no messageId property
        /*
        if (messageData.messageId) {
            try {
                let deleted = await appendList.clear(this.connection.redis, this.getBounceKey(), messageData.messageId);
                if (deleted) {
                    this.logger.error({
                        msg: 'Cleared bounce log for message',
                        id: messageData.id,
                        uid: messageData.uid,
                        messageId: messageData.messageId
                    });
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to clear bounce log',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }
        */

        // Generate packed UID for external reference
        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, MESSAGE_DELETED_NOTIFY, {
            id: packedUid,
            uid: messageData.uid
        });

        try {
            // Remove from notifications queue since message no longer exists
            await this.connection.redis.zremrangebyscore(this.getNotificationsKey(), messageData.uid, messageData.uid);
        } catch (err) {
            this.logger.error({ msg: 'Failed removing deleted message from notifications set', uid: messageData.uid, err });
        }
    }

    /**
     * Processes a new message - fetches details, detects bounces/complaints, sends notifications
     * @param {Object} messageData - Basic message data (uid, flags, etc)
     * @param {Object} options - Processing options
     * @param {Boolean} canSync - Whether message should be synced to document store
     * @param {Object} storedStatus - Current mailbox status
     */
    async processNew(messageData, options, canSync, storedStatus) {
        this.logger.debug({ msg: 'New message', uid: messageData.uid, flags: Array.from(messageData.flags) });

        options.skipLock = true;

        // Handle header fetching options
        let requestedHeaders = options.headers;
        if (options.fetchHeaders) {
            options.headers = options.fetchHeaders;
        } else {
            options.headers = 'headers' in options ? options.headers : false;
        }

        let messageInfo;

        // Retry logic for messages that might not be immediately available (replication lag)
        let missingDelay = 0;
        let missingRetries = 0;
        let maxRetries = 3;

        while (!messageInfo) {
            messageInfo = await this.getMessage(messageData, options);
            if (!messageInfo) {
                // NB! could be a replication lag with specific servers, so retry a few times
                if (missingRetries < maxRetries) {
                    // Exponential backoff: 1.7^n seconds
                    let delay = Math.round(1000 * Math.pow(1.7, missingRetries));

                    this.logger.debug({ msg: 'Missing message', status: 'not found', uid: messageData.uid, missingRetries, missingDelay, nextRetry: delay });
                    await new Promise(r => setTimeout(r, delay));

                    missingRetries++;
                    missingDelay += delay;
                } else {
                    this.logger.debug({ msg: 'Missing message', status: 'not found', uid: messageData.uid, missingRetries, missingDelay, nextRetry: null });
                    break;
                }
            }
        }

        if (!messageInfo) {
            // Message not found after retries - send missing notification
            let packedUid = await this.connection.packUid(this, messageData.uid);
            await this.connection.notify(this, MESSAGE_MISSING_NOTIFY, {
                id: packedUid,
                uid: messageData.uid,
                missingRetries,
                missingDelay
            });
            return;
        }

        if (missingRetries) {
            // Log retry statistics if message was eventually found
            messageInfo.missingDelay = missingDelay;
            messageInfo.missingRetries = missingRetries;

            this.logger.debug({ msg: 'Missing message', status: 'found', uid: messageData.uid, missingRetries, missingDelay });
        }

        // Filter headers based on what was requested
        if (options.headers && Array.isArray(requestedHeaders)) {
            let filteredHeaders = {};
            for (let key of Object.keys(messageInfo.headers)) {
                if (requestedHeaders.includes(key)) {
                    filteredHeaders[key] = messageInfo.headers[key];
                }
            }
            messageInfo.headers = filteredHeaders;
        } else if (options.headers && requestedHeaders === false) {
            delete messageInfo.headers;
        }

        // Check if message is too old to notify about
        let date = new Date(messageInfo.date);
        if (this.connection.notifyFrom && date < this.connection.notifyFrom && !canSync) {
            // skip too old messages
            return;
        }

        // Skip old messages in non-INBOX folders on reconnect
        if (this.previouslyConnected && this.path !== 'INBOX' && !this.isAllMail && storedStatus.initialUidNext > messageData.uid) {
            this.logger.debug({
                msg: 'Skip old message',
                action: 'webhook_ignore',
                initialUidNext: storedStatus.initialUidNext,
                id: messageInfo.id,
                uid: messageInfo.uid,
                connectCount: this.previouslyConnected
            });
            return;
        }

        let bounceNotifyInfo;
        let complaintNotifyInfo;
        let content;

        // Check if this might be an ARF (Abuse Reporting Format) complaint
        if (this.mightBeAComplaint(messageInfo)) {
            try {
                // Download relevant attachments for ARF parsing
                for (let attachment of messageInfo.attachments) {
                    if (!['message/feedback-report', 'message/rfc822-headers', 'message/rfc822'].includes(attachment.contentType)) {
                        continue;
                    }

                    let buf = Buffer.from(attachment.id, 'base64url');
                    let part = buf.subarray(8).toString();

                    let { content: sourceStream } = await this.connection.imapClient.download(messageInfo.uid, part, {
                        uid: true,
                        // headers should fit into 1MB, don't need all contents
                        maxBytes: Math.min(1 * 1024 * 1024, MAX_ALLOWED_DOWNLOAD_SIZE),
                        chunkSize: options.chunkSize
                    });

                    if (sourceStream) {
                        Object.defineProperty(attachment, 'content', {
                            value: (await download(sourceStream)).toString(),
                            enumerable: false
                        });
                    }
                }

                // Parse ARF report
                const report = await arfDetect(messageInfo);

                if (report && report.arf && report.arf['original-rcpt-to'] && report.arf['original-rcpt-to'].length) {
                    // Valid complaint found - prepare notification data
                    let complaint = {};
                    for (let subKey of ['arf', 'headers']) {
                        for (let key of Object.keys(report[subKey])) {
                            if (!complaint[subKey]) {
                                complaint[subKey] = {};
                            }
                            // Convert kebab-case to camelCase
                            complaint[subKey][key.replace(/-(.)/g, (o, c) => c.toUpperCase())] = report[subKey][key];
                        }
                    }

                    complaintNotifyInfo = Object.assign({ complaintMessage: messageInfo.id }, complaint);

                    messageInfo.isComplaint = true;

                    if (complaint.headers && complaint.headers.messageId) {
                        messageInfo.relatedMessageId = complaint.headers.messageId;
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process ARF',
                    id: messageInfo.id,
                    uid: messageInfo.uid,
                    messageId: messageInfo.messageId,
                    err
                });
            }
        }

        // Check if this might be a DSN (Delivery Status Notification)
        if (this.mightBeDSNResponse(messageInfo)) {
            try {
                let { content: sourceStream } = await this.connection.imapClient.download(messageInfo.uid, false, {
                    uid: true,
                    chunkSize: options.chunkSize,
                    maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                });

                let parsed = await simpleParser(sourceStream, { keepDeliveryStatus: true });
                if (parsed) {
                    content = { parsed };

                    // Extract delivery status information
                    let deliveryStatus = parsed.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
                    if (deliveryStatus) {
                        let deliveryEntries = libmime.decodeHeaders((deliveryStatus.content || '').toString().trim());
                        let structured = {};

                        // Parse delivery status headers
                        for (let key of Object.keys(deliveryEntries)) {
                            if (!key) {
                                continue;
                            }
                            let displayKey = key.replace(/-(.)/g, (m, c) => c.toUpperCase());
                            let value = deliveryEntries[key].at(-1);
                            if (typeof value === 'string') {
                                // Parse structured values like "rfc822;example.com"
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

                        // Only consider as delivery report if action indicates delivery or delay
                        if (/^delivered|^delayed/i.test(structured.action)) {
                            this.logger.debug({
                                msg: 'Detected delivery report',
                                id: messageInfo.id,
                                uid: messageInfo.uid,
                                messageId: messageInfo.messageId,
                                report: structured
                            });

                            messageInfo.deliveryReport = structured;
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process DSN',
                    id: messageInfo.id,
                    uid: messageInfo.uid,
                    messageId: messageInfo.messageId,
                    err
                });
            }
        }

        // Check if this could be a bounce message
        if (this.mightBeABounce(messageInfo)) {
            // Parse for bounce information
            try {
                if (!content) {
                    let result = await this.connection.imapClient.download(messageInfo.uid, false, {
                        uid: true,
                        chunkSize: options.chunkSize,
                        maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                    });
                    content = result.content;
                }

                if (content) {
                    // Detect bounce details
                    let bounce = await bounceDetect(content);

                    let stored = 0;
                    if (bounce.action && bounce.recipient && bounce.messageId) {
                        // Store bounce information for later retrieval
                        let storedBounce = {
                            i: messageInfo.id,
                            r: bounce.recipient,
                            t: Date.now(),
                            a: bounce.action
                        };

                        if (bounce.response && bounce.response.message) {
                            storedBounce.m = bounce.response.message;
                        }

                        if (bounce.response && bounce.response.status) {
                            storedBounce.s = bounce.response.status;
                        }

                        // Store bounce info associated with original message ID
                        stored = await appendList.append(this.connection.redis, this.getBounceKey(), bounce.messageId, storedBounce);

                        bounceNotifyInfo = Object.assign({ bounceMessage: messageInfo.id }, bounce);

                        messageInfo.isBounce = true;
                        messageInfo.relatedMessageId = bounce.messageId;
                    }

                    this.logger.debug({
                        msg: 'Detected bounce message',
                        id: messageInfo.id,
                        uid: messageInfo.uid,
                        messageId: messageInfo.messageId,
                        bounce,
                        stored
                    });
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process potential bounce',
                    id: messageInfo.id,
                    uid: messageInfo.uid,
                    messageId: messageInfo.messageId,
                    err
                });
            }
        }

        // Resolve Gmail category for inbox messages
        if (
            this.connection.imapClient.capabilities.has('X-GM-EXT-1') &&
            this.isAllMail &&
            messageInfo.labels &&
            messageInfo.labels.includes('\\Inbox') &&
            (await settings.get('resolveGmailCategories'))
        ) {
            this.logger.trace({
                msg: 'Resolving category for incoming email',
                uid: messageData.uid,
                id: messageInfo.id
            });

            // Try each Gmail category in order
            for (let category of ['primary', 'social', 'promotions', 'updates', 'forums', 'reservations', 'purchases']) {
                try {
                    let results = await this.connection.imapClient.search(
                        {
                            uid: messageInfo.uid,
                            gmraw: `category:${category}`
                        },
                        { uid: true }
                    );
                    if (results && results.includes(messageInfo.uid)) {
                        messageInfo.category = category;
                        this.logger.debug({
                            msg: 'Resolved category for incoming email',
                            category,
                            uid: messageData.uid,
                            id: messageInfo.id
                        });
                        break;
                    }
                } catch (err) {
                    this.logger.error({ msg: 'Failed to resolve category for message', err, category, uid: messageData.uid, id: messageInfo.id });
                    break;
                }
            }
        }

        // Download attachment content if configured
        let notifyAttachments = await settings.get('notifyAttachments');
        let notifyAttachmentSize = await settings.get('notifyAttachmentSize');
        if (notifyAttachments && messageInfo.attachments?.length) {
            for (let attachment of messageInfo.attachments || []) {
                if (notifyAttachmentSize && attachment.encodedSize && attachment.encodedSize > notifyAttachmentSize) {
                    // skip large attachments
                    continue;
                }
                if (!attachment.content) {
                    try {
                        let buf = Buffer.from(attachment.id, 'base64url');
                        let part = buf.subarray(8).toString();

                        let { content: downloadStream } = await this.connection.imapClient.download(messageInfo.uid, part, {
                            uid: true,
                            chunkSize: options.chunkSize,
                            maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                        });

                        if (downloadStream) {
                            attachment.content = (await download(downloadStream)).toString('base64');
                        }
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        // Fetch inline attachments referenced in HTML
        if (messageInfo.attachments?.length && messageInfo.text?.html) {
            // fetch inline attachments
            for (let attachment of messageInfo.attachments) {
                if (attachment.encodedSize && attachment.encodedSize > MAX_INLINE_ATTACHMENT_SIZE) {
                    // skip large attachments
                    continue;
                }

                // Check if attachment is referenced by Content-ID in HTML
                if (!attachment.content && attachment.contentId && messageInfo.text.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                    try {
                        let buf = Buffer.from(attachment.id, 'base64url');
                        let part = buf.subarray(8).toString();

                        let { content: downloadStream } = await this.connection.imapClient.download(messageInfo.uid, part, {
                            uid: true,
                            chunkSize: options.chunkSize,
                            maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                        });

                        if (downloadStream) {
                            attachment.content = (await download(downloadStream)).toString('base64');
                        }
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        // Fetch and process calendar events if needed
        let notifyCalendarEvents = await settings.get('notifyCalendarEvents');
        if (notifyCalendarEvents && messageInfo.attachments && messageInfo.attachments.length) {
            let calendarEventMap = new Map();

            // Process text/calendar before application/ics
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

            for (let attachment of [...messageInfo.attachments].sort(sortCalendarAttachments)) {
                if (['text/calendar', 'application/ics'].includes(attachment.contentType)) {
                    // Download calendar attachment if not already loaded
                    if (!attachment.content) {
                        try {
                            let buf = Buffer.from(attachment.id, 'base64url');
                            let part = buf.subarray(8).toString();

                            let { content: downloadStream } = await this.connection.imapClient.download(messageInfo.uid, part, {
                                uid: true,
                                chunkSize: options.chunkSize,
                                maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                            });

                            if (downloadStream) {
                                let contentBuf = await download(downloadStream);

                                if (contentBuf && contentBuf.length) {
                                    attachment.content = contentBuf.toString('base64');
                                }
                            }
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

                            // Skip duplicate events, prefer ones with filenames
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

                            // Store parsed calendar event
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
                messageInfo.calendarEvents = Array.from(calendarEventMap.values()).map(calendarEvent => {
                    // Generate default filename based on method
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

        // Check if we have seen this message before using HyperLogLog
        messageInfo.seemsLikeNew =
            this.listingEntry.specialUse !== '\\Sent' &&
            !(messageInfo.labels && messageInfo.labels.includes('\\Sent')) &&
            !!(await this.connection.redis.pfadd(this.getSeenMessagesKey(), messageInfo.emailId || messageInfo.messageId));

        // Determine special use folder for the message
        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (this.listingEntry.specialUse === specialUseTag || (messageInfo.labels && messageInfo.labels.includes(specialUseTag))) {
                messageInfo.messageSpecialUse = specialUseTag;
                break;
            }
        }

        // Process with LLM if configured for inbox messages
        if (messageInfo.messageSpecialUse === '\\Inbox' && (!this.connection.notifyFrom || messageData.internalDate >= this.connection.notifyFrom)) {
            let messageData = Object.assign({ account: this.connection.account }, messageInfo);

            let canUseLLM = await llmPreProcess.run(messageData);

            if (canUseLLM && (messageInfo.text.plain || messageInfo.text.html)) {
                // Generate AI summary if enabled
                if (canUseLLM.generateEmailSummary) {
                    try {
                        messageInfo.summary = await this.connection.call({
                            cmd: 'generateSummary',
                            data: {
                                message: {
                                    headers: Object.keys(messageInfo.headers || {}).map(key => ({ key, value: [].concat(messageInfo.headers[key] || []) })),
                                    attachments: messageInfo.attachments,
                                    from: messageInfo.from,
                                    subject: messageInfo.subject,
                                    text: messageInfo.text.plain,
                                    html: messageInfo.text.html
                                },
                                account: this.connection.account
                            },
                            timeout: 2 * 60 * 1000
                        });

                        if (messageInfo.summary) {
                            // Clean up summary output
                            for (let key of Object.keys(messageInfo.summary)) {
                                // remove meta keys from output
                                if (key.charAt(0) === '_' || messageInfo.summary[key] === '') {
                                    delete messageInfo.summary[key];
                                }
                                if (key === 'riskAssessment') {
                                    messageInfo.riskAssessment = messageInfo.summary.riskAssessment;
                                    delete messageInfo.summary.riskAssessment;
                                }
                            }

                            this.logger.trace({ msg: 'Fetched summary from OpenAI', summary: messageInfo.summary });
                        }

                        await this.connection.redis.del(`${REDIS_PREFIX}:openai:error`);
                    } catch (err) {
                        await this.connection.redis.set(
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

                // Generate embeddings if enabled
                if (canUseLLM.generateEmbeddings) {
                    try {
                        messageInfo.embeddings = await this.connection.call({
                            cmd: 'generateEmbeddings',
                            data: {
                                message: {
                                    headers: Object.keys(messageInfo.headers || {}).map(key => ({ key, value: [].concat(messageInfo.headers[key] || []) })),
                                    attachments: messageInfo.attachments,
                                    from: messageInfo.from,
                                    subject: messageInfo.subject,
                                    text: messageInfo.text.plain,
                                    html: messageInfo.text.html
                                },
                                account: this.connection.account
                            },
                            timeout: 2 * 60 * 1000
                        });
                    } catch (err) {
                        await this.connection.redis.set(
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
        if (notifyWebSafeHtml && messageInfo.text && (messageInfo.text.html || messageInfo.text.plain)) {
            // convert to web safe
            messageInfo.text._generatedHtml = mimeHtml({
                html: messageInfo.text.html,
                text: messageInfo.text.plain
            });
            messageInfo.text.webSafe = true;

            // Embed images referenced by Content-ID
            if (messageInfo.text.html && messageInfo.attachments) {
                let attachmentList = new Map();
                let partList = [];

                // Collect CID-referenced attachments
                for (let attachment of messageInfo.attachments) {
                    let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                    if (contentId && messageInfo.text.html.indexOf(contentId) >= 0) {
                        attachmentList.set(contentId, {
                            attachment,
                            content: attachment.content || null
                        });

                        if (attachment.content) {
                            // already downloaded in a previous step
                            continue;
                        }

                        let buf = Buffer.from(attachment.id, 'base64url');
                        let part = buf.subarray(8).toString();

                        Object.defineProperty(attachment, 'part', {
                            value: part,
                            enumerable: false
                        });

                        if (!partList.includes(part)) {
                            partList.push(part);
                        }
                    }
                }

                if (attachmentList.size) {
                    if (partList.length) {
                        // Download missing attachments in batch
                        try {
                            let contentParts = await this.connection.imapClient.downloadMany(messageInfo.uid, partList, {
                                uid: true
                            });

                            if (contentParts) {
                                for (let [contentId, { attachment }] of attachmentList) {
                                    if (attachment.part && contentParts[attachment.part] && contentParts[attachment.part].content) {
                                        attachmentList.set(contentId, { attachment, content: contentParts[attachment.part].content.toString('base64') });
                                    }
                                }
                            }
                        } catch (err) {
                            this.logger.error({ msg: 'Attachment error', uid: messageInfo.uid, partList, err });
                        }
                    }

                    // Replace CID references with data URIs
                    messageInfo.text.html = messageInfo.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
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
        }

        // Send new message notification
        await this.connection.notify(this, MESSAGE_NEW_NOTIFY, messageInfo, {
            skipWebhook: this.connection.notifyFrom && date < this.connection.notifyFrom,
            canSync
        });

        // Send bounce notification if detected
        if (bounceNotifyInfo) {
            let { index, client } = await getESClient(this.logger);
            if (client) {
                // Find the originating message this bounce applies for
                let searchResult = await client.search({
                    index,
                    size: 20,
                    from: 0,
                    query: {
                        bool: {
                            must: [
                                {
                                    term: {
                                        account: this.connection.account
                                    }
                                },
                                {
                                    term: {
                                        messageId: bounceNotifyInfo.messageId
                                    }
                                }
                            ]
                        }
                    },
                    sort: { uid: 'desc' },
                    _source_excludes: 'headers,text'
                });

                if (searchResult && searchResult.hits && searchResult.hits.hits && searchResult.hits.hits.length) {
                    // Prefer sent messages, then earliest message
                    let message = searchResult.hits.hits
                        .sort((a, b) => {
                            if (a._source.specialUse === '\\Sent') {
                                return -1;
                            }
                            if (b._source.specialUse === '\\Sent') {
                                return 1;
                            }
                            return new Date(a._source.date || a._source.created) - new Date(b._source.date || b._source.created);
                        })
                        .shift()._source;
                    bounceNotifyInfo = Object.assign({ id: message.id }, bounceNotifyInfo);
                }
            }

            // send bounce notification _after_ bounce email notification
            await this.connection.notify(false, EMAIL_BOUNCE_NOTIFY, bounceNotifyInfo, {
                skipWebhook: this.connection.notifyFrom && date < this.connection.notifyFrom
            });
        }

        // Send complaint notification if detected
        if (complaintNotifyInfo) {
            // send complaint notification _after_ complaint email notification
            await this.connection.notify(false, EMAIL_COMPLAINT_NOTIFY, complaintNotifyInfo, {
                skipWebhook: this.connection.notifyFrom && date < this.connection.notifyFrom
            });
        }
    }

    /**
     * Builds message info object from raw IMAP data
     * @param {Object} messageData - Raw message data from IMAP
     * @param {Boolean} extended - Include extended information
     * @returns {Object} Formatted message info
     */
    async getMessageInfo(messageData, extended) {
        if (!messageData) {
            return false;
        }

        // Generate unique message ID
        let packedUid = await this.connection.packUid(this, messageData.uid);

        if (!packedUid) {
            let storedStatus;
            try {
                storedStatus = await this.getStoredStatus();
            } catch (err) {
                storedStatus = { err };
            }

            this.logger.error({
                msg: 'Failed to generate message ID',
                uid: messageData.uid,
                messageId: messageData.messageId,
                mailbox: this.path,
                storedStatus
            });

            throw new Error(
                `Failed to generate message ID (uid=${messageData.uid};uv=${storedStatus.uidValidity};path=${this.path};n=${
                    storedStatus.err ? 'err' : storedStatus.uidNext
                })`
            );
        }

        // Extract attachment information from body structure
        let { attachments, textId, encodedTextSize } = this.getAttachmentList(packedUid, messageData.bodyStructure);

        let envelope = messageData.envelope || {};

        // Use envelope date or fall back to internal date
        let date =
            envelope.date && typeof envelope.date.toISOString === 'function' && envelope.date.toString() !== 'Invalid Date'
                ? envelope.date
                : messageData.internalDate;

        let isDraft = false;
        if (messageData.flags && messageData.flags.has('\\Draft')) {
            isDraft = true;
        }

        // Do not expose the \Recent flag as it is session specific
        if (messageData.flags && messageData.flags.has('\\Recent')) {
            messageData.flags.delete('\\Recent');
        }

        if (messageData.labels && messageData.labels.has('\\Draft')) {
            isDraft = true;
        }

        let headers;

        // This section is needed for Lark Mail as some address fields might be missing
        // from the ENVELOPE section, so fall back to the header instead.
        // Normally, these headers are not fetched from the server and only ENVELOPE is used
        let parsedAddresses = {};
        if (messageData.headers) {
            headers = libmime.decodeHeaders(messageData.headers.toString().trim());
            for (let key of ['from', 'to', 'cc', 'bcc']) {
                if (headers[key]?.length) {
                    try {
                        const addressList = addressparser(headers[key])
                            .filter(address => !!address.address)
                            .map(address => {
                                let name = address.name;
                                try {
                                    name = libmime.decodeWords(name);
                                } catch (err) {
                                    // ignore
                                }
                                return {
                                    name,
                                    address: address.address
                                };
                            });
                        if (addressList?.length) {
                            parsedAddresses[key] = addressList;
                        }
                    } catch (err) {
                        // just ignore
                    }
                }
            }
        }

        // Build message info object
        const result = {
            id: packedUid,
            uid: messageData.uid,

            path: (extended && this.path && normalizePath(this.path)) || undefined,

            emailId: messageData.emailId || undefined,
            threadId: messageData.threadId || undefined,

            date: (date && typeof date.toISOString === 'function' && date.toISOString()) || undefined,

            flags: messageData.flags ? Array.from(messageData.flags) : undefined,
            labels: messageData.labels ? Array.from(messageData.labels) : undefined,

            unseen: messageData.flags && !messageData.flags.has('\\Seen') ? true : undefined,
            flagged: messageData.flags && messageData.flags.has('\\Flagged') ? true : undefined,
            answered: messageData.flags && messageData.flags.has('\\Answered') ? true : undefined,

            draft: isDraft ? true : undefined,

            size: messageData.size || undefined,
            subject: envelope.subject || undefined,
            // Prefer envelope from, fall back to parsed header
            from: envelope.from?.[0] ? envelope.from[0] : parsedAddresses.from?.[0] || undefined,

            replyTo: envelope.replyTo && envelope.replyTo.length ? envelope.replyTo : undefined,
            sender: extended && envelope.sender && envelope.sender[0] ? envelope.sender[0] : undefined,

            to: envelope.to?.length ? envelope.to : parsedAddresses.to || undefined,
            cc: envelope.cc?.length ? envelope.cc : parsedAddresses.cc || undefined,

            bcc: extended && envelope.bcc && envelope.bcc.length ? envelope.bcc : undefined,

            attachments: attachments && attachments.length ? attachments : undefined,
            messageId: (envelope.messageId && envelope.messageId.toString().trim()) || undefined,
            inReplyTo: envelope.inReplyTo || undefined,

            headers: (extended && headers) || undefined,
            text: textId
                ? {
                      id: textId,
                      encodedSize: encodedTextSize
                  }
                : undefined
        };

        // Remove undefined properties
        Object.keys(result).forEach(key => {
            if (typeof result[key] === 'undefined') {
                delete result[key];
            }
        });

        // Check if message is an auto-reply
        if (result.headers && this.connection.isAutoreply(result)) {
            result.isAutoReply = true;
        }

        // Fetch associated bounce information
        try {
            if (result.messageId) {
                let bounces = await appendList.list(this.connection.redis, this.getBounceKey(), result.messageId);
                if (bounces && bounces.length) {
                    result.bounces = bounces.map(row => {
                        let bounce = {
                            message: row.i,
                            recipient: row.r,
                            action: row.a
                        };
                        if (row.m || row.s) {
                            bounce.response = {};
                        }
                        if (row.m) {
                            bounce.response.message = row.m;
                        }
                        if (row.s) {
                            bounce.response.status = row.s;
                        }
                        bounce.date = new Date(row.t).toISOString();
                        return bounce;
                    });
                }
            }
        } catch (E) {
            this.logger.error({
                msg: 'Failed to fetch bounces',
                id: messageData.id,
                uid: messageData.uid,
                messageId: messageData.messageId,
                err: E
            });
        }

        return result;
    }

    /**
     * Parses body structure to extract attachment and text part information
     * @param {String} packedUid - Packed UID for generating attachment IDs
     * @param {Object} bodyStructure - IMAP BODYSTRUCTURE
     * @returns {Object} Attachments list and text part information
     */
    getAttachmentList(packedUid, bodyStructure) {
        let attachments = [];
        let textParts = [[], [], []]; // [plain, html, other]
        if (!bodyStructure) {
            return attachments;
        }

        let idBuf = Buffer.from(packedUid, 'base64url');

        let encodedTextSize = {};

        // Recursively walk body structure tree
        let walk = (node, isRelated) => {
            if (node.type === 'multipart/related') {
                isRelated = true;
            }

            if (!/^multipart\//.test(node.type)) {
                // Leaf node - either attachment or text
                if (node.disposition === 'attachment' || !/^text\/(plain|html)/.test(node.type)) {
                    // Attachment
                    let attachment = {
                        // Append body part number to message ID
                        id: Buffer.concat([idBuf, Buffer.from(node.part || '1')]).toString('base64url'),
                        contentType: node.type,
                        encodedSize: node.size,

                        embedded: isRelated,
                        inline: node.disposition === 'inline' || (!node.disposition && isRelated)
                    };

                    // Extract filename from disposition or content-type parameters
                    let filename = (node.dispositionParameters && node.dispositionParameters.filename) || (node.parameters && node.parameters.name) || false;
                    if (filename) {
                        attachment.filename = filename;
                    }

                    if (node.id) {
                        attachment.contentId = node.id;
                    }

                    // Calendar method parameter
                    if (node.parameters && node.parameters.method && typeof node.parameters.method === 'string') {
                        attachment.method = node.parameters.method;
                    }

                    attachments.push(attachment);
                } else if ((!node.disposition || node.disposition === 'inline') && /^text\/(plain|html)/.test(node.type)) {
                    // Text part
                    let type = node.type.substr(5);
                    if (!encodedTextSize[type]) {
                        encodedTextSize[type] = 0;
                    }
                    encodedTextSize[type] += node.size;

                    // Group by type
                    switch (type) {
                        case 'plain':
                            textParts[0].push(node.part || '1');
                            break;
                        case 'html':
                            textParts[1].push(node.part || '1');
                            break;
                        default:
                            textParts[2].push(node.part || '1');
                            break;
                    }
                }
            }

            // Recursively process multipart children
            if (node.childNodes) {
                node.childNodes.forEach(childNode => walk(childNode, isRelated));
            }
        };

        walk(bodyStructure, false);

        return {
            attachments,
            // Encode text parts array into ID
            textId: Buffer.concat([idBuf, msgpack.encode(textParts)]).toString('base64url'),
            encodedTextSize
        };
    }

    /**
     * Processes flag changes for a message
     * @param {Object} messageData - Message data with changes
     * @param {Object} changes - What changed
     */
    async processChanges(messageData, changes) {
        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, MESSAGE_UPDATED_NOTIFY, {
            id: packedUid,
            uid: messageData.uid,
            changes
        });
        await this.markUpdated();
    }

    /**
     * Performs full synchronization based on indexer type
     */
    async fullSync() {
        const imapIndexer = this.imapIndexer;

        this.logger.trace({ msg: 'Running full sync', imapIndexer });

        switch (imapIndexer) {
            case 'fast':
                return this.runFastSync();
            case 'full':
            default:
                return this.runFullSync();
        }
    }

    /**
     * Performs partial synchronization based on indexer type
     * @param {Object} storedStatus - Current stored mailbox status
     */
    async partialSync(storedStatus) {
        const imapIndexer = this.imapIndexer;

        this.logger.trace({ msg: 'Running partial sync', imapIndexer });

        switch (imapIndexer) {
            case 'fast':
                return this.runFastSync(storedStatus);
            case 'full':
            default:
                return this.runPartialSync(storedStatus);
        }
    }

    /**
     * Fast sync mode - only tracks new messages, doesn't maintain full message list
     * More efficient for large mailboxes where we only care about new messages
     * @param {Object} storedStatus - Current stored mailbox status
     */
    async runFastSync(storedStatus) {
        storedStatus = storedStatus || (await this.getStoredStatus());
        let mailboxStatus = this.getMailboxStatus();

        let lock = await this.getMailboxLock(null, { description: 'Fast sync' });
        this.connection.syncing = true;
        this.syncing = true;
        try {
            if (!this.connection.imapClient) {
                throw new Error('IMAP connection not available');
            }

            let knownUidNext = typeof storedStatus.uidNext === 'number' ? storedStatus.uidNext || 1 : 1;

            if (knownUidNext && mailboxStatus.messages) {
                // detected new emails
                let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };

                let imapClient = this.connection.imapClient;

                // If we have not yet scanned this folder, then start by finding the earliest matching email
                if (typeof storedStatus.uidNext !== 'number' && this.connection.notifyFrom && this.connection.notifyFrom < new Date()) {
                    // Find first message after notifyFrom date
                    let matchingMessages = await imapClient.search({ since: this.connection.notifyFrom }, { uid: true });
                    if (matchingMessages) {
                        let earliestUid = matchingMessages[0];
                        if (earliestUid) {
                            knownUidNext = earliestUid;
                        } else if (mailboxStatus.uidNext) {
                            // no match, start from newest
                            knownUidNext = mailboxStatus.uidNext;
                        }
                    }
                }

                let range = `${knownUidNext}:*`;
                let opts = {
                    uid: true
                };

                // Fetch messages with retry logic
                let fetchCompleted = false;
                let fetchRetryCount = 0;

                while (!fetchCompleted) {
                    try {
                        let messages = [];

                        // Fetch all messages in range
                        for await (let messageData of imapClient.fetch(range, fields, opts)) {
                            if (!messageData || !messageData.uid) {
                                //TODO: support partial responses
                                this.logger.debug({ msg: 'Partial FETCH response', code: 'partial_fetch', query: { range, fields, opts } });
                                continue;
                            }

                            // ignore Recent flag
                            messageData.flags.delete('\\Recent');

                            messages.push(messageData);
                        }
                        // ensure that messages are sorted by UID
                        messages = messages.sort((a, b) => a.uid - b.uid);

                        // Process each new message
                        for (let messageData of messages) {
                            // Update uidNext if this is a new message
                            let updated = await this.connection.redis.hUpdateBigger(this.getMailboxKey(), 'uidNext', messageData.uid + 1, messageData.uid + 1);

                            if (updated) {
                                // new email! Queue for processing
                                await this.connection.redis.zadd(
                                    this.getNotificationsKey(),
                                    messageData.uid,
                                    JSON.stringify({
                                        uid: messageData.uid,
                                        flags: messageData.flags,
                                        internalDate:
                                            (messageData.internalDate &&
                                                typeof messageData.internalDate.toISOString === 'function' &&
                                                messageData.internalDate.toISOString()) ||
                                            null
                                    })
                                );
                            }
                        }

                        try {
                            // clear failure flag
                            await this.connection.redis.hdel(this.connection.getAccountKey(), 'syncError');
                        } catch (err) {
                            // ignore
                        }
                        fetchCompleted = true;
                    } catch (err) {
                        try {
                            // set failure flag
                            await this.connection.redis.hSetExists(
                                this.connection.getAccountKey(),
                                'syncError',
                                JSON.stringify({
                                    path: this.path,
                                    time: new Date().toISOString(),
                                    error: {
                                        error: err.message,
                                        responseStatus: err.responseStatus,
                                        responseText: err.responseText
                                    }
                                })
                            );
                        } catch (err) {
                            // ignore
                        }

                        // Retry with exponential backoff
                        if (!imapClient.usable) {
                            // nothing to do here, connection closed
                            this.logger.error({ msg: `FETCH failed, connection already closed, not retrying`, err });
                            return;
                        }

                        const fetchRetryDelay = calculateFetchBackoff(++fetchRetryCount);
                        this.logger.error({ msg: `FETCH failed, retrying in ${Math.round(fetchRetryDelay / 1000)}s`, err });
                        await new Promise(r => setTimeout(r, fetchRetryDelay));

                        if (!imapClient.usable) {
                            // nothing to do here, connection closed
                            this.logger.error({ msg: `FETCH failed, connection already closed, not retrying`, err });
                            return;
                        }
                    }
                }
            }

            await this.updateStoredStatus(this.getMailboxStatus());

            await this.publishSyncedEvents(storedStatus);
        } finally {
            lock.release();
            this.connection.syncing = false;
            this.syncing = false;
        }
    }

    /**
     * Partial sync - fetches only changed messages using MODSEQ or UID range
     * Used for incremental updates when we know something changed
     * @param {Object} storedStatus - Current stored mailbox status
     */
    async runPartialSync(storedStatus) {
        storedStatus = storedStatus || (await this.getStoredStatus());
        let mailboxStatus = this.getMailboxStatus();

        let lock = await this.getMailboxLock(null, { description: 'Partial sync' });
        this.connection.syncing = true;
        this.syncing = true;
        try {
            if (!this.connection.imapClient) {
                throw new Error('IMAP connection not available');
            }

            let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };
            let range = '1:*';
            let opts = {
                uid: true
            };

            // Use CONDSTORE if available for efficient change detection
            if (this.connection.imapClient.enabled.has('CONDSTORE') && storedStatus.highestModseq) {
                // Only fetch messages changed since last known MODSEQ
                opts.changedSince = storedStatus.highestModseq;
            } else if (storedStatus.uidNext) {
                // Fall back to fetching new messages only
                range = `${storedStatus.uidNext}:*`;
            }

            if (mailboxStatus.messages) {
                // only fetch messages if there are some
                let fetchCompleted = false;
                let fetchRetryCount = 0;
                while (!fetchCompleted) {
                    // Get fresh imapClient reference inside retry loop
                    let imapClient = this.connection.imapClient;
                    if (!imapClient || !imapClient.usable) {
                        this.logger.error({ msg: 'IMAP client not available for partial sync' });
                        throw new Error('IMAP connection not available');
                    }

                    try {
                        // Fetch and process each message
                        for await (let messageData of imapClient.fetch(range, fields, opts)) {
                            if (!messageData || !messageData.uid) {
                                //TODO: support partial responses
                                this.logger.debug({ msg: 'Partial FETCH response', code: 'partial_fetch', query: { range, fields, opts } });
                                continue;
                            }

                            // ignore Recent flag
                            messageData.flags.delete('\\Recent');

                            let storedMessage = await this.entryListGet(messageData.uid, { uid: true });

                            let changes;
                            if (!storedMessage) {
                                // New message
                                let seq = await this.entryListSet(messageData);
                                if (seq) {
                                    // Queue for processing
                                    await this.connection.redis.zadd(
                                        this.getNotificationsKey(),
                                        messageData.uid,
                                        JSON.stringify({
                                            uid: messageData.uid,
                                            flags: messageData.flags,
                                            internalDate:
                                                (messageData.internalDate &&
                                                    typeof messageData.internalDate.toISOString === 'function' &&
                                                    messageData.internalDate.toISOString()) ||
                                                null
                                        })
                                    );
                                }
                            } else if ((changes = compareExisting(storedMessage.entry, messageData))) {
                                // Existing message with changes
                                let seq = await this.entryListSet(messageData);
                                if (seq) {
                                    await this.processChanges(messageData, changes);
                                }
                            }
                        }
                        try {
                            // clear failure flag
                            await this.connection.redis.hdel(this.connection.getAccountKey(), 'syncError');
                        } catch (err) {
                            // ignore
                        }
                        fetchCompleted = true;
                    } catch (err) {
                        try {
                            // set failure flag
                            await this.connection.redis.hSetExists(
                                this.connection.getAccountKey(),
                                'syncError',
                                JSON.stringify({
                                    path: this.path,
                                    time: new Date().toISOString(),
                                    error: {
                                        error: err.message,
                                        responseStatus: err.responseStatus,
                                        responseText: err.responseText
                                    }
                                })
                            );
                        } catch (err) {
                            // ignore
                        }

                        // Retry with exponential backoff
                        if (!imapClient.usable) {
                            // nothing to do here, connection closed
                            this.logger.error({ msg: `FETCH failed, connection already closed, not retrying` });
                            return;
                        }

                        const fetchRetryDelay = calculateFetchBackoff(++fetchRetryCount);
                        this.logger.error({ msg: `FETCH failed, retrying in ${Math.round(fetchRetryDelay / 1000)}s` });
                        await new Promise(r => setTimeout(r, fetchRetryDelay));

                        if (!imapClient.usable) {
                            // nothing to do here, connection closed
                            this.logger.error({ msg: `FETCH failed, connection already closed, not retrying` });
                            return;
                        }
                    }
                }
            }

            await this.updateStoredStatus(this.getMailboxStatus());

            await this.publishSyncedEvents(storedStatus);
        } finally {
            lock.release();
            this.connection.syncing = false;
            this.syncing = false;
        }
    }

    /**
     * Full sync - fetches all messages and detects additions, deletions, and changes
     * Most thorough but slowest sync method
     */
    async runFullSync() {
        let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };
        let opts = {};

        let lock = await this.getMailboxLock(null, { description: 'Full sync' });
        this.connection.syncing = true;
        this.syncing = true;
        try {
            // Generate unique ID for this sync loop to track batch ordering
            const loopId = crypto.randomUUID();

            // Wait for next tick to ensure ImapFlow has processed all untagged responses from SELECT
            await new Promise(resolve => setImmediate(resolve));

            let mailboxStatus = this.getMailboxStatus();

            this.logger.debug({
                msg: 'Starting full sync',
                code: 'full_sync_start',
                loopId,
                mailboxStatus,
                imapClientExists: mailboxStatus.messages
            });

            // Track highest sequence number seen
            let seqMax = 0;
            let changes;

            // Get current message count for deletion detection
            let storedMaxSeqOld = await this.connection.redis.zcard(this.getMessagesKey());

            let responseCounters = {
                empty: 0,
                partial: 0,
                messages: 0
            };

            if (mailboxStatus.messages) {
                this.logger.debug({
                    msg: 'Running FETCH',
                    code: 'run_fetch',
                    query: { fields, opts },
                    expectedMessages: mailboxStatus.messages,
                    mailbox: mailboxStatus,
                    maxBatchSize: FETCH_BATCH_SIZE,
                    expectedBatches: Math.ceil(mailboxStatus.messages / FETCH_BATCH_SIZE)
                });

                // Process messages in batches to avoid memory issues
                let range = false;
                let lastHighestUid = 0;
                let batchNumber = 0;
                // process messages in batches
                while ((range = getFetchRange(mailboxStatus.messages, range))) {
                    batchNumber++;
                    this.logger.debug({
                        msg: 'Processing batch',
                        code: 'fetch_batch',
                        loopId,
                        batchNumber,
                        range,
                        totalMessages: mailboxStatus.messages,
                        previousRange: batchNumber > 1 ? 'calculated' : 'initial'
                    });
                    let fetchCompleted = false;
                    let fetchRetryCount = 0;
                    while (!fetchCompleted) {
                        // Get fresh imapClient reference inside retry loop
                        // This ensures we use the current connection state
                        const imapClient = this.connection.imapClient;
                        if (!imapClient || !imapClient.usable) {
                            this.logger.error({ msg: 'IMAP client not available for FETCH' });
                            throw new Error('IMAP connection not available');
                        }

                        try {
                            this.logger.debug({
                                msg: 'Starting FETCH command',
                                code: 'fetch_start',
                                loopId,
                                batchNumber,
                                range,
                                retryCount: fetchRetryCount,
                                totalMessages: mailboxStatus.messages
                            });

                            for await (let messageData of imapClient.fetch(range, fields, opts)) {
                                if (!messageData) {
                                    this.logger.debug({ msg: 'Empty FETCH response', code: 'empty_fetch', query: { range, fields, opts } });
                                    responseCounters.empty++;
                                    continue;
                                }

                                if (!messageData.uid || (fields.flags && !messageData.flags)) {
                                    // TODO: support partial responses
                                    // For now, without UID or FLAGS there's nothing to do
                                    this.logger.debug({
                                        msg: 'Partial FETCH response',
                                        code: 'partial_fetch',
                                        query: { range, fields, opts },
                                        responseKeys: Object.keys(messageData)
                                    });
                                    responseCounters.partial++;
                                    continue;
                                }

                                if (messageData.uid <= lastHighestUid) {
                                    // already processed in the previous batch
                                    // probably an older email was deleted which shifted message entries
                                    continue;
                                }
                                lastHighestUid = messageData.uid;

                                responseCounters.messages++;

                                if (fields.internalDate && !messageData.internalDate) {
                                    this.logger.debug({
                                        msg: 'Missing INTERNALDATE',
                                        code: 'fetch_date_missing',
                                        query: { range, fields, opts },
                                        responseKeys: Object.keys(messageData)
                                    });
                                }

                                // ignore Recent flag
                                messageData.flags.delete('\\Recent');

                                if (messageData.seq > seqMax) {
                                    seqMax = messageData.seq;
                                }

                                let storedMessage = await this.entryListGet(messageData.uid, { uid: true });
                                if (!storedMessage) {
                                    // New message
                                    let seq = await this.entryListSet(messageData);
                                    if (seq) {
                                        await this.connection.redis.zadd(
                                            this.getNotificationsKey(),
                                            messageData.uid,
                                            JSON.stringify({
                                                uid: messageData.uid,
                                                flags: messageData.flags,
                                                internalDate:
                                                    (messageData.internalDate &&
                                                        typeof messageData.internalDate.toISOString === 'function' &&
                                                        messageData.internalDate.toISOString()) ||
                                                    null
                                            })
                                        );
                                    }
                                } else {
                                    // Check for deleted messages between stored and current sequence
                                    let diff = storedMessage.seq - messageData.seq;
                                    if (diff) {
                                        this.logger.trace({ msg: 'Deleted range', inloop: true, diff, start: messageData.seq });
                                    }
                                    // Process deletions
                                    for (let i = diff - 1; i >= 0; i--) {
                                        let seq = messageData.seq + i;
                                        let deletedEntry = await this.entryListExpunge(seq);
                                        if (deletedEntry) {
                                            await this.processDeleted(deletedEntry);
                                        }
                                    }

                                    // Check for changes
                                    if ((changes = compareExisting(storedMessage.entry, messageData))) {
                                        let seq = await this.entryListSet(messageData);
                                        if (seq) {
                                            await this.processChanges(messageData, changes);
                                        }
                                    }
                                }
                            }

                            try {
                                // clear failure flag
                                await this.connection.redis.hdel(this.connection.getAccountKey(), 'syncError');
                            } catch (err) {
                                // ignore
                            }

                            this.logger.debug({
                                msg: 'FETCH completed successfully',
                                code: 'fetch_success',
                                loopId,
                                batchNumber,
                                range,
                                retryCount: fetchRetryCount
                            });

                            fetchCompleted = true;
                        } catch (err) {
                            this.logger.error({
                                msg: 'FETCH failed',
                                code: 'fetch_error',
                                loopId,
                                batchNumber,
                                range,
                                retryCount: fetchRetryCount,
                                totalMessages: mailboxStatus.messages,
                                error: err.message,
                                responseStatus: err.responseStatus,
                                responseText: err.responseText
                            });

                            if (!imapClient.usable) {
                                // nothing to do here, connection closed
                                this.logger.error({ msg: `FETCH failed, connection already closed, not retrying`, loopId });
                                return;
                            }

                            try {
                                // set failure flag
                                await this.connection.redis.hSetExists(
                                    this.connection.getAccountKey(),
                                    'syncError',
                                    JSON.stringify({
                                        path: this.path,
                                        time: new Date().toISOString(),
                                        error: {
                                            error: err.message,
                                            responseStatus: err.responseStatus,
                                            responseText: err.responseText
                                        }
                                    })
                                );
                            } catch (err) {
                                // ignore
                            }

                            // Retry with exponential backoff
                            const fetchRetryDelay = calculateFetchBackoff(++fetchRetryCount);
                            this.logger.error({ msg: `FETCH failed, retrying in ${Math.round(fetchRetryDelay / 1000)}s`, loopId, batchNumber });
                            await new Promise(r => setTimeout(r, fetchRetryDelay));

                            if (!imapClient.usable) {
                                // nothing to do here, connection closed
                                this.logger.error({ msg: `FETCH failed, connection already closed, not retrying`, loopId });
                                return;
                            }

                            // Verify we're still on the correct mailbox after the delay
                            // Another operation might have changed the mailbox while we were waiting
                            const currentMailbox = this.connection.imapClient.mailbox;
                            if (!currentMailbox || currentMailbox.path !== this.path) {
                                this.logger.error({
                                    msg: 'Mailbox changed during retry delay, aborting sync',
                                    expectedPath: this.path,
                                    currentPath: currentMailbox ? currentMailbox.path : 'none',
                                    loopId
                                });
                                throw new Error('Mailbox changed during sync operation');
                            }

                            // Refresh mailbox status in case it changed
                            const oldMailboxMessages = mailboxStatus.messages;
                            mailboxStatus = this.getMailboxStatus();

                            this.logger.debug({
                                msg: 'Refreshed mailbox status after error',
                                code: 'mailbox_status_refresh',
                                loopId,
                                batchNumber,
                                oldMessages: oldMailboxMessages,
                                newMessages: mailboxStatus.messages,
                                range
                            });
                        }
                    }
                }
            }

            // Delete any messages that weren't seen in this sync
            let storedMaxSeq = await this.connection.redis.zcard(this.getMessagesKey());
            let diff = storedMaxSeq - seqMax;
            if (diff) {
                this.logger.trace({
                    msg: 'Deleted range',
                    inloop: false,
                    diff,
                    start: seqMax + 1,
                    messagesKey: this.getMessagesKey(),
                    zcard: storedMaxSeq,
                    zcardOld: storedMaxSeqOld,
                    responseCounters
                });
            }

            // Process remaining deletions
            for (let i = diff - 1; i >= 0; i--) {
                let seq = seqMax + i + 1;
                let deletedEntry = await this.entryListExpunge(seq);
                if (deletedEntry) {
                    await this.processDeleted(deletedEntry);
                }
            }

            // Update status with full sync timestamp
            let status = this.getMailboxStatus();
            status.lastFullSync = new Date();

            await this.updateStoredStatus(status);
            let storedStatus = await this.getStoredStatus();

            await this.publishSyncedEvents(storedStatus);
        } finally {
            this.connection.syncing = false;
            this.syncing = false;
            lock.release();
        }
    }

    /**
     * Processes queued notification events after sync
     * Fetches full message details and sends notifications
     * @param {Object} storedStatus - Current mailbox status
     */
    async publishSyncedEvents(storedStatus) {
        let messageFetchOptions = {};

        let documentStoreEnabled = await settings.get('documentStoreEnabled');

        // Configure text fetching
        let notifyText = await settings.get('notifyText');
        if (documentStoreEnabled || notifyText) {
            messageFetchOptions.textType = '*';
            let notifyTextSize = await settings.get('notifyTextSize');

            if (documentStoreEnabled && notifyTextSize) {
                // Ensure at least 1MB for document store
                notifyTextSize = Math.max(notifyTextSize, 1024 * 1024);
            }

            if (notifyTextSize) {
                messageFetchOptions.maxBytes = notifyTextSize;
            }
        }

        // Configure header fetching
        let notifyHeaders = (await settings.get('notifyHeaders')) || [];
        if (documentStoreEnabled || notifyHeaders.length) {
            messageFetchOptions.headers = notifyHeaders.includes('*') || documentStoreEnabled ? true : notifyHeaders.length ? notifyHeaders : false;
        }

        // Also request autoresponse headers
        if (messageFetchOptions.headers !== true) {
            let fetchHeaders = new Set(messageFetchOptions.headers || []);

            // Auto-reply detection headers
            fetchHeaders.add('x-autoreply');
            fetchHeaders.add('x-autorespond');
            fetchHeaders.add('auto-submitted');
            fetchHeaders.add('precedence');

            // Threading headers
            fetchHeaders.add('in-reply-to');
            fetchHeaders.add('references');

            // Content type for bounce/complaint detection
            fetchHeaders.add('content-type');

            if (this.isLarkSuite) {
                // Add address headers as a fallback for unreliable ENVELOPE
                fetchHeaders.add('from');
                fetchHeaders.add('to');
                fetchHeaders.add('cc');
            }

            messageFetchOptions.fetchHeaders = Array.from(fetchHeaders);
        }

        // Process queued notifications
        let queuedEntry;
        let hadUpdates = false;
        while ((queuedEntry = await this.connection.redis.zpopmin(this.getNotificationsKey(), 1)) && queuedEntry.length) {
            hadUpdates = true;

            let [messageData, uid] = queuedEntry;
            uid = Number(uid);
            try {
                messageData = JSON.parse(messageData);
                if (typeof messageData.internalDate === 'string') {
                    messageData.internalDate = new Date(messageData.internalDate);
                }
            } catch (err) {
                continue;
            }

            // Check if message should be synced to document store
            let canSync = documentStoreEnabled && (!this.connection.syncFrom || messageData.internalDate >= this.connection.syncFrom);

            if (this.connection.notifyFrom && messageData.internalDate < this.connection.notifyFrom && !canSync) {
                // skip too old messages
                continue;
            }

            await this.processNew(messageData, messageFetchOptions, canSync, storedStatus);
        }

        if (hadUpdates) {
            await this.markUpdated();
        }
    }

    /**
     * Called when mailbox is opened/selected
     * Determines what type of sync is needed based on current state
     */
    async onOpen() {
        clearTimeout(this.runPartialSyncTimer);
        this.selected = true;

        // Track connection count to detect reconnects
        this.previouslyConnected = Number(await this.connection.redis.hget(this.connection.getAccountKey(), `state:count:connected`)) || 0;

        let mailboxStatus = this.getMailboxStatus();

        try {
            let storedStatus = await this.getStoredStatus();

            // Store initial UID on first sync
            if (storedStatus.uidNext === false && typeof mailboxStatus.uidNext === 'number') {
                // update first UID
                await this.connection.redis.hSetNew(this.getMailboxKey(), 'initialUidNext', mailboxStatus.uidNext.toString());
                storedStatus = await this.getStoredStatus();
            }

            // Process any queued notifications first
            let hasQueuedNotifications = await this.connection.redis.exists(this.getNotificationsKey());
            if (hasQueuedNotifications) {
                return await this.fullSync();
            }

            // Check for UIDVALIDITY change (mailbox recreated)
            if ('uidValidity' in storedStatus && mailboxStatus.uidValidity !== storedStatus.uidValidity) {
                // UIDVALIDITY has changed, full sync is required!
                // delete mailbox status
                let result = await this.connection.redis.multi().zcard(this.getMessagesKey()).del(this.getMessagesKey()).del(this.getMailboxKey()).exec();

                let deletedMessages = (result[0] && Number(result[0][1])) || 0;
                this.logger.info({
                    msg: 'UIDVALIDITY change',
                    deleted: deletedMessages,
                    prevUidValidity: validUidValidity(storedStatus.uidValidity) ? storedStatus.uidValidity.toString() : false,
                    uidValidity: validUidValidity(mailboxStatus.uidValidity) ? mailboxStatus.uidValidity.toString() : false
                });

                this.logger.debug({ msg: 'Mailbox reset', path: this.listingEntry.path });
                await this.connection.notify(this, MAILBOX_RESET_NOTIFY, {
                    path: this.listingEntry.path,
                    name: this.listingEntry.name,
                    specialUse: this.listingEntry.specialUse || false,
                    uidValidity: validUidValidity(mailboxStatus.uidValidity) ? mailboxStatus.uidValidity.toString() : false,
                    prevUidValidity: validUidValidity(storedStatus.uidValidity) ? storedStatus.uidValidity.toString() : false
                });

                // do not advertise messages as new
                this.listingEntry.isNew = true;

                // generates blank stored status as the Redis key was deleted
                storedStatus = await this.getStoredStatus();
            }

            // Determine sync strategy based on various conditions

            // No changes if MODSEQ hasn't changed
            if (storedStatus.highestModseq && storedStatus.highestModseq === mailboxStatus.highestModseq) {
                return false;
            }

            // No changes if mailbox is empty
            if (storedStatus.messages === 0 && mailboxStatus.messages === 0) {
                return false;
            }

            // Partial sync if we can detect only new messages or flag changes
            if (
                this.connection.imapClient.enabled.has('CONDSTORE') &&
                storedStatus.highestModseq < mailboxStatus.highestModseq &&
                storedStatus.messages <= mailboxStatus.messages &&
                mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
            ) {
                // search for flag changes and new messages
                return await this.partialSync(storedStatus);
            }

            // Partial sync if only new messages
            if (
                storedStatus.messages < mailboxStatus.messages &&
                mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
            ) {
                // seem to have new messages only
                return await this.partialSync(storedStatus);
            }

            // Skip if nothing changed and recent full sync
            if (
                storedStatus.messages === mailboxStatus.messages &&
                storedStatus.uidNext === mailboxStatus.uidNext &&
                storedStatus.lastFullSync &&
                storedStatus.lastFullSync >= new Date(Date.now() - FULL_SYNC_DELAY)
            ) {
                // too soon from last full sync, message count seems the same
                return false;
            }

            // Perform full sync. Only way of getting flag changes from non-CONDSTORE servers
            return await this.fullSync();
        } catch (err) {
            if (err.mailboxMissing) {
                // this mailbox is missing, refresh listing
                try {
                    await this.connection.getCurrentListing();
                } catch (E) {
                    this.logger.error({ msg: 'Missing mailbox', err, E });
                }
            }
            throw err;
        } finally {
            // Send new mailbox notification if this is the first sync
            if (this.listingEntry.isNew) {
                // fully synced, so not new anymore
                this.listingEntry.isNew = false;
                this.logger.debug({ msg: 'New mailbox', path: this.listingEntry.path });
                this.connection.notify(this, MAILBOX_NEW_NOTIFY, {
                    path: this.listingEntry.path,
                    name: this.listingEntry.name,
                    specialUse: this.listingEntry.specialUse || false,
                    uidValidity: mailboxStatus.uidValidity.toString()
                });
            }

            // Resolve sync promise or start IDLE
            if (this.synced) {
                this.synced();
            } else {
                await this.select();
            }
        }
    }

    /**
     * Called when mailbox is closed/deselected
     */
    async onClose() {
        clearTimeout(this.runPartialSyncTimer);
        this.selected = false;
    }

    // User methods
    // Call `clearTimeout(this.connection.completedTimer);` after locking mailbox
    // Call this.onTaskCompleted() after selected mailbox is processed and lock is released

    /**
     * Fetches text content for a message
     * @param {Object} message - Message object with uid
     * @param {Array} textParts - Array of body part numbers to fetch
     * @param {Object} options - Fetch options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Text content by type (plain, html, etc)
     */
    async getText(message, textParts, options, connectionOptions) {
        options = options || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let result = {};

        let maxBytes = options.maxBytes || Infinity;
        // Request extra bytes to ensure complete UTF-8 sequences
        let reqMaxBytes = options.maxBytes && !isNaN(options.maxBytes) ? Number(options.maxBytes) + 4 : maxBytes;

        let hasMore = false;

        let lock;
        if (!options.skipLock) {
            lock = await this.getMailboxLock(connectionClient, { description: `Get text: ${message.uid}` });
        }

        try {
            for (let part of textParts) {
                let { meta, content } = await connectionClient.download(message.uid, part, {
                    uid: true,
                    // make sure we request enough bytes so we would have complete utf-8 codepoints
                    maxBytes: Math.min(reqMaxBytes, MAX_ALLOWED_DOWNLOAD_SIZE),
                    chunkSize: options.chunkSize
                });

                if (!content) {
                    continue;
                }
                let text = await download(content);
                text = text.toString().replace(/\r?\n/g, '\n');

                // Group by content type (plain, html, etc)
                let typeKey = (meta.contentType && meta.contentType.split('/')[1]) || 'plain';
                if (!result[typeKey]) {
                    result[typeKey] = [];
                }

                // Check size limits
                let typeSize = result[typeKey].reduce((sum, entry) => sum + entry.length, 0);
                if (typeSize >= maxBytes) {
                    hasMore = true;
                    continue;
                }
                if (typeSize + text.length > maxBytes) {
                    text = text.substr(0, maxBytes - typeSize);
                    hasMore = true;
                }
                result[typeKey].push(text);
            }
        } finally {
            if (lock) {
                lock.release();
            }
        }

        // Join multiple parts of same type
        Object.keys(result).forEach(key => {
            result[key] = result[key].join('\n');
        });

        result.hasMore = hasMore;

        if (!options.skipLock) {
            this.onTaskCompleted(connectionClient);
        }

        return result;
    }

    /**
     * Downloads an attachment
     * @param {Object} message - Message object with uid
     * @param {String} part - Body part number
     * @param {Object} options - Download options
     * @param {Object} connectionOptions - Connection options
     * @returns {Stream} Readable stream of attachment content
     */
    async getAttachment(message, part, options, connectionOptions) {
        options = options || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Get attachment: ${message.uid}/${part}` });

        let streaming = false;
        let released = false;
        try {
            let { meta, content } = await connectionClient.download(message.uid, part, {
                uid: true,
                maxBytes: Math.min(options.maxBytes || 0, MAX_ALLOWED_DOWNLOAD_SIZE),
                chunkSize: options.chunkSize
            });

            if (!meta) {
                return false;
            }

            // Build content-disposition header with proper encoding
            let filenameParam = '';
            if (meta.filename) {
                let isCleartextFilename = meta.filename && /^[a-z0-9 _\-()^[\]~=,+*$]+$/i.test(meta.filename);
                if (isCleartextFilename) {
                    filenameParam = `; filename=${JSON.stringify(meta.filename)}`;
                } else {
                    // Use RFC 2231 encoding for non-ASCII filenames
                    filenameParam = `; filename=${JSON.stringify(he.encode(meta.filename))}; filename*=utf-8''${encodeURIComponent(meta.filename)}`;
                }
            }

            // Add HTTP headers to stream
            content.headers = {
                'content-type': meta.contentType || 'application/octet-stream',
                'content-disposition': 'attachment' + filenameParam
            };

            content.contentType = meta.contentType;
            content.filename = meta.filename;
            content.disposition = meta.disposition;
            streaming = true;

            // Release lock when stream ends
            content.once('end', () => {
                if (!released) {
                    released = true;
                    lock.release();
                }
            });

            content.once('error', () => {
                if (!released) {
                    released = true;
                    lock.release();
                    this.connection.onTaskCompleted(connectionClient);
                }
            });

            return content;
        } finally {
            if (!streaming) {
                lock.release();
                this.connection.onTaskCompleted(connectionClient);
            }
        }
    }

    /**
     * Fetches complete message details
     * @param {Object} message - Message object with uid
     * @param {Object} options - Fetch options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Complete message information
     */
    async getMessage(message, options, connectionOptions) {
        options = options || {};

        let messageInfo;

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        try {
            let lock;
            if (!options.skipLock) {
                lock = await this.getMailboxLock(connectionClient, { description: `Get message: ${message.uid}` });
            }

            try {
                // Configure which fields to fetch
                let fields = options.fields || {
                    uid: true,
                    flags: true,
                    size: true,
                    bodyStructure: true,
                    envelope: true,
                    internalDate: true,
                    headers: 'headers' in options ? options.headers : true,
                    emailId: true,
                    threadId: true,
                    labels: true
                };

                let messageData = await connectionClient.fetchOne(message.uid, fields, { uid: true });

                // Mark as seen if requested
                if (options.markAsSeen && (!messageData.flags || !messageData.flags.has('\\Seen'))) {
                    try {
                        let res = await connectionClient.messageFlagsAdd(message.uid, ['\\Seen'], { uid: true });
                        if (res) {
                            messageData.flags.add('\\Seen');
                        }
                    } catch (err) {
                        this.logger.debug({ msg: 'Failed to mark message as Seen', message: message.uid, err });
                    }
                }

                if (!messageData || !messageData.uid) {
                    //TODO: support partial responses
                    this.logger.debug({ msg: 'Partial FETCH response', code: 'partial_fetch', query: { range: message.uid, fields, opts: { uid: true } } });
                    return false;
                }

                messageInfo = await this.getMessageInfo(messageData, true);
            } finally {
                if (lock) {
                    lock.release();
                }
            }

            if (!messageInfo) {
                return false;
            }

            // Merge decoded text content with message data (if requested)
            if (options.textType && messageInfo.text && messageInfo.text.id) {
                let { textParts } = await this.connection.getMessageTextPaths(messageInfo.text.id);
                if (textParts && textParts.length) {
                    // Select which text parts to fetch
                    switch (options.textType) {
                        case 'plain':
                            textParts = textParts[0];
                            break;
                        case 'html':
                            textParts = textParts[1];
                            break;
                        default:
                            textParts = textParts.flatMap(entry => entry);
                            break;
                    }

                    if (textParts && textParts.length) {
                        let textContent = await this.getText(message, textParts, options, { connectionClient });
                        if (options.textType && options.textType !== '*') {
                            textContent = {
                                [options.textType]: textContent[options.textType] || '',
                                hasMore: textContent.hasMore
                            };
                        }
                        messageInfo.text = Object.assign(messageInfo.text, textContent);
                    }
                }
            }

            // Convert to web-safe HTML if requested
            if (options.preProcessHtml && messageInfo.text && (messageInfo.text.html || messageInfo.text.plain)) {
                messageInfo.text.html = mimeHtml({
                    html: messageInfo.text.html,
                    text: messageInfo.text.plain
                });
                messageInfo.text.webSafe = true;
            }

            // Embed attached images as data URIs if requested
            if (options.embedAttachedImages && messageInfo.text && messageInfo.text.html && messageInfo.attachments) {
                let attachmentList = new Map();
                let partList = [];

                // Find images referenced by CID
                for (let attachment of messageInfo.attachments) {
                    let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                    if (contentId && messageInfo.text.html.indexOf(contentId) >= 0) {
                        attachmentList.set(contentId, { attachment, content: null });

                        let buf = Buffer.from(attachment.id, 'base64url');
                        let part = buf.subarray(8).toString();

                        Object.defineProperty(attachment, 'part', {
                            value: part,
                            enumerable: false
                        });

                        if (!partList.includes(part)) {
                            partList.push(part);
                        }
                    }
                }

                if (partList.length) {
                    try {
                        // Download all referenced images in batch
                        let contentParts = await connectionClient.downloadMany(messageInfo.uid, partList, {
                            uid: true
                        });

                        if (contentParts) {
                            for (let { attachment } of attachmentList.values()) {
                                if (attachment.part && contentParts[attachment.part] && contentParts[attachment.part].content) {
                                    Object.defineProperty(attachment, 'content', {
                                        value: contentParts[attachment.part].content,
                                        enumerable: false
                                    });
                                }
                            }

                            // Replace CID references with data URIs
                            messageInfo.text.html = messageInfo.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                                if (attachmentList.has(cidMatch)) {
                                    let { attachment } = attachmentList.get(cidMatch);
                                    if (attachment.content) {
                                        return `data:${attachment.contentType || 'application/octet-stream'};base64,${attachment.content.toString('base64')}`;
                                    }
                                }
                                return fullMatch;
                            });
                        }
                    } catch (err) {
                        this.logger.error({ msg: 'Attachment error', uid: messageInfo.uid, partList, err });
                    }
                }
            }

            // Add mailbox special use information
            if (this.listingEntry.specialUse) {
                messageInfo.specialUse = this.listingEntry.specialUse;
            }

            // Determine message's special use folder
            for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
                if (this.listingEntry.specialUse === specialUseTag || (messageInfo.labels && messageInfo.labels.includes(specialUseTag))) {
                    messageInfo.messageSpecialUse = specialUseTag;
                    break;
                }
            }

            return messageInfo;
        } finally {
            if (!options.skipLock) {
                this.connection.onTaskCompleted(connectionClient);
            }
        }
    }

    /**
     * Updates message flags and labels
     * @param {Object} message - Message object with uid
     * @param {Object} updates - Updates to apply (flags, labels)
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result of updates
     */
    async updateMessage(message, updates, connectionOptions) {
        updates = updates || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Update message: ${message.uid}` });

        try {
            let result = {};

            // Update flags
            if (updates.flags) {
                if (updates.flags.set) {
                    // If set exists then ignore add/delete calls
                    let value = await connectionClient.messageFlagsSet(message.uid, updates.flags.set, { uid: true });
                    result.flags = {
                        set: value
                    };
                } else {
                    if (updates.flags.add && updates.flags.add.length) {
                        let value = await connectionClient.messageFlagsAdd(message.uid, updates.flags.add, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.add = value;
                    }

                    if (updates.flags.delete && updates.flags.delete.length) {
                        let value = await connectionClient.messageFlagsRemove(message.uid, updates.flags.delete, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.delete = value;
                    }
                }
            }

            // Update Gmail labels
            if (updates.labels && this.isGmail) {
                if (updates.labels.set) {
                    // If set exists then ignore add/delete calls
                    let value = await connectionClient.messageFlagsSet(message.uid, updates.labels.set, { uid: true, useLabels: true });
                    result.labels = {
                        set: value
                    };
                } else {
                    if (updates.labels.add && updates.labels.add.length) {
                        let value = await connectionClient.messageFlagsAdd(message.uid, updates.labels.add, { uid: true, useLabels: true });
                        if (!result.labels) {
                            result.labels = {};
                        }
                        result.labels.add = value;
                    }

                    if (updates.labels.delete && updates.labels.delete.length) {
                        let value = await connectionClient.messageFlagsRemove(message.uid, updates.labels.delete, { uid: true, useLabels: true });
                        if (!result.labels) {
                            result.labels = {};
                        }
                        result.labels.delete = value;
                    }
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Updates multiple messages based on search criteria
     * @param {Object} search - Search criteria
     * @param {Object} updates - Updates to apply
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result of updates
     */
    async updateMessages(search, updates, connectionOptions) {
        updates = updates || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Update messages` });

        try {
            let result = {};

            // Update flags for matching messages
            if (updates.flags) {
                if (updates.flags.set) {
                    // If set exists then ignore add/delete calls
                    let value = await connectionClient.messageFlagsSet(search, updates.flags.set, { uid: true });
                    result.flags = {
                        set: value
                    };
                } else {
                    if (updates.flags.add && updates.flags.add.length) {
                        let value = await connectionClient.messageFlagsAdd(search, updates.flags.add, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.add = value;
                    }

                    if (updates.flags.delete && updates.flags.delete.length) {
                        let value = await connectionClient.messageFlagsRemove(search, updates.flags.delete, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.delete = value;
                    }
                }
            }

            // Update Gmail labels for matching messages
            if (updates.labels && this.isGmail) {
                if (updates.labels.set) {
                    // If set exists then ignore add/delete calls
                    let value = await connectionClient.messageFlagsSet(search, updates.labels.set, { uid: true, useLabels: true });
                    result.labels = {
                        set: value
                    };
                } else {
                    if (updates.labels.add && updates.labels.add.length) {
                        let value = await connectionClient.messageFlagsAdd(search, updates.labels.add, { uid: true, useLabels: true });
                        if (!result.labels) {
                            result.labels = {};
                        }
                        result.labels.add = value;
                    }

                    if (updates.labels.delete && updates.labels.delete.length) {
                        let value = await connectionClient.messageFlagsRemove(search, updates.labels.delete, { uid: true, useLabels: true });
                        if (!result.labels) {
                            result.labels = {};
                        }
                        result.labels.delete = value;
                    }
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Moves a message to another mailbox
     * @param {Object} message - Message object with uid
     * @param {Object} target - Target mailbox with path
     * @param {Object} options - Move options
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result with new message ID and UID
     */
    async moveMessage(message, target, options, connectionOptions) {
        target = target || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Move message: ${message.uid} to: ${target.path}` });

        try {
            let result = {};

            if (target.path) {
                // Perform the move
                let value = await connectionClient.messageMove(message.uid, target.path, { uid: true });
                result.path = target.path;

                // Get new UID in target mailbox
                if (value && value.uidMap && value.uidMap.has(message.uid)) {
                    let uid = value.uidMap.get(message.uid);
                    let packed = await this.connection.packUid(target.path, uid);
                    result.id = packed;
                    result.uid = uid;
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Moves multiple messages to another mailbox
     * @param {Object} search - Search criteria
     * @param {Object} target - Target mailbox with path
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result with ID mappings
     */
    async moveMessages(search, target, connectionOptions) {
        target = target || {};

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Move messages to: ${target.path}` });

        try {
            let result = {};

            if (target.path) {
                // Perform the move
                let value = await connectionClient.messageMove(search, target.path, { uid: true });
                result.path = target.path;

                // Build ID map for moved messages
                if (value && value.uidMap && value.uidMap.size) {
                    let moveMap = [];
                    for (let [suid, tuid] of value.uidMap) {
                        moveMap.push([await this.connection.packUid(this.path, suid), await this.connection.packUid(target.path, tuid)]);
                    }
                    result.idMap = moveMap;
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Deletes a message or moves it to trash
     * @param {Object} message - Message object with uid
     * @param {Boolean} force - Force permanent deletion
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result of deletion
     */
    async deleteMessage(message, force, connectionOptions) {
        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Delete message: ${message.uid}` });

        try {
            let result = {};

            // Permanently delete if in Trash/Junk or forced
            if (['\\Trash', '\\Junk'].includes(this.listingEntry.specialUse) || force) {
                // delete
                result.deleted = await connectionClient.messageDelete(message.uid, { uid: true });
            } else {
                // Move to trash
                // Find Trash folder path
                let trashMailbox = await this.connection.getSpecialUseMailbox('\\Trash');
                if (!trashMailbox || normalizePath(trashMailbox.path) === normalizePath(this.path)) {
                    // No Trash found or already in trash - delete permanently
                    result.deleted = await connectionClient.messageDelete(message.uid, { uid: true });
                } else {
                    result.deleted = false;
                    // We have a destination, so can move message to there
                    let moved = await connectionClient.messageMove(message.uid, trashMailbox.path, { uid: true });
                    if (moved) {
                        result.moved = {
                            destination: moved.destination
                        };
                        if (moved && moved.uidMap && moved.uidMap.has(message.uid)) {
                            result.moved.message = await this.connection.packUid(trashMailbox.path, moved.uidMap.get(message.uid));
                        }
                    }
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Deletes multiple messages or moves them to trash
     * @param {Object} search - Search criteria
     * @param {Boolean} force - Force permanent deletion
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Result of deletion
     */
    async deleteMessages(search, force, connectionOptions) {
        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `Delete messages` });

        try {
            let result = {};

            // Permanently delete if in Trash/Junk or forced
            if (['\\Trash', '\\Junk'].includes(this.listingEntry.specialUse) || force) {
                // delete
                result.deleted = await connectionClient.messageDelete(search, { uid: true });
            } else {
                // Move to trash
                // Find Trash folder path
                let trashMailbox = await this.connection.getSpecialUseMailbox('\\Trash');
                if (!trashMailbox || normalizePath(trashMailbox.path) === normalizePath(this.path)) {
                    // No Trash found or already in trash - delete permanently
                    result.deleted = await connectionClient.messageDelete(search, { uid: true });
                } else {
                    result.deleted = false;
                    // We have a destination, so can move messages to there
                    let moved = await connectionClient.messageMove(search, trashMailbox.path, { uid: true });
                    if (moved) {
                        result.moved = {
                            destination: moved.destination
                        };
                        if (moved && moved.uidMap && moved.uidMap.size) {
                            let moveMap = [];
                            for (let [suid, tuid] of moved.uidMap) {
                                moveMap.push([await this.connection.packUid(this.path, suid), await this.connection.packUid(trashMailbox.path, tuid)]);
                            }
                            result.moved.idMap = moveMap;
                        }
                    }
                }
            }

            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Lists messages in the mailbox with pagination
     * @param {Object} options - List options
     * @param {Number} options.page - Page number (0-based)
     * @param {String} options.cursor - Cursor string for pagination
     * @param {Number} options.pageSize - Messages per page
     * @param {Object} options.search - Search criteria
     * @param {Object} connectionOptions - Connection options
     * @returns {Object} Paginated message list
     */
    async listMessages(options, connectionOptions) {
        options = options || {};

        let page = Number(options.page) || 0;

        // Handle cursor-based pagination
        if (options.cursor) {
            let cursorPage = this.decodeCursorStr(options.cursor);
            if (typeof cursorPage === 'number' && cursorPage >= 0) {
                page = cursorPage;
            }
        }

        let pageSize = Math.abs(Number(options.pageSize) || 20);

        const connectionClient = await this.connection.getImapConnection(connectionOptions);

        let lock = await this.getMailboxLock(connectionClient, { description: `List messages from: ${this.path}` });

        try {
            let mailboxStatus = this.getMailboxStatus(connectionClient);

            let messageCount = mailboxStatus.messages;
            let uidList;
            let opts = {};

            // Apply search filter if provided
            if (options.search) {
                uidList = await connectionClient.search(options.search, { uid: true });
                uidList = !uidList ? [] : uidList.sort((a, b) => b - a); // newer first
                messageCount = uidList.length;
            }

            // Calculate pagination
            let pages = Math.ceil(messageCount / pageSize) || 1;

            if (page < 0) {
                page = 0;
            }

            let messages = [];
            let seqMax, seqMin, range;

            // Generate pagination cursors
            let nextPageCursor = page < pages - 1 ? this.encodeCursorString(page + 1) : null;
            let prevPageCursor = page > 0 ? this.encodeCursorString(Math.min(page - 1, pages - 1)) : null;

            // Return empty result if no messages or page out of bounds
            if (!messageCount || page >= pages) {
                return {
                    total: messageCount,
                    page,
                    pages,
                    nextPageCursor,
                    prevPageCursor,
                    messages
                };
            }

            // Calculate range to fetch
            if (options.search && uidList) {
                // For search results, use specific UIDs
                let start = page * pageSize;
                let uidRange = uidList.slice(start, start + pageSize).reverse();
                range = uidRange.join(',');
                opts.uid = true;
            } else {
                // For full listing, use sequence range
                seqMax = messageCount - page * pageSize;
                seqMin = seqMax - pageSize + 1;

                if (seqMax >= messageCount) {
                    seqMax = '*';
                }

                if (seqMin < 1) {
                    seqMin = 1;
                }

                range = seqMin === seqMax ? `${seqMin}` : `${seqMin}:${seqMax}`;
            }

            // Configure fields to fetch
            let fields = {
                uid: true,
                flags: true,
                size: true,
                bodyStructure: true,
                envelope: true,
                internalDate: true,
                emailId: true,
                threadId: true,
                labels: true
            };

            // LarkSuite specific handling - ensure address headers are fetched
            if (this.isLarkSuite) {
                if (!fields.headers && fields.headers !== true) {
                    fields.headers = [];
                }
                if (Array.isArray(fields.headers)) {
                    // ensure that the response includes header fields because Lark Mail ENVELOPE response is unreliable
                    for (let key of ['from', 'to', 'cc']) {
                        if (!fields.headers.includes(key)) {
                            fields.headers.push(key);
                        }
                    }
                }
            }

            // Fetch messages in the range
            for await (let messageData of connectionClient.fetch(range, fields, opts)) {
                if (!messageData || !messageData.uid) {
                    //TODO: support partial responses
                    this.logger.debug({ msg: 'Partial FETCH response', code: 'partial_fetch', query: { range, fields, opts } });
                    continue;
                }
                let messageInfo;
                try {
                    messageInfo = await this.getMessageInfo(messageData);
                } catch (err) {
                    // Return error info for failed messages
                    messageInfo = {
                        uid: messageData.uid,
                        status: 'failed',
                        error: `Failed to process message entry ${err.message}`
                    };
                }

                messages.push(messageInfo);
            }

            return {
                total: messageCount,
                page,
                pages,
                nextPageCursor,
                prevPageCursor,
                // List newer entries first. Servers like yahoo do not return ordered list, so we need to order manually
                messages: messages.sort((a, b) => b.uid - a.uid)
            };
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    /**
     * Updates the last sync timestamp in Redis
     */
    async markUpdated() {
        try {
            await this.connection.redis.hSetExists(this.connection.getAccountKey(), 'sync', new Date().toISOString());
        } catch (err) {
            this.logger.error({ msg: 'Redis error', err });
        }
    }

    /**
     * Heuristic check if message might be a bounce
     * @param {Object} messageInfo - Message information
     * @returns {Boolean} True if likely a bounce
     */
    mightBeABounce(messageInfo) {
        // Only check messages in Inbox or Junk
        if (
            !['\\Inbox', '\\Junk'].includes(this.listingEntry.specialUse) &&
            !(messageInfo.labels?.includes('\\Inbox') || messageInfo.labels?.includes('\\Junk'))
        ) {
            return false;
        }

        // Skip if already identified as delivery report
        if (messageInfo.deliveryReport) {
            // already processed
            return false;
        }

        let name = (messageInfo.from && messageInfo.from.name) || '';
        let address = (messageInfo.from && messageInfo.from.address) || '';

        // Check common bounce sender names
        if (/Mail Delivery System|Mail Delivery Subsystem|Internet Mail Delivery/i.test(name)) {
            return true;
        }

        // Check common bounce sender addresses
        if (/mailer-daemon@|postmaster@/i.test(address)) {
            return true;
        }

        // Check for delivery-status attachment + subject pattern
        let hasDeliveryStatus = false;
        for (let attachment of messageInfo.attachments || []) {
            if (attachment.contentType === 'message/delivery-status') {
                hasDeliveryStatus = true;
            }
        }

        if (hasDeliveryStatus && /Undeliver(able|ed)/i.test(messageInfo.subject)) {
            return true;
        }

        return false;
    }

    /**
     * Heuristic check if message might be an ARF complaint
     * @param {Object} messageInfo - Message information
     * @returns {Boolean} True if likely a complaint
     */
    mightBeAComplaint(messageInfo) {
        // Only check inbox messages
        if (this.path !== 'INBOX' && !(this.isAllMail && messageInfo.labels && messageInfo.labels.includes('\\Inbox'))) {
            return false;
        }

        let hasEmbeddedMessage = false;
        for (let attachment of messageInfo.attachments || []) {
            // Direct ARF indicator
            if (attachment.contentType === 'message/feedback-report') {
                return true;
            }

            // Check for embedded message (complaint might contain original)
            if (['message/rfc822', 'message/rfc822-headers'].includes(attachment.contentType)) {
                hasEmbeddedMessage = true;
            }
        }

        let fromAddress = (messageInfo.from && messageInfo.from.address) || '';

        // Hotmail-specific complaint pattern
        if (hasEmbeddedMessage && fromAddress === 'staff@hotmail.com' && /complaint/i.test(messageInfo.subject)) {
            return true;
        }

        return false;
    }

    /**
     * Heuristic check if message might be a DSN (Delivery Status Notification)
     * @param {Object} messageInfo - Message information
     * @returns {Boolean} True if likely a DSN
     */
    mightBeDSNResponse(messageInfo) {
        // Only check inbox messages
        if (this.path !== 'INBOX' && !(this.isAllMail && messageInfo.labels && messageInfo.labels.includes('\\Inbox'))) {
            return false;
        }

        // Check Content-Type header for multipart/report with delivery-status
        if (messageInfo.headers && messageInfo.headers['content-type'] && messageInfo.headers['content-type'].length) {
            let parsedContentType = libmime.parseHeaderValue(messageInfo.headers['content-type'].at(-1));
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
     * Decodes a cursor string for pagination
     * @param {String} cursorStr - Base64-encoded cursor string
     * @returns {Number|null} Page number or null if invalid
     */
    decodeCursorStr(cursorStr) {
        let type = 'imap';

        if (cursorStr) {
            // Extract cursor type prefix
            let splitPos = cursorStr.indexOf('_');
            if (splitPos >= 0) {
                let cursorType = cursorStr.substring(0, splitPos);
                cursorStr = cursorStr.substring(splitPos + 1);
                if (cursorType && type !== cursorType) {
                    let error = new Error('Invalid cursor');
                    error.code = 'InvalidCursorType';
                    throw error;
                }
            }

            try {
                // Decode cursor data
                let { page: cursorPage } = JSON.parse(Buffer.from(cursorStr, 'base64url'));
                if (typeof cursorPage === 'number' && cursorPage >= 0) {
                    return cursorPage;
                }
            } catch (err) {
                this.logger.error({ msg: 'Cursor parsing error', cursorStr, err });

                let error = new Error('Invalid paging cursor');
                error.code = 'InvalidCursorValue';
                error.statusCode = 400;
                throw error;
            }
        }

        return null;
    }

    /**
     * Encodes a page number into a cursor string
     * @param {Number} cursorPage - Page number to encode
     * @returns {String|null} Base64-encoded cursor string
     */
    encodeCursorString(cursorPage) {
        if (typeof cursorPage !== 'number' || cursorPage < 0) {
            return null;
        }
        cursorPage = cursorPage || 0;
        let type = 'imap';
        // Prefix with type for future extensibility
        return `${type}_${Buffer.from(JSON.stringify({ page: cursorPage })).toString('base64url')}`;
    }
}

module.exports.Mailbox = Mailbox;
