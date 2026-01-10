'use strict';

const crypto = require('crypto');
const { compareExisting, calculateFetchBackoff, readEnvValue } = require('../../tools');
const config = require('@zone-eu/wild-config');
const { DEFAULT_FETCH_BATCH_SIZE } = require('../../consts');

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
 * Determines if a full sync should be skipped based on timing
 * @param {Object} storedStatus - Stored mailbox status
 * @returns {Boolean} True if full sync was performed recently
 */
function isRecentFullSync(storedStatus) {
    return storedStatus.lastFullSync && storedStatus.lastFullSync >= new Date(Date.now() - FULL_SYNC_DELAY);
}

/**
 * Checks if UIDVALIDITY has changed (mailbox was recreated)
 * @param {Object} storedStatus - Stored mailbox status
 * @param {Object} mailboxStatus - Current mailbox status from IMAP
 * @returns {Boolean} True if UIDVALIDITY changed
 */
function hasUidValidityChanged(storedStatus, mailboxStatus) {
    return 'uidValidity' in storedStatus && mailboxStatus.uidValidity !== storedStatus.uidValidity;
}

/**
 * Checks if MODSEQ indicates no changes
 * @param {Object} storedStatus - Stored mailbox status
 * @param {Object} mailboxStatus - Current mailbox status from IMAP
 * @returns {Boolean} True if MODSEQ is unchanged
 */
function hasNoModseqChanges(storedStatus, mailboxStatus) {
    return storedStatus.highestModseq && storedStatus.highestModseq === mailboxStatus.highestModseq;
}

/**
 * Determines if partial sync can be used based on CONDSTORE support
 * @param {Object} imapClient - IMAP client with enabled extensions
 * @param {Object} storedStatus - Stored mailbox status
 * @param {Object} mailboxStatus - Current mailbox status from IMAP
 * @returns {Boolean} True if partial sync with CONDSTORE is appropriate
 */
function canUseCondstorePartialSync(imapClient, storedStatus, mailboxStatus) {
    return (
        imapClient.enabled.has('CONDSTORE') &&
        storedStatus.highestModseq < mailboxStatus.highestModseq &&
        storedStatus.messages <= mailboxStatus.messages &&
        mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
    );
}

/**
 * Determines if partial sync can be used based on message count
 * @param {Object} storedStatus - Stored mailbox status
 * @param {Object} mailboxStatus - Current mailbox status from IMAP
 * @returns {Boolean} True if only new messages were added
 */
function canUseSimplePartialSync(storedStatus, mailboxStatus) {
    return (
        storedStatus.messages < mailboxStatus.messages &&
        mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
    );
}

/**
 * Determines if sync can be skipped due to no changes
 * @param {Object} storedStatus - Stored mailbox status
 * @param {Object} mailboxStatus - Current mailbox status from IMAP
 * @returns {Boolean} True if no sync is needed
 */
function canSkipSync(storedStatus, mailboxStatus) {
    return (
        storedStatus.messages === mailboxStatus.messages &&
        storedStatus.uidNext === mailboxStatus.uidNext &&
        isRecentFullSync(storedStatus)
    );
}

/**
 * Handles the synchronization of IMAP mailboxes
 */
class SyncOperations {
    /**
     * Creates a new SyncOperations instance
     * @param {Object} mailbox - The parent Mailbox instance
     */
    constructor(mailbox) {
        this.mailbox = mailbox;
        this.connection = mailbox.connection;
        this.logger = mailbox.logger;
    }

    /**
     * Performs full synchronization based on indexer type
     * @returns {Promise} Resolves when sync is complete
     */
    async fullSync() {
        const imapIndexer = this.mailbox.imapIndexer;

        this.logger.trace({ msg: 'Running full sync', imapIndexer });

        if (imapIndexer === 'fast') {
            return this.runFastSync();
        }
        return this.runFullSync();
    }

    /**
     * Performs partial synchronization based on indexer type
     * @param {Object} storedStatus - Current stored mailbox status
     * @returns {Promise} Resolves when sync is complete
     */
    async partialSync(storedStatus) {
        const imapIndexer = this.mailbox.imapIndexer;

        this.logger.trace({ msg: 'Running partial sync', imapIndexer });

        if (imapIndexer === 'fast') {
            return this.runFastSync(storedStatus);
        }
        return this.runPartialSync(storedStatus);
    }

    /**
     * Determines the appropriate sync strategy based on mailbox state
     * @param {Object} storedStatus - Stored mailbox status
     * @param {Object} mailboxStatus - Current mailbox status from IMAP
     * @returns {Object} Sync decision with type and reason
     */
    determineSyncStrategy(storedStatus, mailboxStatus) {
        // No changes if MODSEQ hasn't changed
        if (hasNoModseqChanges(storedStatus, mailboxStatus)) {
            return { type: 'none', reason: 'modseq_unchanged' };
        }

        // No changes if mailbox is empty
        if (storedStatus.messages === 0 && mailboxStatus.messages === 0) {
            return { type: 'none', reason: 'empty_mailbox' };
        }

        // Partial sync if CONDSTORE indicates only new messages or flag changes
        if (canUseCondstorePartialSync(this.connection.imapClient, storedStatus, mailboxStatus)) {
            return { type: 'partial', reason: 'condstore_changes' };
        }

        // Partial sync if only new messages
        if (canUseSimplePartialSync(storedStatus, mailboxStatus)) {
            return { type: 'partial', reason: 'new_messages_only' };
        }

        // Skip if nothing changed and recent full sync
        if (canSkipSync(storedStatus, mailboxStatus)) {
            return { type: 'none', reason: 'recent_full_sync' };
        }

        // Full sync for all other cases
        return { type: 'full', reason: 'changes_detected' };
    }

    /**
     * Fast sync mode - only tracks new messages, doesn't maintain full message list
     * More efficient for large mailboxes where we only care about new messages
     * @param {Object} storedStatus - Current stored mailbox status
     */
    async runFastSync(storedStatus) {
        storedStatus = storedStatus || (await this.mailbox.getStoredStatus());
        let mailboxStatus = this.mailbox.getMailboxStatus();

        let lock = await this.mailbox.getMailboxLock(null, { description: 'Fast sync' });
        this.connection.syncing = true;
        this.mailbox.syncing = true;
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
                            let updated = await this.connection.redis.hUpdateBigger(this.mailbox.getMailboxKey(), 'uidNext', messageData.uid + 1, messageData.uid + 1);

                            if (updated) {
                                // new email! Queue for processing
                                await this.connection.redis.zadd(
                                    this.mailbox.getNotificationsKey(),
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
                                    path: this.mailbox.path,
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

            await this.mailbox.updateStoredStatus(this.mailbox.getMailboxStatus());

            await this.mailbox.publishSyncedEvents(storedStatus);
        } finally {
            lock.release();
            this.connection.syncing = false;
            this.mailbox.syncing = false;
        }
    }

    /**
     * Partial sync - fetches only changed messages using MODSEQ or UID range
     * Used for incremental updates when we know something changed
     * @param {Object} storedStatus - Current stored mailbox status
     */
    async runPartialSync(storedStatus) {
        storedStatus = storedStatus || (await this.mailbox.getStoredStatus());
        let mailboxStatus = this.mailbox.getMailboxStatus();

        let lock = await this.mailbox.getMailboxLock(null, { description: 'Partial sync' });
        this.connection.syncing = true;
        this.mailbox.syncing = true;
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

                            let storedMessage = await this.mailbox.entryListGet(messageData.uid, { uid: true });

                            let changes;
                            if (!storedMessage) {
                                // New message
                                let seq = await this.mailbox.entryListSet(messageData);
                                if (seq) {
                                    // Queue for processing
                                    await this.connection.redis.zadd(
                                        this.mailbox.getNotificationsKey(),
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
                                let seq = await this.mailbox.entryListSet(messageData);
                                if (seq) {
                                    await this.mailbox.processChanges(messageData, changes);
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
                                    path: this.mailbox.path,
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

            await this.mailbox.updateStoredStatus(this.mailbox.getMailboxStatus());

            await this.mailbox.publishSyncedEvents(storedStatus);
        } finally {
            lock.release();
            this.connection.syncing = false;
            this.mailbox.syncing = false;
        }
    }

    /**
     * Full sync - fetches all messages and detects additions, deletions, and changes
     * Most thorough but slowest sync method
     */
    async runFullSync() {
        let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };
        let opts = {};

        let lock = await this.mailbox.getMailboxLock(null, { description: 'Full sync' });
        this.connection.syncing = true;
        this.mailbox.syncing = true;
        try {
            // Generate unique ID for this sync loop to track batch ordering
            const loopId = crypto.randomUUID();

            // Wait for next tick to ensure ImapFlow has processed all untagged responses from SELECT
            await new Promise(resolve => setImmediate(resolve));

            let mailboxStatus = this.mailbox.getMailboxStatus();

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
            let storedMaxSeqOld = await this.connection.redis.zcard(this.mailbox.getMessagesKey());

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

                                let storedMessage = await this.mailbox.entryListGet(messageData.uid, { uid: true });
                                if (!storedMessage) {
                                    // New message
                                    let seq = await this.mailbox.entryListSet(messageData);
                                    if (seq) {
                                        await this.connection.redis.zadd(
                                            this.mailbox.getNotificationsKey(),
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
                                        let deletedEntry = await this.mailbox.entryListExpunge(seq);
                                        if (deletedEntry) {
                                            await this.mailbox.processDeleted(deletedEntry);
                                        }
                                    }

                                    // Check for changes
                                    if ((changes = compareExisting(storedMessage.entry, messageData))) {
                                        let seq = await this.mailbox.entryListSet(messageData);
                                        if (seq) {
                                            await this.mailbox.processChanges(messageData, changes);
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
                                        path: this.mailbox.path,
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
                            if (!currentMailbox || currentMailbox.path !== this.mailbox.path) {
                                this.logger.error({
                                    msg: 'Mailbox changed during retry delay, aborting sync',
                                    expectedPath: this.mailbox.path,
                                    currentPath: currentMailbox ? currentMailbox.path : 'none',
                                    loopId
                                });
                                throw new Error('Mailbox changed during sync operation');
                            }

                            // Refresh mailbox status in case it changed
                            const oldMailboxMessages = mailboxStatus.messages;
                            mailboxStatus = this.mailbox.getMailboxStatus();

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
            let storedMaxSeq = await this.connection.redis.zcard(this.mailbox.getMessagesKey());
            let diff = storedMaxSeq - seqMax;
            if (diff) {
                this.logger.trace({
                    msg: 'Deleted range',
                    inloop: false,
                    diff,
                    start: seqMax + 1,
                    messagesKey: this.mailbox.getMessagesKey(),
                    zcard: storedMaxSeq,
                    zcardOld: storedMaxSeqOld,
                    responseCounters
                });
            }

            // Process remaining deletions
            for (let i = diff - 1; i >= 0; i--) {
                let seq = seqMax + i + 1;
                let deletedEntry = await this.mailbox.entryListExpunge(seq);
                if (deletedEntry) {
                    await this.mailbox.processDeleted(deletedEntry);
                }
            }

            // Update status with full sync timestamp
            let status = this.mailbox.getMailboxStatus();
            status.lastFullSync = new Date();

            await this.mailbox.updateStoredStatus(status);
            let storedStatus = await this.mailbox.getStoredStatus();

            await this.mailbox.publishSyncedEvents(storedStatus);
        } finally {
            this.connection.syncing = false;
            this.mailbox.syncing = false;
            lock.release();
        }
    }
}

module.exports = {
    SyncOperations,
    getFetchRange,
    isRecentFullSync,
    hasUidValidityChanged,
    hasNoModseqChanges,
    canUseCondstorePartialSync,
    canUseSimplePartialSync,
    canSkipSync,
    FETCH_BATCH_SIZE,
    FULL_SYNC_DELAY
};
