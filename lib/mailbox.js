'use strict';

const crypto = require('crypto');
const { serialize, unserialize, compareExisting, normalizePath, download, filterEmptyObjectValues, validUidValidity } = require('./tools');
const msgpack = require('msgpack5')();
const he = require('he');
const libmime = require('libmime');
const settings = require('./settings');
const { bounceDetect } = require('./bounce-detect');
const { arfDetect } = require('./arf-detect');
const appendList = require('./append-list');
const { mimeHtml } = require('@postalsys/email-text-tools');
const simpleParser = require('mailparser').simpleParser;
const ical = require('ical.js');
const { llmPreProcess } = require('../lib/llm-pre-process');

const { getESClient } = require('./document-store');

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
    MAX_ALLOWED_DOWNLOAD_SIZE
} = require('./consts');

// Do not check for flag updates using full sync more often than this value
const FULL_SYNC_DELAY = 30 * 60 * 1000;

class Mailbox {
    constructor(connection, entry) {
        this.status = false;
        this.connection = connection;
        this.path = entry.path;
        this.listingEntry = entry;
        this.syncDisabled = entry.syncDisabled;

        this.logger = this.connection.mainLogger.child({
            sub: 'mailbox',
            path: this.path
        });

        this.isGmail = connection.isGmail;
        this.isAllMail = this.isGmail && this.listingEntry.specialUse === '\\All';

        this.selected = false;

        this.redisKey = BigInt('0x' + crypto.createHash('sha1').update(normalizePath(this.path)).digest('hex')).toString(36);

        this.runPartialSyncTimer = false;

        this.synced = false;
    }

    getMailboxStatus(connectionClient) {
        connectionClient = connectionClient || this.connection.imapClient;
        if (!connectionClient) {
            throw new Error('IMAP connection not available');
        }

        let mailboxInfo = connectionClient.mailbox;

        let status = {
            path: this.path
        };

        status.highestModseq = mailboxInfo.highestModseq ? mailboxInfo.highestModseq : false;
        status.uidValidity = validUidValidity(mailboxInfo.uidValidity) ? mailboxInfo.uidValidity : false;
        status.uidNext = mailboxInfo.uidNext ? mailboxInfo.uidNext : false;
        status.messages = mailboxInfo.exists ? mailboxInfo.exists : 0;

        return status;
    }

    /**
     * Loads last known mailbox state from Redis
     * @returns {Object} mailbox state
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
            noInferiors: !!data.noInferiors,
            lastFullSync: data.lastFullSync ? new Date(data.lastFullSync) : false
        };
    }

    /**
     * Updates known mailbox state in Redis
     * @param {Object} data
     */
    async updateStoredStatus(data) {
        if (!data || typeof data !== 'object') {
            return false;
        }

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

        await this.connection.redis.hmset(this.getMailboxKey(), Object.fromEntries(list));
    }

    /**
     * Sets message entry object. Entries are ordered by `uid` property
     * @param {Object} data
     * @param {Number} Sequence number for the added entry
     */
    async entryListSet(data) {
        if (isNaN(data.uid)) {
            return null;
        }

        return await this.connection.redis.zSet(this.getMessagesKey(), Number(data.uid), serialize(data));
    }

    /**
     * Retrieves message entry object for the provided sequence value
     * @param {Number} seq Sequence number
     * @returns {Object|null} Message entry object
     */
    async entryListGet(seq, options) {
        let range = Number(seq);
        options = options || {};
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
     * @param {Number} seq Sequence number
     * @param {Number} [uid] UID number if seq is not set
     * @returns {Object|null} Message entry object that was deleted
     */
    async entryListExpunge(seq, uid) {
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

    isSelected() {
        return (
            this.selected &&
            this.connection.imapClient &&
            this.connection.imapClient.mailbox &&
            normalizePath(this.connection.imapClient.mailbox.path) === normalizePath(this.path)
        );
    }

    getMessagesKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:l:${this.redisKey}`;
    }

    getMailboxKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:h:${this.redisKey}`;
    }

    getBounceKey() {
        return `${REDIS_PREFIX}iar:b:${this.connection.account}`;
    }

    getSeenMessagesKey() {
        return `${REDIS_PREFIX}iar:s:${this.connection.account}`;
    }

    getNotificationsKey() {
        return `${REDIS_PREFIX}iam:${this.connection.account}:n:${this.redisKey}`;
    }

    startIdle() {
        if (!this.isSelected() || !this.connection.imapClient || this.connection.imapClient.idling) {
            return;
        }
        this.connection.imapClient.idle().catch(err => {
            this.logger.error({ msg: 'IDLE error', err });
        });
    }

    // clear mailbox records
    async clear(opts) {
        opts = opts || {};

        clearTimeout(this.runPartialSyncTimer);

        await this.connection.redis.del(this.getMailboxKey());
        await this.connection.redis.del(this.getMessagesKey());
        await this.connection.redis.del(this.getNotificationsKey());

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

    async sync(forceEmpty) {
        if (this.selected || !this.connection.imapClient) {
            // expect current folder to be already synced
            return false;
        }

        let status;
        try {
            status = await this.connection.imapClient.status(this.path, {
                uidNext: true,
                messages: true,
                highestModseq: true,
                uidValidity: true
            });
        } catch (err) {
            if (err.code === 'NotFound') {
                // folder is missing
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
            // only update counters
            await this.updateStoredStatus(status);
            return true;
        }

        let hasQueuedNotifications = await this.connection.redis.exists(this.getNotificationsKey());
        // if we have unprocessed notifications, then do not skip this folder
        if (!hasQueuedNotifications && !forceEmpty) {
            let storedStatus = await this.getStoredStatus();
            if (status.uidValidity === storedStatus.uidValidity) {
                if (
                    status.uidNext === storedStatus.uidNext &&
                    status.messages === storedStatus.messages &&
                    storedStatus.lastFullSync > new Date(Date.now() - FULL_SYNC_DELAY)
                ) {
                    // no reason to sync
                    return true;
                }

                if ((!status.messages && !storedStatus.messages) || (status.highestModseq && status.highestModseq === storedStatus.highestModseq)) {
                    // no reason to sync
                    return true;
                }
            }
        }

        let syncedPromise = new Promise((resolve, reject) => {
            this.synced = resolve;
            this.select(true).catch(err => reject(err));
        });

        await syncedPromise;
    }

    async select(skipIdle) {
        let lock = await this.getMailboxLock();
        // have to release the lock immediatelly, otherwise difficult to process 'exists' / 'expunge' events
        lock.release();

        if (!skipIdle) {
            // do not wait until command finishes before proceeding
            this.startIdle();
        }
    }

    async getMailboxLock(connectionClient) {
        connectionClient = connectionClient || this.connection.imapClient;

        if (!connectionClient) {
            throw new Error('IMAP connection not available');
        }

        let lock = await connectionClient.getMailboxLock(this.path, {});

        if (connectionClient === this.connection.imapClient) {
            clearTimeout(this.connection.completedTimer);
        }

        return lock;
    }

    onTaskCompleted(connectionClient) {
        connectionClient = connectionClient || this.connection.imapClient;
        if (connectionClient === this.connection.imapClient) {
            this.connection.onTaskCompleted();
        }
    }

    logEvent(msg, event) {
        const logObj = Object.assign({ msg }, event);
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

    async onExists(event) {
        this.logEvent('Untagged EXISTS', event);

        clearTimeout(this.runPartialSyncTimer);
        this.runPartialSyncTimer = setTimeout(() => {
            this.shouldRunPartialSyncAfterExists()
                .then(shouldRun => {
                    if (shouldRun) {
                        this.logger.trace({ msg: 'Running partial sync' });
                        return this.partialSync();
                    }
                    return false;
                })
                .then(() => this.select())
                .catch(err => this.logger.error({ msg: 'Sync error', err }));
        }, 1000);
    }

    async onExpunge(event) {
        this.logEvent('Untagged EXPUNGE', event);

        let deletedEntry;

        if (event.seq) {
            // * 123 EXPUNGE
            deletedEntry = await this.entryListExpunge(event.seq);
        } else if (event.uid) {
            // * VANISHED 123
            deletedEntry = await this.entryListExpunge(false, event.uid);
        }

        if (deletedEntry) {
            await this.processDeleted(deletedEntry);
            await this.markUpdated();
        }
    }

    async onFlags(event) {
        this.logEvent('Untagged FETCH', event);

        let storedMessage = await this.entryListGet(event.uid || event.seq, { uid: !!event.uid });
        let changes;

        // ignore Recent flag
        event.flags.delete('\\Recent');

        if (!storedMessage) {
            // New! There should not be new messages.
            // What should we do? Currently triggering partial sync.
            return await this.onExists();
        } else if ((changes = compareExisting(storedMessage.entry, event, ['flags']))) {
            let messageData = storedMessage.entry;
            messageData.flags = event.flags;
            let seq = await this.entryListSet(messageData);

            if (seq) {
                await this.processChanges(storedMessage, changes);
            }
        }
    }

    async shouldRunPartialSyncAfterExists() {
        let storedStatus = await this.getStoredStatus();
        let mailboxStatus = this.getMailboxStatus();
        return mailboxStatus.messages !== storedStatus.messages;
    }

    async partialSync(storedStatus) {
        storedStatus = storedStatus || (await this.getStoredStatus());
        let mailboxStatus = this.getMailboxStatus();

        let lock = await this.getMailboxLock();
        this.connection.syncing = true;
        try {
            if (!this.connection.imapClient) {
                throw new Error('IMAP connection not available');
            }

            let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };
            let range = '1:*';
            let opts = {
                uid: true
            };

            if (this.connection.imapClient.enabled.has('CONDSTORE') && storedStatus.highestModseq) {
                opts.changedSince = storedStatus.highestModseq;
            } else if (storedStatus.uidNext) {
                range = `${storedStatus.uidNext}:*`;
            }

            if (mailboxStatus.messages) {
                // only fetch messages if there is some
                for await (let messageData of this.connection.imapClient.fetch(range, fields, opts)) {
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
                        // new!
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
                    } else if ((changes = compareExisting(storedMessage.entry, messageData))) {
                        let seq = await this.entryListSet(messageData);
                        if (seq) {
                            await this.processChanges(messageData, changes);
                        }
                    }
                }
            }

            await this.updateStoredStatus(this.getMailboxStatus());

            let messageFetchOptions = {};

            let documentStoreEnabled = await settings.get('documentStoreEnabled');

            let notifyText = await settings.get('notifyText');
            if (documentStoreEnabled || notifyText) {
                messageFetchOptions.textType = '*';
                let notifyTextSize = await settings.get('notifyTextSize');

                if (documentStoreEnabled && notifyTextSize) {
                    notifyTextSize = Math.max(notifyTextSize, 1024 * 1024);
                }

                if (notifyTextSize) {
                    messageFetchOptions.maxBytes = notifyTextSize;
                }
            }

            let notifyHeaders = (await settings.get('notifyHeaders')) || [];
            if (documentStoreEnabled || notifyHeaders.length) {
                messageFetchOptions.headers = notifyHeaders.includes('*') || documentStoreEnabled ? true : notifyHeaders.length ? notifyHeaders : false;
            }

            // also request autoresponse headers
            if (messageFetchOptions.headers !== true) {
                let fetchHeaders = new Set(messageFetchOptions.headers || []);

                fetchHeaders.add('x-autoreply');
                fetchHeaders.add('x-autorespond');
                fetchHeaders.add('auto-submitted');
                fetchHeaders.add('precedence');

                fetchHeaders.add('in-reply-to');
                fetchHeaders.add('references');

                fetchHeaders.add('content-type');

                messageFetchOptions.fetchHeaders = Array.from(fetchHeaders);
            }

            // can't process messages before fetch() has finished

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

                let canSync = documentStoreEnabled && (!this.connection.syncFrom || messageData.internalDate >= this.connection.syncFrom);

                if (this.connection.notifyFrom && messageData.internalDate < this.connection.notifyFrom && !canSync) {
                    // skip too old messages
                    continue;
                }

                await this.processNew(messageData, messageFetchOptions, canSync);
            }

            if (hadUpdates) {
                await this.markUpdated();
            }
        } finally {
            lock.release();
            this.connection.syncing = false;
        }
    }

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

        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, MESSAGE_DELETED_NOTIFY, {
            id: packedUid,
            uid: messageData.uid
        });

        try {
            // no point in notifying about a new message if the entry ws already deleted
            await this.connection.redis.zremrangebyscore(this.getNotificationsKey(), messageData.uid, messageData.uid);
        } catch (err) {
            this.logger.error({ msg: 'Failed removing deleted message from notifications set', uid: messageData.uid, err });
        }
    }

    async processNew(messageData, options, canSync) {
        this.logger.debug({ msg: 'New message', uid: messageData.uid, flags: Array.from(messageData.flags) });

        options.skipLock = true;

        let requestedHeaders = options.headers;
        if (options.fetchHeaders) {
            options.headers = options.fetchHeaders;
        } else {
            options.headers = 'headers' in options ? options.headers : false;
        }

        let messageInfo;

        let missingDelay = 0;
        let missingRetries = 0;
        let maxRetries = 3;

        while (!messageInfo) {
            messageInfo = await this.getMessage(messageData, options);
            if (!messageInfo) {
                // NB! could be a replication lag with specific servers, so retry a few times
                if (missingRetries < maxRetries) {
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
            messageInfo.missingDelay = missingDelay;
            messageInfo.missingRetries = missingRetries;

            this.logger.debug({ msg: 'Missing message', status: 'found', uid: messageData.uid, missingRetries, missingDelay });
        }

        // we might have fetched more headers than was asked for, so filter out all the unneeded ones
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

        let date = new Date(messageInfo.date);
        if (this.connection.notifyFrom && date < this.connection.notifyFrom && !canSync) {
            // skip too old messages
            return;
        }

        let bounceNotifyInfo;
        let complaintNotifyInfo;
        let content;

        if (this.mightBeAComplaint(messageInfo)) {
            try {
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

                const report = await arfDetect(messageInfo);

                if (report && report.arf && report.arf['original-rcpt-to'] && report.arf['original-rcpt-to'].length) {
                    // can send report
                    let complaint = {};
                    for (let subKey of ['arf', 'headers']) {
                        for (let key of Object.keys(report[subKey])) {
                            if (!complaint[subKey]) {
                                complaint[subKey] = {};
                            }
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

        if (this.mightBeDSNResponse(messageInfo)) {
            try {
                let { content: sourceStream } = await this.connection.imapClient.download(messageInfo.uid, false, {
                    uid: true,
                    // future feature
                    chunkSize: options.chunkSize,
                    maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                });

                let parsed = await simpleParser(sourceStream, { keepDeliveryStatus: true });
                if (parsed) {
                    content = { parsed };

                    let deliveryStatus = parsed.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
                    if (deliveryStatus) {
                        let deliveryEntries = libmime.decodeHeaders((deliveryStatus.content || '').toString().trim());
                        let structured = {};
                        for (let key of Object.keys(deliveryEntries)) {
                            if (!key) {
                                continue;
                            }
                            let displayKey = key.replace(/-(.)/g, (m, c) => c.toUpperCase());
                            let value = deliveryEntries[key].at(-1);
                            if (typeof value === 'string') {
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

        // Check if this could be a bounce
        if (this.mightBeABounce(messageInfo)) {
            // parse for bounce
            try {
                if (!content) {
                    let result = await this.connection.imapClient.download(messageInfo.uid, false, {
                        uid: true,
                        // future feature
                        chunkSize: options.chunkSize,
                        maxBytes: MAX_ALLOWED_DOWNLOAD_SIZE
                    });
                    content = result.content;
                }

                if (content) {
                    let bounce = await bounceDetect(content);

                    let stored = 0;
                    if (bounce.action && bounce.recipient && bounce.messageId) {
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

                        // Store bounce info
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

        // resolve inbox tab if needed
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

        if (messageInfo.attachments && messageInfo.attachments.length && messageInfo.text && messageInfo.text.html) {
            // fetch inline attachments
            for (let attachment of messageInfo.attachments) {
                if (attachment.encodedSize && attachment.encodedSize > MAX_INLINE_ATTACHMENT_SIZE) {
                    // skip large attachments
                    continue;
                }

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

            for (let attachment of [...messageInfo.attachments].sort(sortCalendarAttachments)) {
                if (['text/calendar', 'application/ics'].includes(attachment.contentType)) {
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
                            const jcalData = ical.parse(contentBuf.toString());

                            const comp = new ical.Component(jcalData);
                            if (!comp) {
                                continue;
                            }

                            const vevent = comp.getFirstSubcomponent('vevent');
                            if (!vevent) {
                                continue;
                            }

                            let eventMethodProp = comp.getFirstProperty('method');
                            let eventMethodValue = eventMethodProp ? eventMethodProp.getFirstValue() : null;

                            const event = new ical.Event(vevent);

                            if (!event || !event.uid) {
                                continue;
                            }

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

                            let timezone;
                            const vtz = comp.getFirstSubcomponent('vtimezone');
                            if (vtz) {
                                const tz = new ical.Timezone(vtz);
                                timezone = tz && tz.tzid;
                            }

                            let startDate = event.startDate && event.startDate.toJSDate();
                            let endDate = event.endDate && event.endDate.toJSDate();

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

        // check if we have seen this message before or not (approximate estimation, not 100% exact)
        messageInfo.seemsLikeNew =
            this.listingEntry.specialUse !== '\\Sent' &&
            !(messageInfo.labels && messageInfo.labels.includes('\\Sent')) &&
            !!(await this.connection.redis.pfadd(this.getSeenMessagesKey(), messageInfo.emailId || messageInfo.messageId));

        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (this.listingEntry.specialUse === specialUseTag || (messageInfo.labels && messageInfo.labels.includes(specialUseTag))) {
                messageInfo.messageSpecialUse = specialUseTag;
                break;
            }
        }

        if (messageInfo.messageSpecialUse === '\\Inbox' && (!this.connection.notifyFrom || messageData.internalDate >= this.connection.notifyFrom)) {
            let messageData = Object.assign({ account: this.connection.account }, messageInfo);

            let canUseLLM = await llmPreProcess.run(messageData);

            if (canUseLLM && (messageInfo.text.plain || messageInfo.text.html)) {
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
                                time: Date.now()
                            })
                        );
                        this.logger.error({ msg: 'Failed to fetch summary from OpenAI', err });
                    }
                }

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

            if (messageInfo.text.html && messageInfo.attachments) {
                let attachmentList = new Map();
                let partList = [];

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
                        // download missing attachments
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

            messageInfo.text._generatedHtml = mimeHtml({
                html: messageInfo.text.html,
                text: messageInfo.text.plain
            });
            messageInfo.text.webSafe = true;
        }

        await this.connection.notify(this, MESSAGE_NEW_NOTIFY, messageInfo, {
            skipWebhook: this.connection.notifyFrom && date < this.connection.notifyFrom,
            canSync
        });

        if (bounceNotifyInfo) {
            let { index, client } = await getESClient(this.logger);
            if (client) {
                // find the originating message this bounce applies for
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

        if (complaintNotifyInfo) {
            // send complaint notification _after_ complaint email notification
            await this.connection.notify(false, EMAIL_COMPLAINT_NOTIFY, complaintNotifyInfo, {
                skipWebhook: this.connection.notifyFrom && date < this.connection.notifyFrom
            });
        }
    }

    async getMessageInfo(messageData, extended) {
        if (!messageData) {
            return false;
        }

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

        let { attachments, textId, encodedTextSize } = this.getAttachmentList(packedUid, messageData.bodyStructure);

        let envelope = messageData.envelope || {};

        let date =
            envelope.date && typeof envelope.date.toISOString === 'function' && envelope.date.toString() !== 'Invalid Date'
                ? envelope.date
                : messageData.internalDate;

        let isDraft = false;
        if (messageData.flags && messageData.flags.has('\\Draft')) {
            isDraft = true;
        }

        // do not expose the \Recent flag as it is session specific
        if (messageData.flags && messageData.flags.has('\\Recent')) {
            messageData.flags.delete('\\Recent');
        }

        if (messageData.labels && messageData.labels.has('\\Draft')) {
            isDraft = true;
        }

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
            from: envelope.from && envelope.from[0] ? envelope.from[0] : undefined,

            replyTo: envelope.replyTo && envelope.replyTo.length ? envelope.replyTo : undefined,
            sender: extended && envelope.sender && envelope.sender[0] ? envelope.sender[0] : undefined,

            to: envelope.to && envelope.to.length ? envelope.to : undefined,
            cc: envelope.cc && envelope.cc.length ? envelope.cc : undefined,

            bcc: extended && envelope.bcc && envelope.bcc.length ? envelope.bcc : undefined,

            attachments: attachments && attachments.length ? attachments : undefined,
            messageId: (envelope.messageId && envelope.messageId.toString().trim()) || undefined,
            inReplyTo: envelope.inReplyTo || undefined,

            headers: (extended && messageData.headers && libmime.decodeHeaders(messageData.headers.toString().trim())) || undefined,
            text: textId
                ? {
                      id: textId,
                      encodedSize: encodedTextSize
                  }
                : undefined
        };

        Object.keys(result).forEach(key => {
            if (typeof result[key] === 'undefined') {
                delete result[key];
            }
        });

        if (result.headers && this.isAutoreply(result)) {
            result.isAutoReply = true;
        }

        // is there a related bounce as well?
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

    getAttachmentList(packedUid, bodyStructure) {
        let attachments = [];
        let textParts = [[], [], []];
        if (!bodyStructure) {
            return attachments;
        }

        let idBuf = Buffer.from(packedUid, 'base64url');

        let encodedTextSize = {};

        let walk = (node, isRelated) => {
            if (node.type === 'multipart/related') {
                isRelated = true;
            }

            if (!/^multipart\//.test(node.type)) {
                if (node.disposition === 'attachment' || !/^text\/(plain|html)/.test(node.type)) {
                    let attachment = {
                        // append body part nr to message id
                        id: Buffer.concat([idBuf, Buffer.from(node.part || '1')]).toString('base64url'),
                        contentType: node.type,
                        encodedSize: node.size,

                        embedded: isRelated,
                        inline: node.disposition === 'inline' || (!node.disposition && isRelated)
                    };

                    let filename = (node.dispositionParameters && node.dispositionParameters.filename) || (node.parameters && node.parameters.name) || false;
                    if (filename) {
                        attachment.filename = filename;
                    }

                    if (node.id) {
                        attachment.contentId = node.id;
                    }

                    if (node.parameters && node.parameters.method && typeof node.parameters.method === 'string') {
                        attachment.method = node.parameters.method;
                    }

                    attachments.push(attachment);
                } else if ((!node.disposition || node.disposition === 'inline') && /^text\/(plain|html)/.test(node.type)) {
                    let type = node.type.substr(5);
                    if (!encodedTextSize[type]) {
                        encodedTextSize[type] = 0;
                    }
                    encodedTextSize[type] += node.size;
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

            if (node.childNodes) {
                node.childNodes.forEach(childNode => walk(childNode, isRelated));
            }
        };

        walk(bodyStructure, false);

        return {
            attachments,
            textId: Buffer.concat([idBuf, msgpack.encode(textParts)]).toString('base64url'),
            encodedTextSize
        };
    }

    async processChanges(messageData, changes) {
        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, MESSAGE_UPDATED_NOTIFY, {
            id: packedUid,
            uid: messageData.uid,
            changes
        });
        await this.markUpdated();
    }

    async fullSync() {
        let range = '1:*';
        let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true, internalDate: true };
        let opts = {};

        let lock = await this.getMailboxLock();
        this.connection.syncing = true;
        try {
            let mailboxStatus = this.getMailboxStatus();

            // full sync
            let seqMax = 0;
            let changes;

            let storedMaxSeqOld = await this.connection.redis.zcard(this.getMessagesKey());

            let responseCounters = {
                empty: 0,
                partial: 0,
                messages: 0
            };

            if (mailboxStatus.messages) {
                // only fetch messages if there is some

                for await (let messageData of this.connection.imapClient.fetch(range, fields, opts)) {
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
                        // new!
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
                        let diff = storedMessage.seq - messageData.seq;
                        if (diff) {
                            this.logger.trace({ msg: 'Deleted range', inloop: true, diff, start: messageData.seq });
                        }
                        for (let i = diff - 1; i >= 0; i--) {
                            let seq = messageData.seq + i;
                            let deletedEntry = await this.entryListExpunge(seq);
                            if (deletedEntry) {
                                await this.processDeleted(deletedEntry);
                            }
                        }

                        if ((changes = compareExisting(storedMessage.entry, messageData))) {
                            let seq = await this.entryListSet(messageData);
                            if (seq) {
                                await this.processChanges(messageData, changes);
                            }
                        }
                    }
                }
            }

            // delete unlisted messages
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

            for (let i = diff - 1; i >= 0; i--) {
                let seq = seqMax + i + 1;
                let deletedEntry = await this.entryListExpunge(seq);
                if (deletedEntry) {
                    await this.processDeleted(deletedEntry);
                }
            }

            let status = this.getMailboxStatus();
            status.lastFullSync = new Date();
            await this.updateStoredStatus(status);

            let messageFetchOptions = {};

            let documentStoreEnabled = await settings.get('documentStoreEnabled');

            let notifyText = await settings.get('notifyText');
            if (documentStoreEnabled || notifyText) {
                messageFetchOptions.textType = '*';
                let notifyTextSize = await settings.get('notifyTextSize');

                if (documentStoreEnabled && notifyTextSize) {
                    notifyTextSize = Math.max(notifyTextSize, 1024 * 1024);
                }

                if (notifyTextSize) {
                    messageFetchOptions.maxBytes = notifyTextSize;
                }
            }

            let notifyHeaders = (await settings.get('notifyHeaders')) || [];
            if (documentStoreEnabled || notifyHeaders.length) {
                messageFetchOptions.headers = notifyHeaders.includes('*') || documentStoreEnabled ? true : notifyHeaders.length ? notifyHeaders : false;
            }

            // also request autoresponse headers
            if (messageFetchOptions.headers !== true) {
                let fetchHeaders = new Set(messageFetchOptions.headers || []);

                fetchHeaders.add('x-autoreply');
                fetchHeaders.add('x-autorespond');
                fetchHeaders.add('auto-submitted');
                fetchHeaders.add('precedence');

                fetchHeaders.add('in-reply-to');
                fetchHeaders.add('references');

                fetchHeaders.add('content-type');

                messageFetchOptions.fetchHeaders = Array.from(fetchHeaders);
            }

            // have to call after fetch is finished

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

                let canSync = documentStoreEnabled && (!this.connection.syncFrom || messageData.internalDate >= this.connection.syncFrom);

                if (this.connection.notifyFrom && messageData.internalDate < this.connection.notifyFrom && !canSync) {
                    // skip too old messages
                    continue;
                }

                await this.processNew(messageData, messageFetchOptions, canSync);
            }

            if (hadUpdates) {
                await this.markUpdated();
            }
        } finally {
            this.connection.syncing = false;
            lock.release();
        }
    }

    async onOpen() {
        clearTimeout(this.runPartialSyncTimer);
        this.selected = true;

        let mailboxStatus = this.getMailboxStatus();

        try {
            let storedStatus = await this.getStoredStatus();

            let hasQueuedNotifications = await this.connection.redis.exists(this.getNotificationsKey());
            if (hasQueuedNotifications) {
                return await this.fullSync();
            }

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

            if (storedStatus.highestModseq && storedStatus.highestModseq === mailboxStatus.highestModseq) {
                return false;
            }

            if (storedStatus.messages === 0 && mailboxStatus.messages === 0) {
                return false;
            }

            if (
                this.connection.imapClient.enabled.has('CONDSTORE') &&
                storedStatus.highestModseq < mailboxStatus.highestModseq &&
                storedStatus.messages <= mailboxStatus.messages &&
                mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
            ) {
                // search for flag changes and new messages
                return await this.partialSync(storedStatus);
            }

            if (
                storedStatus.messages < mailboxStatus.messages &&
                mailboxStatus.uidNext - storedStatus.uidNext === mailboxStatus.messages - storedStatus.messages
            ) {
                // seem to have new messages only
                return await this.partialSync(storedStatus);
            }

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

            if (this.synced) {
                this.synced();
            } else {
                await this.select();
            }
        }
    }

    async onClose() {
        clearTimeout(this.runPartialSyncTimer);
        this.selected = false;
    }

    // User methods
    // Call `clearTimeout(this.connection.completedTimer);` after locking mailbox
    // Call this.onTaskCompleted() after selected mailbox is processed and lock is released

    async getText(message, textParts, options, allowSecondary) {
        options = options || {};

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let result = {};

        let maxBytes = options.maxBytes || Infinity;
        let reqMaxBytes = options.maxBytes && !isNaN(options.maxBytes) ? Number(options.maxBytes) + 4 : maxBytes;

        let hasMore = false;

        let lock;
        if (!options.skipLock) {
            lock = await this.getMailboxLock(connectionClient);
        }

        try {
            for (let part of textParts) {
                let { meta, content } = await connectionClient.download(message.uid, part, {
                    uid: true,
                    // make sure we request enough bytes so we would have complete utf-8 codepoints
                    maxBytes: Math.min(reqMaxBytes, MAX_ALLOWED_DOWNLOAD_SIZE),
                    // future feature
                    chunkSize: options.chunkSize
                });

                if (!content) {
                    continue;
                }
                let text = await download(content);
                text = text.toString().replace(/\r?\n/g, '\n');

                let typeKey = (meta.contentType && meta.contentType.split('/')[1]) || 'plain';
                if (!result[typeKey]) {
                    result[typeKey] = [];
                }

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

        Object.keys(result).forEach(key => {
            result[key] = result[key].join('\n');
        });

        result.hasMore = hasMore;

        if (!options.skipLock) {
            this.onTaskCompleted(connectionClient);
        }

        return result;
    }

    async getAttachment(message, part, options, allowSecondary) {
        options = options || {};
        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        let streaming = false;
        let released = false;
        try {
            let { meta, content } = await connectionClient.download(message.uid, part, {
                uid: true,
                maxBytes: Math.min(options.maxBytes, MAX_ALLOWED_DOWNLOAD_SIZE),
                // future feature
                chunkSize: options.chunkSize
            });

            if (!meta) {
                return false;
            }

            let filenameParam = '';
            if (meta.filename) {
                let isCleartextFilename = meta.filename && /^[a-z0-9 _\-()^[\]~=,+*$]$/i.test(meta.filename);
                if (isCleartextFilename) {
                    filenameParam = `; filename=${JSON.stringify(meta.filename)}`;
                } else {
                    filenameParam = `; filename=${JSON.stringify(he.encode(meta.filename))}; filename*=utf-8''${encodeURIComponent(meta.filename)}`;
                }
            }

            content.headers = {
                'content-type': meta.contentType || 'application/octet-stream',
                'content-disposition': 'attachment' + filenameParam
            };

            content.contentType = meta.contentType;
            content.filename = meta.filename;
            content.disposition = meta.disposition;
            streaming = true;

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

    async getMessage(message, options, allowSecondary) {
        options = options || {};
        let messageInfo;

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        try {
            let lock;
            if (!options.skipLock) {
                lock = await this.getMailboxLock(connectionClient);
            }

            try {
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
                if (options.markAsSeen && (!messageData.flags || !messageData.flags.has('\\Seen'))) {
                    //
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

                messageInfo = await this.getMessageInfo(messageData, true, allowSecondary);
            } finally {
                if (lock) {
                    lock.release();
                }
            }

            if (!messageInfo) {
                return false;
            }

            // merge decoded text content with message data (if requested)
            if (options.textType && messageInfo.text && messageInfo.text.id) {
                let { textParts } = await this.connection.getMessageTextPaths(messageInfo.text.id);
                if (textParts && textParts.length) {
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
                        let textContent = await this.getText(message, textParts, options, allowSecondary);
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

            if (options.embedAttachedImages && messageInfo.text && messageInfo.text.html && messageInfo.attachments) {
                let attachmentList = new Map();
                let partList = [];

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

            if (options.preProcessHtml && messageInfo.text && (messageInfo.text.html || messageInfo.text.plain)) {
                messageInfo.text.html = mimeHtml({
                    html: messageInfo.text.html,
                    text: messageInfo.text.plain
                });
                messageInfo.text.webSafe = true;
            }

            if (this.listingEntry.specialUse) {
                messageInfo.specialUse = this.listingEntry.specialUse;
            }

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

    async updateMessage(message, updates, allowSecondary) {
        updates = updates || {};

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (updates.flags) {
                if (updates.flags.set) {
                    // If set exists the ignore add/delete calls
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

            if (updates.labels && this.isGmail) {
                if (updates.labels.set) {
                    // If set exists the ignore add/delete calls
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

    async updateMessages(search, updates, allowSecondary) {
        updates = updates || {};

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (updates.flags) {
                if (updates.flags.set) {
                    // If set exists the ignore add/delete calls
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

            if (updates.labels && this.isGmail) {
                if (updates.labels.set) {
                    // If set exists the ignore add/delete calls
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

    async moveMessage(message, target, allowSecondary) {
        target = target || {};

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (target.path) {
                // If set exists the ignore add/delete calls
                let value = await connectionClient.messageMove(message.uid, target.path, { uid: true });
                result.path = target.path;
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

    async moveMessages(search, target, allowSecondary) {
        target = target || {};

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (target.path) {
                // If set exists the ignore add/delete calls
                let value = await connectionClient.messageMove(search, target.path, { uid: true });
                result.path = target.path;

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

    async deleteMessage(message, force, allowSecondary) {
        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (['\\Trash', '\\Junk'].includes(this.listingEntry.specialUse) || force) {
                // delete
                result.deleted = await connectionClient.messageDelete(message.uid, { uid: true });
            } else {
                // move to trash
                // find Trash folder path
                let trashMailbox = await this.connection.getSpecialUseMailbox('\\Trash');
                if (!trashMailbox || normalizePath(trashMailbox.path) === normalizePath(this.path)) {
                    // no Trash found or already in trash
                    result.deleted = await connectionClient.messageDelete(message.uid, { uid: true });
                } else {
                    result.deleted = false;
                    // we have a destionation, so can move message to there
                    let moved = await await connectionClient.messageMove(message.uid, trashMailbox.path, { uid: true });
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

    async deleteMessages(search, force, allowSecondary) {
        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let result = {};

            if (['\\Trash', '\\Junk'].includes(this.listingEntry.specialUse) || force) {
                // delete
                result.deleted = await connectionClient.messageDelete(search, { uid: true });
            } else {
                // move to trash
                // find Trash folder path
                let trashMailbox = await this.connection.getSpecialUseMailbox('\\Trash');
                if (!trashMailbox || normalizePath(trashMailbox.path) === normalizePath(this.path)) {
                    // no Trash found or already in trash
                    result.deleted = await connectionClient.messageDelete(search, { uid: true });
                } else {
                    result.deleted = false;
                    // we have a destionation, so can move message to there
                    let moved = await await connectionClient.messageMove(search, trashMailbox.path, { uid: true });
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

    async listMessages(options, allowSecondary) {
        options = options || {};
        let page = Number(options.page) || 0;
        let pageSize = Math.abs(Number(options.pageSize) || 20);

        const connectionClient = await this.connection.getImapConnection(allowSecondary);

        let lock = await this.getMailboxLock(connectionClient);

        try {
            let mailboxStatus = this.getMailboxStatus(connectionClient);

            let messageCount = mailboxStatus.messages;
            let uidList;
            let opts = {};

            if (options.search) {
                uidList = await connectionClient.search(options.search, { uid: true });
                uidList = !uidList ? [] : uidList.sort((a, b) => b - a); // newer first
                messageCount = uidList.length;
            }

            let pages = Math.ceil(messageCount / pageSize) || 1;

            if (page < 0) {
                page = 0;
            }

            let messages = [];
            let seqMax, seqMin, range;

            if (!messageCount || page >= pages) {
                return {
                    page,
                    pages,
                    messages
                };
            }

            if (options.search && uidList) {
                let start = page * pageSize;
                let uidRange = uidList.slice(start, start + pageSize).reverse();
                range = uidRange.join(',');
                opts.uid = true;
            } else {
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
                // list newer first. servers like yahoo do not return ordered list, so we need to order manually
                messages: messages.sort((a, b) => b.uid - a.uid)
            };
        } finally {
            lock.release();
            this.connection.onTaskCompleted(connectionClient);
        }
    }

    async markUpdated() {
        try {
            await this.connection.redis.hSetExists(this.connection.getAccountKey(), 'sync', new Date().toISOString());
        } catch (err) {
            this.logger.error({ msg: 'Redis error', err });
        }
    }

    mightBeABounce(messageInfo) {
        if (this.path !== 'INBOX' && !(this.isAllMail && messageInfo.labels && messageInfo.labels.includes('\\Inbox'))) {
            return false;
        }

        if (messageInfo.deliveryReport) {
            // already processed
            return false;
        }

        let name = (messageInfo.from && messageInfo.from.name) || '';
        let address = (messageInfo.from && messageInfo.from.address) || '';

        if (/Mail Delivery System|Mail Delivery Subsystem|Internet Mail Delivery/i.test(name)) {
            return true;
        }

        if (/mailer-daemon@|postmaster@/i.test(address)) {
            return true;
        }

        let hasDeliveryStatus = false;
        for (let attachment of messageInfo.attachments || []) {
            if (attachment.contentType === 'message/delivery-status') {
                hasDeliveryStatus = true;
            }
        }

        if (hasDeliveryStatus && /Undeliverable/i.test(messageInfo.subject)) {
            return true;
        }

        return false;
    }

    mightBeAComplaint(messageInfo) {
        if (this.path !== 'INBOX' && !(this.isAllMail && messageInfo.labels && messageInfo.labels.includes('\\Inbox'))) {
            return false;
        }

        let hasEmbeddedMessage = false;
        for (let attachment of messageInfo.attachments || []) {
            if (attachment.contentType === 'message/feedback-report') {
                return true;
            }

            if (['message/rfc822', 'message/rfc822-headers'].includes(attachment.contentType)) {
                hasEmbeddedMessage = true;
            }
        }

        let fromAddress = (messageInfo.from && messageInfo.from.address) || '';

        if (hasEmbeddedMessage && fromAddress === 'staff@hotmail.com' && /complaint/i.test(messageInfo.subject)) {
            return true;
        }

        return false;
    }

    mightBeDSNResponse(messageInfo) {
        if (this.path !== 'INBOX' && !(this.isAllMail && messageInfo.labels && messageInfo.labels.includes('\\Inbox'))) {
            return false;
        }

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

    isAutoreply(messageInfo) {
        if (/^(auto:|Out of Office|OOF:|OOO:)/i.test(messageInfo.subject) && messageInfo.inReplyTo) {
            return true;
        }

        if (!messageInfo.headers) {
            return false;
        }

        if (messageInfo.headers.precedence && messageInfo.headers.precedence.some(e => /auto[_-]?reply/.test(e))) {
            return true;
        }

        if (messageInfo.headers['auto-submitted'] && messageInfo.headers['auto-submitted'].some(e => /auto[_-]?replied/.test(e))) {
            return true;
        }

        for (let headerKey of ['x-autoresponder', 'x-autorespond', 'x-autoreply']) {
            if (messageInfo.headers[headerKey] && messageInfo.headers[headerKey].length) {
                return true;
            }
        }

        return false;
    }
}

module.exports.Mailbox = Mailbox;
