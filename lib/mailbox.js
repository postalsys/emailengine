'use strict';

const crypto = require('crypto');
const { serialize, unserialize, compareExisting, normalizePath } = require('./tools');
const msgpack = require('msgpack5')();
const he = require('he');
const libmime = require('libmime');

// Do not check for flag updates using full sync more often than this value
const FULL_SYNC_DELAY = 30 * 60 * 1000;

class Mailbox {
    constructor(connection, entry) {
        this.status = false;
        this.connection = connection;
        this.path = entry.path;
        this.listingEntry = entry;
        this.syncDisabled = entry.syncDisabled;

        this.imapClient = this.connection.imapClient;

        this.logger = this.connection.logger.child({
            sub: 'mailbox',
            path: this.path
        });

        this.isGmail = connection.isGmail;
        this.isAllMail = this.isGmail && this.listingEntry.specialUse === '\\All';

        this.selected = false;

        this.redisKey = BigInt(
            '0x' +
                crypto
                    .createHash('sha1')
                    .update(normalizePath(this.path))
                    .digest('hex')
        ).toString(36);

        this.runPartialSyncTimer = false;

        this.synced = false;
    }

    getMailboxStatus() {
        let mailboxInfo = this.imapClient.mailbox;

        let status = {
            path: this.path
        };

        status.highestModseq = mailboxInfo.highestModseq ? mailboxInfo.highestModseq : false;
        status.uidValidity = mailboxInfo.uidValidity ? mailboxInfo.uidValidity : false;
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
            uidValidity: data.uidValidity && !isNaN(data.uidValidity) ? BigInt(data.uidValidity) : false,
            highestModseq: data.highestModseq && !isNaN(data.highestModseq) ? BigInt(data.highestModseq) : false,
            messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
            uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false,
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
     * Deletes entry from message list for the provided sequence value
     * @param {Number} seq Sequence number
     * @returns {Object|null} Message entry object that was deleted
     */
    async entryListExpunge(seq) {
        let response = await this.connection.redis.zExpungeBuffer(this.getMessagesKey(), this.getMailboxKey(), seq);
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
        return this.selected && this.imapClient.mailbox && normalizePath(this.imapClient.mailbox.path) === normalizePath(this.path);
    }

    getMessagesKey() {
        return `iam:${this.connection.account}:l:${this.redisKey}`;
    }

    getMailboxKey() {
        return `iam:${this.connection.account}:h:${this.redisKey}`;
    }

    startIdle() {
        if (!this.isSelected() || this.imapClient.idling) {
            return;
        }
        this.imapClient.idle().catch(err => {
            this.logger.error({ msg: 'IDLE error', err });
        });
    }

    // clear mailbox records
    async clear(opts) {
        opts = opts || {};

        clearTimeout(this.runPartialSyncTimer);

        await this.connection.redis.del(this.getMailboxKey());
        await this.connection.redis.del(this.getMessagesKey());

        this.logger.debug({ msg: 'Deleted mailbox', path: this.listingEntry.path });

        if (!opts.skipNotify) {
            this.connection.notify(this, 'mailboxDeleted', {
                path: this.listingEntry.path,
                name: this.listingEntry.name,
                specialUse: this.listingEntry.specialUse || false
            });
        }
    }

    async sync() {
        if (this.selected) {
            // expect current folder to be already synced
            return false;
        }

        let status = await this.imapClient.status(this.path, {
            uidNext: true,
            messages: true,
            highestModseq: true,
            uidValidity: true
        });

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

            if ((!status.messages && !storedStatus.messages) || status.highestModseq === storedStatus.highestModseq) {
                // no reason to sync
                return true;
            }
        }

        let syncedPromise = new Promise((resolve, reject) => {
            this.synced = resolve;
            this.select(true).catch(err => reject(err));
        });

        await syncedPromise;
    }

    async select(skipIdle) {
        let lock = await this.imapClient.getMailboxLock(this.path);
        // have to release the lock immediatelly, otherwise difficult to process 'exists' / 'expunge' events
        lock.release();

        if (!skipIdle) {
            // do not wait until command finishes before proceeding
            this.startIdle();
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

        let deletedEntry = await this.entryListExpunge(event.seq);
        if (deletedEntry) {
            await this.processDeleted(deletedEntry);
        }
    }

    async onFlags(event) {
        this.logEvent('Untagged FETCH', event);

        let storedMessage = await this.entryListGet(event.seq, { uid: false });
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

        let lock = await this.imapClient.getMailboxLock(this.path);
        try {
            let newMesages = [];

            let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true };
            let range = '1:*';
            let opts = {
                uid: true
            };

            if (this.imapClient.enabled.has('CONDSTORE') && storedStatus.highestModseq) {
                opts.changedSince = storedStatus.highestModseq;
            } else if (storedStatus.uidNext) {
                range = `${storedStatus.uidNext}:*`;
            }

            if (mailboxStatus.messages) {
                // only fetch messages if there is some
                for await (let messageData of this.imapClient.fetch(range, fields, opts)) {
                    // ignore Recent flag
                    messageData.flags.delete('\\Recent');

                    let storedMessage = await this.entryListGet(messageData.uid, { uid: true });
                    let changes;
                    if (!storedMessage) {
                        // new!
                        let seq = await this.entryListSet(messageData);
                        if (seq) {
                            newMesages.push(messageData);
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

            // have to call after fetch is finished
            for (let messageData of newMesages) {
                await this.processNew(messageData);
            }
        } finally {
            lock.release();
        }
    }

    async processDeleted(messageData) {
        this.logger.debug({ msg: 'Deleted', uid: messageData.uid });

        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, 'messageDeleted', {
            id: packedUid,
            uid: messageData.uid
        });
    }

    async processNew(messageData) {
        this.logger.debug({ msg: 'New message', uid: messageData.uid, flags: Array.from(messageData.flags) });
        if (this.listingEntry.isNew) {
            // ignore new messages for first sync
            return;
        }

        let additionalData = await this.imapClient.fetchOne(
            messageData.uid,
            {
                uid: true,
                flags: true,
                size: true,
                bodyStructure: true,
                envelope: true,
                internalDate: true,
                labels: true
            },
            { uid: true }
        );

        if (!additionalData) {
            this.logger.debug({ msg: 'Not found', uid: messageData.uid });
            return;
        }

        let messageInfo = await this.getMessageInfo(additionalData);
        await this.connection.notify(this, 'messageNew', messageInfo);
    }

    async getMessageInfo(messageData, extended) {
        if (!messageData) {
            return false;
        }

        let packedUid = await this.connection.packUid(this, messageData.uid);
        let { attachments, textId, encodedTextSize } = this.getAttachmentList(packedUid, messageData.bodyStructure);

        let envelope = messageData.envelope || {};
        let date = envelope.date || messageData.internalDate;

        let result = {
            id: packedUid,
            uid: messageData.uid,

            emailId: messageData.emailId || undefined,
            threadId: messageData.threadId || undefined,

            date: (date && date.toISOString()) || undefined,
            flags: (extended && messageData.flags && messageData.flags.size && Array.from(messageData.flags)) || undefined,

            unseen: messageData.flags && !messageData.flags.has('\\Seen') ? true : undefined,
            flagged: messageData.flags && messageData.flags.has('\\Flagged') ? true : undefined,
            answered: messageData.flags && messageData.flags.has('\\Answered') ? true : undefined,
            draft: messageData.flags && messageData.flags.has('\\Draft') ? true : undefined,

            size: messageData.size || undefined,
            subject: envelope.subject || undefined,
            from: envelope.from && envelope.from[0] ? envelope.from[0] : undefined,

            replyTo: extended && envelope.replyTo && envelope.replyTo[0] ? envelope.replyTo[0] : undefined,
            sender: extended && envelope.sender && envelope.sender[0] ? envelope.sender[0] : undefined,

            to: envelope.to && envelope.to.length ? envelope.to : undefined,
            cc: envelope.cc && envelope.cc.length ? envelope.cc : undefined,

            bcc: extended && envelope.bcc && envelope.bcc.length ? envelope.bcc : undefined,

            attachments: attachments && attachments.length ? attachments : undefined,
            messageId: envelope.messageId || undefined,
            inReplyTo: envelope.inReplyTo || undefined,

            labels: messageData.labels && messageData.labels.size ? Array.from(messageData.labels) : undefined,

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

        return result;
    }

    getAttachmentList(packedUid, bodyStructure) {
        let attachments = [];
        let textParts = [[], [], []];
        if (!bodyStructure) {
            return attachments;
        }

        let idBuf = Buffer.from(packedUid.replace(/-/g, '+').replace(/_/g, '\\'), 'base64');

        let encodedTextSize = {};

        let walk = (node, isRelated) => {
            if (node.type === 'multipart/related') {
                isRelated = true;
            }

            if (!/^multipart\//.test(node.type)) {
                if (node.disposition === 'attachment' || !/^text\//.test(node.type)) {
                    attachments.push({
                        // append body part nr to message id
                        id: Buffer.concat([idBuf, Buffer.from(node.part || '1')])
                            .toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\\/g, '_')
                            .replace(/[=]+/g, ''),
                        contentType: node.type,
                        encodedSize: node.size,
                        filename: (node.dispositionParameters && node.dispositionParameters.filename) || (node.parameters && node.parameters.name) || false,
                        embedded: isRelated,
                        inline: node.disposition === 'inline' || (!node.disposition && isRelated),
                        contentId: node.id
                    });
                } else if ((!node.disposition || node.disposition === 'inline') && /^text\//.test(node.type)) {
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
            textId: Buffer.concat([idBuf, msgpack.encode(textParts)])
                .toString('base64')
                .replace(/\+/g, '-')
                .replace(/\\/g, '_')
                .replace(/[=]+/g, ''),
            encodedTextSize
        };
    }

    async processChanges(messageData, changes) {
        let packedUid = await this.connection.packUid(this, messageData.uid);
        await this.connection.notify(this, 'messageUpdated', {
            id: packedUid,
            uid: messageData.uid,
            changes
        });
    }

    async fullSync() {
        let range = '1:*';
        let fields = { uid: true, flags: true, modseq: true, emailId: true, labels: true };
        let opts = {};

        let lock = await this.imapClient.getMailboxLock(this.path);
        try {
            let mailboxStatus = this.getMailboxStatus();
            let newMesages = [];

            // full sync
            let seqMax = 0;
            let changes;

            if (mailboxStatus.messages) {
                // only fetch messages if there is some
                for await (let messageData of this.imapClient.fetch(range, fields, opts)) {
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
                            newMesages.push(messageData);
                        }
                    } else {
                        let diff = storedMessage.seq - messageData.seq;
                        for (let i = 0; i < diff; i++) {
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
            for (let i = 0; i < diff; i++) {
                let seq = seqMax + i + 1;
                let deletedEntry = await this.entryListExpunge(seq);
                if (deletedEntry) {
                    await this.processDeleted(deletedEntry);
                }
            }

            let status = this.getMailboxStatus();
            status.lastFullSync = new Date();
            await this.updateStoredStatus(status);

            // have to call after fetch is finished
            for (let messageData of newMesages) {
                await this.processNew(messageData);
            }
        } finally {
            lock.release();
        }
    }

    async onOpen() {
        clearTimeout(this.runPartialSyncTimer);
        this.selected = true;

        let mailboxStatus = this.getMailboxStatus();

        try {
            let storedStatus = await this.getStoredStatus();

            if (storedStatus.uidValidity && storedStatus.uidValidity !== mailboxStatus.uidValidity) {
                // UIDVALIDITY has changed, full sync is required!
                // delete mailbox status
                let result = await this.connection.redis
                    .multi()
                    .zcard(this.getMessagesKey())
                    .del(this.getMessagesKey())
                    .del(this.getMailboxKey())
                    .exec();

                let deletedMessages = (result[0] && Number(result[0][1])) || 0;
                this.logger.info({
                    msg: 'UIDVALIDITY change',
                    deleted: deletedMessages,
                    prevUidValidity: storedStatus.uidValidity && storedStatus.uidValidity.toString(),
                    uidValidity: mailboxStatus.uidValidity && mailboxStatus.uidValidity.toString()
                });

                this.logger.debug({ msg: 'Mailbox reset', path: this.listingEntry.path });
                await this.connection.notify(this, 'mailboxReset', {
                    path: this.listingEntry.path,
                    name: this.listingEntry.name,
                    specialUse: this.listingEntry.specialUse || false,
                    uidValidity: mailboxStatus.uidValidity && mailboxStatus.uidValidity.toString(),
                    prevUidValidity: storedStatus.uidValidity && storedStatus.uidValidity.toString()
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

            if (this.imapClient.enabled.has('CONDSTORE') && storedStatus.highestModseq < mailboxStatus.highestModseq) {
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
        } finally {
            if (this.listingEntry.isNew) {
                // fully synced, so not new anymore
                this.listingEntry.isNew = false;
                this.logger.debug({ msg: 'New mailbox', path: this.listingEntry.path });
                this.connection.notify(this, 'mailboxNew', {
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

    async download(stream) {
        return new Promise((resolve, reject) => {
            let chunks = [];
            let chunklen = 0;
            stream.on('error', err => reject(err));
            stream.on('readable', () => {
                let chunk;
                while ((chunk = stream.read()) !== null) {
                    if (typeof chunk === 'string') {
                        chunk = Buffer.from(chunk);
                    }
                    if (!chunk || !Buffer.isBuffer(chunk)) {
                        // what's that?
                        return;
                    }
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });
            stream.on('end', () => {
                resolve(Buffer.concat(chunks, chunklen));
            });
        });
    }

    // User methods
    // Call `clearTimeout(this.connection.completedTimer);` after locking mailbox
    // Call this.onTaskCompleted() after selected mailbox is processed and lock is released

    async getText(message, textParts, options) {
        options = options || {};
        let result = {};

        let maxBytes = options.maxBytes || Infinity;
        let reqMaxBytes = options.maxBytes && !isNaN(options.maxBytes) ? Number(options.maxBytes) + 4 : maxBytes;

        let hasMore = false;

        let lock = await this.imapClient.getMailboxLock(this.path);
        clearTimeout(this.connection.completedTimer);
        try {
            for (let part of textParts) {
                let { meta, content } = await this.imapClient.download(message.uid, part, {
                    uid: true,
                    // make sure we request enough bytes so we would have complete utf-8 codepoints
                    maxBytes: reqMaxBytes
                });
                if (!content) {
                    continue;
                }
                let text = await this.download(content);
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
            lock.release();
        }

        Object.keys(result).forEach(key => {
            result[key] = result[key].join('\n');
        });

        result.hasMore = hasMore;

        this.connection.onTaskCompleted();
        return result;
    }

    async getAttachment(message, part, options) {
        options = options || {};
        let lock = await this.imapClient.getMailboxLock(this.path);
        clearTimeout(this.connection.completedTimer);

        let streaming = false;
        let released = false;
        try {
            let { meta, content } = await this.imapClient.download(message.uid, part, {
                uid: true,
                maxBytes: options.maxBytes
            });

            if (!meta) {
                return false;
            }

            content.headers = {
                'content-type': meta.contentType || 'application/octet-stream',
                'content-disposition': 'attachment' + (meta.filename ? `; filename=${he.encode(meta.filename)}` : '')
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
                    this.connection.onTaskCompleted();
                }
            });

            return content;
        } finally {
            if (!streaming) {
                lock.release();
                this.connection.onTaskCompleted();
            }
        }
    }

    async getMessage(message, options) {
        options = options || {};
        let messageInfo;

        try {
            let lock = await this.imapClient.getMailboxLock(this.path);
            clearTimeout(this.connection.completedTimer);

            try {
                let fields = options.fields || {
                    uid: true,
                    flags: true,
                    size: true,
                    bodyStructure: true,
                    envelope: true,
                    internalDate: true,
                    headers: true,
                    emailId: true,
                    threadId: true,
                    labels: true
                };

                let messageData = await this.imapClient.fetchOne(message.uid, fields, { uid: true });
                if (!messageData) {
                    return false;
                }
                messageInfo = await this.getMessageInfo(messageData, true);
            } finally {
                lock.release();
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
                        let textContent = await this.getText(message, textParts, options);
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
            return messageInfo;
        } finally {
            this.connection.onTaskCompleted();
        }
    }

    async updateMessage(message, updates) {
        updates = updates || {};
        let lock = await this.imapClient.getMailboxLock(this.path);
        clearTimeout(this.connection.completedTimer);

        try {
            let result = {};
            if (updates.flags) {
                if (updates.flags.set) {
                    // If set exists the ignore add/delete calls
                    let value = await this.imapClient.messageFlagsSet(message.uid, updates.flags.set, { uid: true });
                    result.flags = {
                        set: value
                    };
                } else {
                    if (updates.flags.add && updates.flags.add.length) {
                        let value = await this.imapClient.messageFlagsAdd(message.uid, updates.flags.add, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.add = value;
                    }

                    if (updates.flags.delete && updates.flags.delete.length) {
                        let value = await this.imapClient.messageFlagsRemove(message.uid, updates.flags.delete, { uid: true });
                        if (!result.flags) {
                            result.flags = {};
                        }
                        result.flags.delete = value;
                    }
                }
            }
            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted();
        }
    }

    async deleteMessage(message) {
        let lock = await this.imapClient.getMailboxLock(this.path);
        clearTimeout(this.connection.completedTimer);

        try {
            let result = {};

            if (this.listingEntry.specialUse === '\\Trash') {
                // delete
                result.deleted = await this.imapClient.messageDelete(message.uid, { uid: true });
            } else {
                // move to trash
                // find Trash folder path
                let trashMailbox = await this.connection.getSpecialUseMailbox('\\Trash');
                if (!trashMailbox || normalizePath(trashMailbox.path) === normalizePath(this.path)) {
                    // no Trash found or already in trash
                    result.deleted = await this.imapClient.messageDelete(message.uid, { uid: true });
                } else {
                    // we have a destionation, so can move message to there
                    let moved = await await this.imapClient.messageMove(message.uid, trashMailbox.path, { uid: true });
                    if (moved) {
                        result.moved = {
                            destination: moved.destination
                        };
                        if (moved && moved.uidMap && moved.uidMap.has(message.uid)) {
                            result.moved.messageId = await this.connection.packUid(trashMailbox.path, moved.uidMap.get(message.uid));
                        }
                    }
                }
            }
            return result;
        } finally {
            lock.release();
            this.connection.onTaskCompleted();
        }
    }

    async listMessages(options) {
        options = options || {};
        let page = Number(options.page) || 0;
        let pageSize = Number(options.pageSize) || 20;

        let lock = await this.imapClient.getMailboxLock(this.path);
        clearTimeout(this.connection.completedTimer);

        try {
            let mailboxStatus = this.getMailboxStatus();

            let messageCount = mailboxStatus.messages;
            let uidList;
            let opts = {};

            if (options.search) {
                uidList = await this.imapClient.search(options.search, { uid: true });
                uidList = uidList.sort((a, b) => b - a); // newer first
                messageCount = uidList.length;
            }

            let pages = Math.ceil(messageCount / pageSize) || 1;

            if (page < 0) {
                page = 0;
            }

            if (page >= pages) {
                page = pages - 1;
            }

            let messages = [];
            let seqMax, seqMin;

            if (!messageCount) {
                return {
                    page,
                    pages,
                    messages
                };
            }

            if (options.search && uidList) {
                let start = page * pageSize;
                let uidRange = uidList.slice(start, start + pageSize).reverse();
                seqMin = uidRange[0];
                seqMax = uidRange[uidRange.length - 1];
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
            }

            let range = seqMin === seqMax ? `${seqMin}` : `${seqMin}:${seqMax}`;

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

            for await (let messageData of this.imapClient.fetch(range, fields, opts)) {
                let messageInfo = await this.getMessageInfo(messageData);
                messages.push(messageInfo);
            }

            return {
                page,
                pages,
                // list newer first
                messages: messages.reverse()
            };
        } finally {
            lock.release();
            this.connection.onTaskCompleted();
        }
    }
}

module.exports.Mailbox = Mailbox;
