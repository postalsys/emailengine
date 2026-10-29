'use strict';

const { randomUUID: uuid } = require('crypto');
const { redis, notifyQueue } = require('./db');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX, MESSAGE_NEW_NOTIFY } = require('./consts');
const { SubScript } = require('./sub-script');
const settings = require('./settings');
const { filterListPage, redactUrlCredentials, truncateTextContents } = require('./tools');
const { buildRetentionPolicy } = require('./queue-retention');
const { getFailedJobRetention } = require('./env-setting-overrides');
const { isDeliverableRoute, defaultRouteTakes, webhookRetryPolicy } = require('./webhook-routing');
const { withinNotifyAttachmentSize } = require('./notify-attachments');
const { notifyHeadersIncludeOtp } = require('./otp');

// Every setting pushToQueue() decides by, read in one round trip per event
const QUEUE_SETTINGS = ['webhooksEnabled', 'queueKeep', 'webhookEvents', 'inboxNewOnly', 'webhooksDeliveryAttempts', 'webhooksRetryDelay'];
const { encryptField, decryptField } = require('./encrypt');
const getSecret = require('./get-secret');

// Route fields that carry credentials: the target URL may embed `user:pass@` and the custom
// headers usually hold an Authorization value. Encrypted inside the stored meta entry like the
// global `webhooks` / `webhooksCustomHeaders` settings; the header list is stored as encrypted
// JSON. A route written before this holds cleartext (and an array for the headers), which reads
// as is. `emailengine encrypt` re-encrypts exactly these fields.
const ENCRYPTED_ROUTE_FIELDS = ['targetUrl', 'customHeaders'];

class WebhooksHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;

        this.handlerCache = [];
        this.handlerCacheV = 0;
        // the refresh in flight, shared by concurrent getWebhookHandlers() calls
        this.handlerRefresh = null;
    }

    getWebhooksIndexKey() {
        return `${REDIS_PREFIX}wh:i`;
    }

    getWebhooksContentKey() {
        return `${REDIS_PREFIX}wh:c`;
    }

    getWebhooksLogKey(id) {
        return `${REDIS_PREFIX}wh:l:${id}`;
    }

    getSettingsKey() {
        return `${REDIS_PREFIX}settings`;
    }

    // Stored form of a route's meta entry, see ENCRYPTED_ROUTE_FIELDS
    async encodeMeta(entry) {
        const secret = await getSecret();
        const stored = Object.assign({}, entry);
        if (secret) {
            if (typeof stored.targetUrl === 'string') {
                stored.targetUrl = encryptField(stored.targetUrl, secret);
            }
            if (Array.isArray(stored.customHeaders)) {
                stored.customHeaders = encryptField(JSON.stringify(stored.customHeaders), secret);
            }
        }
        return msgpack.encode(stored);
    }

    // Decodes a stored meta entry. A field that does not decrypt with the current secret is left
    // out and logged: without a targetUrl the route is not deliverable, which is the safe outcome
    // for a route whose credentials cannot be read.
    async decodeMeta(buf, id) {
        const meta = msgpack.decode(buf);
        if (!meta || typeof meta !== 'object') {
            return meta;
        }

        const secret = await getSecret();

        if (typeof meta.targetUrl === 'string') {
            meta.targetUrl = decryptField(meta.targetUrl, secret, err =>
                logger.error({ msg: 'Failed to decrypt webhook route field', webhook: id || meta.id, field: 'targetUrl', err })
            );
            if (typeof meta.targetUrl === 'undefined') {
                delete meta.targetUrl;
            }
        }

        if (typeof meta.customHeaders === 'string') {
            // never log the value, it is a credential once decrypted
            const report = err =>
                logger.error({
                    msg: 'Failed to decrypt webhook route field',
                    webhook: id || meta.id,
                    field: 'customHeaders',
                    errorType: err.name,
                    code: err.code
                });
            const json = decryptField(meta.customHeaders, secret, report);
            try {
                // JSON.parse(undefined) throws, so a value that did not decrypt lands here too
                // and is left out, already reported
                meta.customHeaders = JSON.parse(json);
            } catch (err) {
                if (typeof json !== 'undefined') {
                    report(err);
                }
                delete meta.customHeaders;
            }
        }

        return meta;
    }

    async list(page, pageSize, query) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let webhookIds = await this.redis.smembers(this.getWebhooksIndexKey());
        webhookIds = [].concat(webhookIds || []).sort((a, b) => -a.localeCompare(b));

        let response = {
            total: webhookIds.length,
            pages: Math.ceil(webhookIds.length / pageSize),
            page,
            webhooks: []
        };

        // Without a query only the visible page's metadata is fetched; with a query
        // all metadata is loaded so the filter can run before pagination
        let selectedIds = query ? webhookIds : webhookIds.slice(startPos, startPos + pageSize);
        if (!selectedIds.length) {
            return response;
        }

        let keys = selectedIds.flatMap(id => [`${id}:meta`, `${id}:tcount`, `${id}:webhookErrorFlag`]);
        let list = await this.redis.hmgetBuffer(this.getWebhooksContentKey(), keys);

        for (let i = 0; i < list.length; i += 3) {
            let entry = list[i];
            let tcount = Number((list[i + 1] && list[i + 1].length && list[i + 1].toString()) || 0) || 0;
            let webhookErrorFlag = {};
            try {
                if (list[i + 2] && list[i + 2].length) {
                    webhookErrorFlag = JSON.parse(list[i + 2].toString());
                }
            } catch (err) {
                logger.error({
                    msg: 'Failed to parse webhook error flag',
                    webhook: selectedIds[i / 3],
                    entry: list[i + 2] && list[i + 2].toString('base64'),
                    err
                });
            }

            try {
                let webhookMeta = await this.decodeMeta(entry, selectedIds[i / 3]);
                if (webhookErrorFlag && typeof webhookErrorFlag === 'object' && !Object.keys(webhookErrorFlag).length) {
                    webhookErrorFlag = null;
                }
                response.webhooks.push(Object.assign(webhookMeta, { tcount, webhookErrorFlag }));
            } catch (err) {
                logger.error({ msg: 'Failed to process webhook', entry: entry && entry.toString('base64'), err });
                continue;
            }
        }

        if (query) {
            // Matched against the target URL as a reader of the listing sees it, credentials taken
            // out: the decrypted URL can carry user:pass@, and matching on it would let a caller
            // that only ever gets the masked value guess the credential one character at a time
            // from whether an entry matches
            let original = new Map(response.webhooks.map(entry => [Object.assign({}, entry, { targetUrl: redactUrlCredentials(entry.targetUrl) }), entry]));
            let paged = filterListPage([...original.keys()], ['id', 'name', 'description', 'targetUrl'], query, startPos, pageSize);
            response.webhooks = paged.entries.map(view => original.get(view));
            response.total = paged.total;
            response.pages = paged.pages;
        }

        return response;
    }

    async generateId() {
        let idNum = await this.redis.hincrby(this.getSettingsKey(), 'idcount', 1);

        let idBuf = Buffer.alloc(8 + 4);
        idBuf.writeBigUInt64BE(BigInt(Date.now()), 0);
        idBuf.writeUInt32BE(idNum, 8);

        return idBuf.toString('base64url');
    }

    async create(meta, content) {
        const id = await this.generateId();

        let entry = Object.assign({ id: null }, meta || {}, {
            id,
            created: new Date().toISOString()
        });

        let insertResult = await this.redis
            .multi()
            .sadd(this.getWebhooksIndexKey(), id)
            .hmset(this.getWebhooksContentKey(), {
                [`${id}:meta`]: await this.encodeMeta(entry),
                [`${id}:content`]: msgpack.encode(content),
                [`${id}:v`]: 1
            })
            .hincrby(this.getWebhooksContentKey(), `v`, 1)
            .exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        return {
            created: true,
            id
        };
    }

    async update(id, meta, content) {
        let metaBuf = await this.redis.hgetBuffer(this.getWebhooksContentKey(), `${id}:meta`);
        if (!metaBuf) {
            let err = new Error('Document was not found');
            err.code = 'NotFound';
            err.statusCode = 404;
            throw err;
        }

        let existingMeta = await this.decodeMeta(metaBuf, id);

        let entry = Object.assign(existingMeta, meta || {}, {
            id: existingMeta.id,
            created: existingMeta.created,
            updated: new Date().toISOString()
        });

        let updates = {
            [`${id}:meta`]: await this.encodeMeta(entry)
        };

        if (content) {
            updates[`${id}:content`] = msgpack.encode(content);
        }

        let insertResult = await this.redis
            .multi()
            .sadd(this.getWebhooksIndexKey(), id)
            .hmset(this.getWebhooksContentKey(), updates)
            .hincrby(this.getWebhooksContentKey(), `${id}:v`, 1)
            .hincrby(this.getWebhooksContentKey(), `v`, 1)
            .exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        return {
            updated: true,
            id
        };
    }

    async getErrorLog(id) {
        let logLines = await redis.lrangeBuffer(this.getWebhooksLogKey(id), 0, -1);
        if (!Array.isArray(logLines)) {
            logLines = [].concat(logLines || []);
        }

        let logEntries = [];

        for (let line of logLines) {
            try {
                let entry = msgpack.decode(line);
                logEntries.unshift(entry);
            } catch (err) {
                logger.error({ msg: 'Failed to decode log line', webhook: id, entry: line && line.toString('base64'), err });
            }
        }

        return logEntries;
    }

    async getMeta(id) {
        let getResult = await this.redis.hmgetBuffer(this.getWebhooksContentKey(), [`${id}:meta`]);
        if (!getResult || getResult.length !== 1 || !getResult[0]) {
            return false;
        }

        let meta;

        try {
            if (getResult[0]) {
                meta = await this.decodeMeta(getResult[0], id);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', webhook: id, entry: getResult[0].toString('base64'), err });
        }

        return Object.assign({}, meta || {});
    }

    async get(id) {
        let getResult = await this.redis.hmgetBuffer(this.getWebhooksContentKey(), [
            `${id}:meta`,
            `${id}:content`,
            `${id}:v`,
            `${id}:webhookErrorFlag`,
            `${id}:tcount`
        ]);
        if (!getResult || !getResult[0] || !getResult[1]) {
            return false;
        }

        let meta, content, webhookErrorFlag, v, tcount;

        try {
            if (getResult[0]) {
                meta = await this.decodeMeta(getResult[0], id);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', webhook: id, entry: getResult[0].toString('base64'), err });
        }

        try {
            if (getResult[1]) {
                content = msgpack.decode(getResult[1]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', webhook: id, entry: getResult[1].toString('base64'), err });
        }

        v = Number(getResult[2] && getResult[2].toString()) || 0;

        try {
            if (getResult[3]) {
                webhookErrorFlag = JSON.parse(getResult[3].toString());
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', webhook: id, entry: getResult[3].toString('base64'), err });
        }

        tcount = Number(getResult[4] && getResult[4].toString()) || 0;

        return Object.assign({}, meta || {}, { content, v, webhookErrorFlag, tcount });
    }

    async del(id) {
        let deleteResult = await this.redis
            .multi()
            .srem(this.getWebhooksIndexKey(), id)
            .hdel(this.getWebhooksContentKey(), [`${id}:meta`, `${id}:content`])
            .del(this.getWebhooksLogKey(id))
            .hincrby(this.getWebhooksContentKey(), `v`, 1)
            // The per-route counters and error flag go with the route. Not counted below: they
            // exist only once the route was updated, used or failed.
            .hdel(this.getWebhooksContentKey(), [`${id}:v`, `${id}:tcount`, `${id}:webhookErrorFlag`])
            .exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        let deletedDocs = ((deleteResult[0] && deleteResult[0][1]) || 0) + ((deleteResult[1] && deleteResult[1][1]) || 0);

        return {
            deleted: deletedDocs === 3, // any other count means something went wrong
            id
        };
    }

    async flush() {
        let deleteResult = await this.redis
            .multi()
            .del(this.getWebhooksIndexKey())
            .hget(this.getWebhooksContentKey(), 'id')
            .del(this.getWebhooksContentKey())
            .exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]) || (deleteResult[2] && deleteResult[2][0]);
        if (hasError) {
            throw hasError;
        }

        let idVal = deleteResult[1][1];
        if (idVal) {
            await this.redis.hset(this.getWebhooksContentKey(), 'id', idVal);
        }

        return {
            flushed: true
        };
    }

    async storeLog(id, type, payload, error) {
        const maxLogLines = 20;

        let logRow = msgpack.encode({
            type,
            payload,
            error,
            created: new Date().toISOString()
        });

        try {
            await redis
                .multi()
                .rpush(this.getWebhooksLogKey(id), logRow)
                .ltrim(this.getWebhooksLogKey(id), -maxLogLines, -1)
                .hset(
                    this.getWebhooksContentKey(),
                    `${id}:webhookErrorFlag`,
                    JSON.stringify({
                        event: 'exec',
                        message: (error || '')
                            .toString()
                            .split(/\r?\n/)
                            .map(line => line.trim())
                            .filter(line => line)
                            .shift(),
                        time: Date.now()
                    })
                )
                .exec();
        } catch (err) {
            logger.error({ msg: 'Failed to insert error log entries', webhook: id, err });
        }
    }

    // Filter-presence markers for the routes asked about, as a Map of id -> boolean. The
    // delivery gate in pushToQueue() requires a compiled filter function, so anything
    // describing routes to an operator (the account page's routing card) has to know which
    // routes carry a script at all. Reads only the content entries of the given ids.
    async getFilterInfo(ids) {
        let result = new Map();
        if (!ids || !ids.length) {
            return result;
        }

        let entries = await this.redis.hmgetBuffer(
            this.getWebhooksContentKey(),
            ids.map(id => `${id}:content`)
        );

        for (let i = 0; i < ids.length; i++) {
            let content = null;
            try {
                content = entries[i] ? msgpack.decode(entries[i]) : null;
            } catch (err) {
                logger.error({ msg: 'Failed to process webhook', webhook: ids[i], entry: entries[i] && entries[i].toString('base64'), err });
            }
            result.set(ids[i], !!(content && content.fn));
        }

        return result;
    }

    async getHandler(id) {
        let webhookData = await this.get(id);
        if (!webhookData) {
            // The route was deleted between the index read and the content read. Callers skip a
            // null handler; anything else would leave the cache refresh half done, with its
            // version marker stale and the main webhook never queued
            return null;
        }

        try {
            if (webhookData.content.fn) {
                webhookData.compiledFn = SubScript.create(`webhooks:filter:${id}`, webhookData.content.fn);
            } else {
                webhookData.compiledFn = false;
            }
        } catch (err) {
            await this.storeLog(id, 'filter', null, err.stack);

            logger.error({ msg: 'Failed to compile webhook script', type: 'filter', webhook: id, err });
            webhookData.compiledFn = null;
            webhookData.compiledMap = null;
        }

        if (webhookData.compiledFn) {
            try {
                if (webhookData.content.map) {
                    webhookData.compiledMap = SubScript.create(`webhooks:map:${id}`, webhookData.content.map);
                } else {
                    webhookData.content.map = false;
                }
            } catch (err) {
                await this.storeLog(id, 'map', null, err.stack);

                logger.error({ msg: 'Failed to compile webhook script', type: 'map', webhook: id, err });
                webhookData.compiledFn = null;
                webhookData.compiledMap = null;
            }
        }

        if (webhookData.compiledFn) {
            webhookData.filterFn = async payload => {
                try {
                    return await webhookData.compiledFn.exec(payload);
                } catch (err) {
                    await this.storeLog(id, 'filter', payload, err.stack);

                    logger.error({ msg: 'Failed to execute webhook script', type: 'filter', webhook: webhookData.id, err });
                    return null;
                }
            };
        }

        if (webhookData.compiledMap) {
            webhookData.mapFn = async payload => {
                try {
                    return await webhookData.compiledMap.exec(payload);
                } catch (err) {
                    await this.storeLog(id, 'map', payload, err.stack);

                    logger.error({ msg: 'Failed to execute webhook script', type: 'map', webhook: webhookData.id, err });
                    // No mapping: pushToQueue() then skips the route. The worker used to be
                    // handed the unmapped payload in its place, everything a stripping map was
                    // there to remove
                    return null;
                }
            };
        }

        return webhookData;
    }

    // Concurrent callers share one refresh. pushToQueue() runs for every event, so two refreshes
    // used to overlap: both saw the version change, both loaded the new route and both pushed it,
    // and every matching event was then queued twice to that route until the worker restarted.
    async getWebhookHandlers() {
        if (this.handlerRefresh) {
            return await this.handlerRefresh;
        }
        this.handlerRefresh = this.refreshWebhookHandlers();
        try {
            return await this.handlerRefresh;
        } finally {
            this.handlerRefresh = null;
        }
    }

    async refreshWebhookHandlers() {
        let v = await this.redis.hget(this.getWebhooksContentKey(), 'v');
        v = Number(v) || 0;
        if (v !== this.handlerCacheV) {
            // changes detected

            let webhookIds = await this.redis.smembers(this.getWebhooksIndexKey());
            webhookIds = [].concat(webhookIds || []).sort((a, b) => -a.localeCompare(b));

            // remove deleted from cache
            for (let i = this.handlerCache.length - 1; i >= 0; i--) {
                if (!webhookIds.includes(this.handlerCache[i].id)) {
                    this.handlerCache.splice(i, 1);
                }
            }

            for (let webhookId of webhookIds) {
                let existing = this.handlerCache.find(c => c.id === webhookId);
                if (!existing) {
                    // add as new
                    let handler = await this.getHandler(webhookId);
                    if (handler) {
                        this.handlerCache.push(handler);
                    }
                } else {
                    // compare existing
                    // the per-route counter is stored as a string, existing.v is a number (see get())
                    let webhookV = Number(await this.redis.hget(this.getWebhooksContentKey(), `${webhookId}:v`)) || 0;
                    if (existing.v !== webhookV) {
                        // update
                        for (let i = this.handlerCache.length - 1; i >= 0; i--) {
                            if (webhookId === this.handlerCache[i].id) {
                                let handler = await this.getHandler(webhookId);
                                if (handler) {
                                    this.handlerCache[i] = handler;
                                } else {
                                    this.handlerCache.splice(i, 1);
                                }
                            }
                        }
                    }
                }
            }

            // mark the cache as current only after a successful refresh, so a failure above
            // leaves the cache stale and the next call retries
            this.handlerCacheV = v;
        }

        return this.handlerCache;
    }

    /**
     * The messageNew normalizations: text, headers and attachment contents are kept only as far
     * as the notify settings ask
     * @param {Object} data - The event's data, changed in place
     */
    async normalizeMessageNew(data) {
        // one read for every setting these use
        const { notifyText, notifyTextSize, notifyHeaders, notifyAttachments, notifyAttachmentSize } = await settings.getMulti(
            'notifyText',
            'notifyTextSize',
            'notifyHeaders',
            'notifyAttachments',
            'notifyAttachmentSize'
        );

        if (data.text) {
            // normalize text content
            if (!notifyText) {
                // remove text content if any
                for (let key of Object.keys(data.text)) {
                    if (!['id', 'encodedSize'].includes(key)) {
                        delete data.text[key];
                    }
                }
                if (!Object.keys(data.text).length) {
                    delete data.text;
                }
            } else if (data.text && truncateTextContents(data.text, notifyTextSize)) {
                data.text.hasMore = true;
            }
        }

        if (data.headers) {
            // normalize headers
            if (!notifyHeaders?.length) {
                delete data.headers;
            } else if (!notifyHeaders.includes('*')) {
                // filter unneeded headers
                for (let header of Object.keys(data.headers || {})) {
                    if (!notifyHeaders.includes(header.toLowerCase())) {
                        delete data.headers[header];
                    }
                }
            }

            if (data.headers && !Object.keys(data.headers).length) {
                delete data.headers;
            }
        }

        if (data.otp && !notifyHeadersIncludeOtp(notifyHeaders)) {
            delete data.otp;
        }

        // remove attachment contents
        if (data.attachments) {
            for (let attachment of data.attachments) {
                if (attachment.content) {
                    if (notifyAttachments && withinNotifyAttachmentSize(attachment, notifyAttachmentSize)) {
                        // keep the attachment
                        continue;
                    }
                    delete attachment.content;
                }
            }
        }
    }

    async formatPayload(event, originalPayload) {
        // run all normalizations before sending the data

        const payload = structuredClone(originalPayload);
        payload.eventId = payload.eventId || uuid();

        if (event === MESSAGE_NEW_NOTIFY && payload.data) {
            await this.normalizeMessageNew(payload.data);
        }

        if (payload && payload.data && payload.data.text && payload.data.text._generatedHtml) {
            payload.data.text.html = payload.data.text._generatedHtml;

            delete payload.data.text._generatedHtml;
        }

        return payload;
    }

    /**
     * Formats an event and queues it for delivery. The entry point for every producer of webhook
     * events: with delivery switched off it returns before the payload is cloned and formatted.
     * @param {string} event - Event name
     * @param {Object} payload - Unformatted event payload
     */
    async enqueue(event, payload) {
        let queueSettings = await settings.getMulti(...QUEUE_SETTINGS);
        if (!queueSettings.webhooksEnabled) {
            return;
        }
        await this.pushToQueue(event, await this.formatPayload(event, payload), queueSettings);
    }

    /**
     * Queues a formatted event for the custom routes that take it and for the default route.
     * @param {string} event - Event name
     * @param {Object} originalPayload - Payload as formatPayload() returned it
     * @param {Object} [queueSettings] - QUEUE_SETTINGS values when the caller has read them already
     */
    async pushToQueue(event, originalPayload, queueSettings) {
        queueSettings = queueSettings || (await settings.getMulti(...QUEUE_SETTINGS));

        // With delivery switched off the worker drops every job before looking at its target,
        // custom routes included, so nothing is queued and no route script runs
        if (!queueSettings.webhooksEnabled) {
            return;
        }

        // custom webhook routes
        let webhookRoutes = await this.getWebhookHandlers();
        let queueKeep = queueSettings.queueKeep ?? true;

        let jobOpts = {
            ...buildRetentionPolicy(queueKeep, await getFailedJobRetention()),
            ...webhookRetryPolicy(queueSettings)
        };

        for (let route of webhookRoutes) {
            if (isDeliverableRoute(route) && typeof route.filterFn === 'function') {
                let canSend;
                let payload = structuredClone(originalPayload);

                payload._route = {
                    id: route.id
                };

                try {
                    canSend = await route.filterFn(payload);
                } catch (err) {
                    await this.storeLog(route.id, 'filter', payload, err.stack);

                    logger.error({ msg: 'Failed to execute webhook script', type: 'filter', webhook: route.id, err });
                }

                if (canSend && typeof route.mapFn === 'function') {
                    // A route with a map sends the mapped payload or nothing. mapFn logs its own
                    // failure and answers null for it, the same as a script opting out.
                    let mapping = await route.mapFn(payload);
                    if (mapping === null || typeof mapping === 'undefined' || mapping === false) {
                        logger.debug({ msg: 'Webhook map script returned no payload, skipping route', event, webhook: route.id });
                        canSend = false;
                    } else {
                        payload._route.mapping = mapping;
                    }
                }

                if (canSend && payload) {
                    let job = await notifyQueue.add(event, payload, jobOpts);

                    logger.trace({
                        msg: 'Triggered custom webhook route',
                        event,
                        webhook: route.id,
                        job: job.id
                    });

                    try {
                        await this.redis.hincrby(this.getWebhooksContentKey(), `${route.id}:tcount`, 1);
                    } catch (err) {
                        logger.warn({ msg: 'Failed to increment counter', event, webhook: route.id, err });
                    }
                }
            }
        }

        // MAIN webhook, unless its allowlist or inboxNewOnly already rules the event out. The worker
        // asks the same again at delivery, since either setting can change while a job waits
        if (defaultRouteTakes(event, originalPayload, queueSettings)) {
            await notifyQueue.add(event, originalPayload, jobOpts);
        }
    }
}

module.exports.webhooks = new WebhooksHandler({ redis });
module.exports.ENCRYPTED_ROUTE_FIELDS = ENCRYPTED_ROUTE_FIELDS;
