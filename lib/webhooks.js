'use strict';

const uuid = require('uuid');
const { redis, notifyQueue } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX, MESSAGE_NEW_NOTIFY } = require('./consts');
const { SubScript } = require('./sub-script');
const settings = require('./settings');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

class WebhooksHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;

        this.handlerCache = [];
        this.handlerCacheV = 0;
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

    async list(page, pageSize) {
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

        if (webhookIds.length <= startPos) {
            return response;
        }

        let keys = webhookIds.slice(startPos, startPos + pageSize).flatMap(id => [`${id}:meta`, `${id}:tcount`, `${id}:webhookErrorFlag`]);
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
                logger.error({ msg: 'Failed to process webhook error', entry: list[i + 2] && list[i + 2].toString('base64') });
            }

            try {
                let webhookMeta = msgpack.decode(entry);
                if (webhookErrorFlag && typeof webhookErrorFlag === 'object' && !Object.keys(webhookErrorFlag)) {
                    webhookErrorFlag = null;
                }
                response.webhooks.push(Object.assign(webhookMeta, { tcount, webhookErrorFlag }));
            } catch (err) {
                logger.error({ msg: 'Failed to process webhook', entry: entry.toString('base64') });
                continue;
            }
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
                [`${id}:meta`]: msgpack.encode(entry),
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

        let existingMeta = msgpack.decode(metaBuf);

        let entry = Object.assign(existingMeta, meta || {}, {
            id: existingMeta.id,
            created: existingMeta.created,
            updated: new Date().toISOString()
        });

        let updates = {
            [`${id}:meta`]: msgpack.encode(entry)
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
                logger.error({ msg: 'Failed to retrieve log line', webhook: id, entry: line && line.toString('base64') });
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
                meta = msgpack.decode(getResult[0]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', entry: getResult[0].toString('base64') });
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
                meta = msgpack.decode(getResult[0]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', entry: getResult[0].toString('base64') });
        }

        try {
            if (getResult[1]) {
                content = msgpack.decode(getResult[1]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', entry: getResult[1].toString('base64') });
        }

        v = Number(getResult[2] && getResult[2].toString()) || 0;

        try {
            if (getResult[3]) {
                webhookErrorFlag = JSON.parse(getResult[3].toString());
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process webhook', entry: getResult[3].toString('base64') });
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

    async getHandler(id) {
        let webhookData = await this.get(id);

        try {
            if (webhookData.content.fn) {
                webhookData.compiledFn = SubScript.create(`webhooks:filter:${id}`, webhookData.content.fn);
            } else {
                webhookData.compiledFn = false;
            }
        } catch (err) {
            await this.storeLog(id, 'filter', null, err.stack);

            logger.error({ msg: 'Compilation failed', type: 'filter', webhook: id, err });
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

                logger.error({ msg: 'Compilation failed', type: 'map', webhook: id, err });
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

                    logger.error({ msg: 'Exec failed', type: 'filter', webhook: webhookData.id, err });
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

                    logger.error({ msg: 'Exec failed', type: 'map', webhook: webhookData.id, err });
                    return null;
                }
            };
        }

        return webhookData;
    }

    async getWebhookHandlers() {
        let v = await this.redis.hget(this.getWebhooksContentKey(), 'v');
        v = Number(v) || 0;
        if (v !== this.handlerCacheV) {
            // changes detected
            v = this.handlerCacheV;

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
                    this.handlerCache.push(handler);
                } else {
                    // compare existing
                    let webhookV = await this.redis.hget(this.getWebhooksContentKey(), `${webhookId}:v`);
                    if (existing.v !== webhookV) {
                        // update
                        for (let i = this.handlerCache.length - 1; i >= 0; i--) {
                            if (webhookId === this.handlerCache[i].id) {
                                let handler = await this.getHandler(webhookId);
                                this.handlerCache[i] = handler;
                            }
                        }
                    }
                }
            }
        }

        return this.handlerCache;
    }

    async formatPayload(event, originalPayload) {
        // run all normalizations before sending the data

        const payload = pfStructuredClone(originalPayload);
        payload.eventId = payload.eventId || uuid.v4();

        if (event === MESSAGE_NEW_NOTIFY && payload && payload.data && payload.data.text) {
            // normalize text content
            let notifyText = await settings.get('notifyText');
            if (!notifyText) {
                // remove text content if any
                for (let key of Object.keys(payload.data.text)) {
                    if (!['id', 'encodedSize'].includes(key)) {
                        delete payload.data.text[key];
                    }
                }
                if (!Object.keys(payload.data.text).length) {
                    delete payload.data.text;
                }
            } else {
                let notifyTextSize = await settings.get('notifyTextSize');
                if (notifyTextSize) {
                    for (let textType of ['html', 'plain']) {
                        if (payload.data.text && typeof payload.data.text[textType] === 'string' && payload.data.text[textType].length > notifyTextSize) {
                            payload.data.text[textType] = payload.data.text[textType].substr(0, notifyTextSize);
                            payload.data.text.hasMore = true;
                        }
                    }
                }
            }
        }

        if (event === MESSAGE_NEW_NOTIFY && payload && payload.data && payload.data.headers) {
            // normalize headers
            let notifyHeaders = (await settings.get('notifyHeaders')) || [];
            if (!notifyHeaders.length) {
                delete payload.data.headers;
            } else if (!notifyHeaders.includes('*')) {
                // filter unneeded headers
                for (let header of Object.keys(payload.data.headers || {})) {
                    if (!notifyHeaders.includes(header.toLowerCase())) {
                        delete payload.data.headers[header];
                    }
                }
            }

            if (payload.data.headers && !Object.keys(payload.data.headers).length) {
                delete payload.data.headers;
            }
        }

        // remove attachment contents
        if (event === MESSAGE_NEW_NOTIFY && payload && payload.data && payload.data.attachments) {
            for (let attachment of payload.data.attachments) {
                if (attachment.content) {
                    delete attachment.content;
                }
            }
        }

        if (payload && payload.data && payload.data.text && payload.data.text._generatedHtml) {
            payload.data.text.html = payload.data.text._generatedHtml;

            delete payload.data.text._generatedHtml;
        }

        return payload;
    }

    async pushToQueue(event, originalPayload, opts = {}) {
        // custom webhoom routes
        let webhookRoutes = await this.getWebhookHandlers();
        let queueKeep = (await settings.get('queueKeep')) || true;

        for (let route of webhookRoutes) {
            if (route.enabled && route.targetUrl && typeof route.filterFn === 'function') {
                let canSend;
                let payload = pfStructuredClone(originalPayload);

                payload._route = {
                    id: route.id
                };

                try {
                    canSend = await route.filterFn(payload);
                } catch (err) {
                    await this.storeLog(route.id, 'filter', payload, err.stack);

                    logger.error({ msg: 'Exec failed', type: 'filter', webhook: route.id, err });
                }

                if (canSend) {
                    if (typeof route.mapFn === 'function') {
                        try {
                            payload._route.mapping = await route.mapFn(payload);
                        } catch (err) {
                            await this.storeLog(route.id, 'map', payload, err.stack);

                            logger.error({ msg: 'Exec failed', type: 'map', webhook: route.id, err });
                            canSend = false;
                        }
                    }
                }

                if (canSend && payload) {
                    if (opts.queueFlow) {
                        opts.queueFlow.push({
                            name: event,
                            data: payload,
                            queueName: 'notify'
                        });

                        logger.trace({
                            msg: 'Added custom webhook route to queue flow',
                            event,
                            webhook: route.id
                        });
                    } else {
                        let job = await notifyQueue.add(event, payload, {
                            removeOnComplete: queueKeep,
                            removeOnFail: queueKeep,
                            attempts: 10,
                            backoff: {
                                type: 'exponential',
                                delay: 5000
                            }
                        });

                        logger.trace({
                            msg: 'Triggered custom webhook route',
                            event,
                            webhook: route.id,
                            job: job.id
                        });
                    }

                    try {
                        await this.redis.hincrby(this.getWebhooksContentKey(), `${route.id}:tcount`, 1);
                    } catch (err) {
                        logger.error({ msg: 'Failed to increment counter', event, webhook: route.id, err });
                    }
                }
            }
        }

        if (!opts.routesOnly) {
            // MAIN webhook
            await notifyQueue.add(event, originalPayload, {
                removeOnComplete: queueKeep,
                removeOnFail: queueKeep,
                attempts: 10,
                backoff: {
                    type: 'exponential',
                    delay: 5000
                }
            });
        }
    }
}

module.exports.webhooks = new WebhooksHandler({ redis });
