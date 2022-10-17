'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');

class WebhooksHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;
    }

    getWebhooksIndexKey() {
        return `${REDIS_PREFIX}wh:i`;
    }

    getWebhooksContentKey() {
        return `${REDIS_PREFIX}wh:c`;
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

        let keys = webhookIds.slice(startPos, startPos + pageSize).flatMap(id => [`${id}:meta`]);
        let list = await this.redis.hmgetBuffer(this.getWebhooksContentKey(), keys);
        for (let entry of list) {
            try {
                let webhookMeta = msgpack.decode(entry);
                response.webhooks.push(webhookMeta);
            } catch (err) {
                logger.error({ msg: 'Failed to process webhook', entry: entry.toString('base64') });
                continue;
            }
        }

        return response;
    }

    async generateId() {
        let idNum = await this.redis.hincrby(this.getWebhooksContentKey(), 'id', 1);

        let idBuf = Buffer.alloc(8 + 4);
        idBuf.writeBigUInt64BE(BigInt(Date.now()), 0);
        idBuf.writeUInt32BE(idNum, 8);

        return idBuf.toString('base64url');
    }

    unpackId(id) {
        let idBuf = Buffer.from(id, 'base64');
        return {
            counter: idBuf.readUInt32BE(8),
            created: new Date(Number(idBuf.readBigUInt64BE(0))).toISOString()
        };
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
                [`${id}:content`]: msgpack.encode(content)
            })
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

        let insertResult = await this.redis.multi().sadd(this.getWebhooksIndexKey(), id).hmset(this.getWebhooksContentKey(), updates).exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        return {
            updated: true,
            id
        };
    }

    async get(id) {
        let getResult = await this.redis.hmgetBuffer(this.getWebhooksContentKey(), [`${id}:meta`, `${id}:content`]);
        if (!getResult || getResult.length !== 2 || !getResult[0] || !getResult[1]) {
            return false;
        }

        let meta, content;
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

        return Object.assign({}, meta, { content });
    }

    async del(id) {
        let deleteResult = await this.redis
            .multi()
            .srem(this.getWebhooksIndexKey(), id)
            .hdel(this.getWebhooksContentKey(), [`${id}:meta`, `${id}:content`])
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
}

module.exports.webhooks = new WebhooksHandler({ redis });
