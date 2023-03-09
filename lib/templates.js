'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');

class TemplateHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;
    }

    getTemplatesIndexKey(account) {
        account = account || '';
        return `${REDIS_PREFIX}tpl:${account}:i`;
    }

    getTemplatesContentKey(account) {
        account = account || '';
        return `${REDIS_PREFIX}tpl:${account}:c`;
    }

    getSettingsKey() {
        return `${REDIS_PREFIX}settings`;
    }

    async list(account, page, pageSize) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let templateIds = await this.redis.smembers(this.getTemplatesIndexKey(account));
        templateIds = [].concat(templateIds || []).sort((a, b) => -a.localeCompare(b));

        let response = {
            account: account || null,
            total: templateIds.length,
            pages: Math.ceil(templateIds.length / pageSize),
            page,
            templates: []
        };

        if (templateIds.length <= startPos) {
            return response;
        }

        let keys = templateIds.slice(startPos, startPos + pageSize).flatMap(id => [`${id}:meta`]);
        let list = await this.redis.hmgetBuffer(this.getTemplatesContentKey(account), keys);
        for (let entry of list) {
            try {
                let templateMeta = msgpack.decode(entry);
                response.templates.push(templateMeta);
            } catch (err) {
                logger.error({ msg: 'Failed to process template', entry: entry.toString('base64') });
                continue;
            }
        }

        return response;
    }

    async generateId(account) {
        let idNum = await this.redis.hincrby(this.getSettingsKey(), 'idcount', 1);

        let idBuf = Buffer.alloc(8 + 4);
        idBuf.writeBigUInt64BE(BigInt(Date.now()), 0);
        idBuf.writeUInt32BE(idNum, 8);

        const id = Buffer.concat([idBuf, Buffer.from(account || '')]).toString('base64url');

        return id;
    }

    unpackId(id) {
        let idBuf = Buffer.from(id, 'base64');
        return {
            counter: idBuf.readUInt32BE(8),
            created: new Date(Number(idBuf.readBigUInt64BE(0))).toISOString(),
            account: idBuf.subarray(4 + 8).toString()
        };
    }

    async create(account, meta, content) {
        const id = await this.generateId(account);

        let entry = Object.assign({ id: null }, meta || {}, {
            id,
            created: new Date().toISOString()
        });

        let insertResult = await this.redis
            .multi()
            .sadd(this.getTemplatesIndexKey(account), id)
            .hmset(this.getTemplatesContentKey(account), {
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
            account: account || null,
            id
        };
    }

    async update(id, meta, content) {
        let idData = this.unpackId(id);
        const account = idData.account || null;

        let metaBuf = await this.redis.hgetBuffer(this.getTemplatesContentKey(account), `${id}:meta`);
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

        let insertResult = await this.redis.multi().sadd(this.getTemplatesIndexKey(account), id).hmset(this.getTemplatesContentKey(account), updates).exec();

        let hasError = (insertResult[0] && insertResult[0][0]) || (insertResult[1] && insertResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        return {
            updated: true,
            account: account || null,
            id
        };
    }

    async get(id) {
        let idData = this.unpackId(id);
        const account = idData.account || null;

        let getResult = await this.redis.hmgetBuffer(this.getTemplatesContentKey(account), [`${id}:meta`, `${id}:content`]);
        if (!getResult || getResult.length !== 2 || !getResult[0] || !getResult[1]) {
            return false;
        }

        let meta, content;
        try {
            if (getResult[0]) {
                meta = msgpack.decode(getResult[0]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process template', entry: getResult[0].toString('base64') });
        }

        try {
            if (getResult[1]) {
                content = msgpack.decode(getResult[1]);
            }
        } catch (err) {
            logger.error({ msg: 'Failed to process template', entry: getResult[1].toString('base64') });
        }

        return Object.assign(
            {
                account: account || null
            },
            meta,
            { content }
        );
    }

    async del(id) {
        let idData = this.unpackId(id);
        const account = idData.account || null;

        let deleteResult = await this.redis
            .multi()
            .srem(this.getTemplatesIndexKey(account), id)
            .hdel(this.getTemplatesContentKey(account), [`${id}:meta`, `${id}:content`])
            .exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]);
        if (hasError) {
            throw hasError;
        }

        let deletedDocs = ((deleteResult[0] && deleteResult[0][1]) || 0) + ((deleteResult[1] && deleteResult[1][1]) || 0);

        return {
            deleted: deletedDocs === 3, // any other count means something went wrong
            account: account || null,
            id
        };
    }

    async flush(account) {
        let deleteResult = await this.redis
            .multi()
            .del(this.getTemplatesIndexKey(account))
            .hget(this.getTemplatesContentKey(account), 'id')
            .del(this.getTemplatesContentKey(account))
            .exec();

        let hasError = (deleteResult[0] && deleteResult[0][0]) || (deleteResult[1] && deleteResult[1][0]) || (deleteResult[2] && deleteResult[2][0]);
        if (hasError) {
            throw hasError;
        }

        let idVal = deleteResult[1][1];
        if (idVal) {
            await this.redis.hset(this.getTemplatesContentKey(account), 'id', idVal);
        }

        return {
            flushed: true, // any other count means something went wrong
            account: account || null
        };
    }
}

module.exports.templates = new TemplateHandler({ redis });
