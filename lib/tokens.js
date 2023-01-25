'use strict';

const { redis } = require('./db');
const crypto = require('crypto');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');

module.exports = {
    async provision(opts) {
        opts = opts || {};
        const { account, restrictions, ip, remoteAddress, description, metadata, scopes, nolog } = opts;

        const token = crypto.randomBytes(32);
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        let now = new Date();

        let tokenData = {
            created: now.getTime()
        };

        if (account) {
            tokenData.account = account;
        }

        if (ip) {
            tokenData.ip = ip;
        }

        if (remoteAddress) {
            tokenData.remoteAddress = remoteAddress;
        }

        if (scopes) {
            tokenData.scopes = scopes;
        }

        if (description) {
            tokenData.description = description;
        }

        if (restrictions) {
            tokenData.restrictions = restrictions;
        }

        if (metadata) {
            tokenData.metadata = metadata;
        }

        let req = redis
            .multi()
            .hsetBuffer(`${REDIS_PREFIX}tokens`, hashedToken, msgpack.encode(tokenData))
            .hsetBuffer(`${REDIS_PREFIX}tokens:access`, hashedToken, msgpack.encode({}));

        if (account) {
            req = req.sadd(`${REDIS_PREFIX}iat:${account}`, hashedToken);
        } else {
            // root token
            req = req.sadd(`${REDIS_PREFIX}iat`, hashedToken);
        }

        let res = await req.exec();

        for (let entry of res) {
            if (entry[0]) {
                throw entry[0];
            }
        }

        if (!nolog) {
            logger.info(Object.assign({}, tokenData, { hash: hashedToken, msg: 'Provisioned new access token' }));
        }

        return token.toString('hex');
    },

    async get(token, hashed, opts) {
        opts = opts || {};

        if (!/^[0-9a-f]{64}$/i.test(token)) {
            let err = new Error('Invalid token format');
            err.code = 'InvalidToken';
            throw err;
        }

        const hashedToken = hashed ? token : crypto.createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex');

        let tokenDataEncoded = await redis.hgetBuffer(`${REDIS_PREFIX}tokens`, hashedToken);
        if (!tokenDataEncoded) {
            let err = new Error('Unknown token');
            err.code = 'UnknownToken';
            throw err;
        }

        let tokenData = msgpack.decode(tokenDataEncoded);

        if (opts.log) {
            // log access time
            let accessData = { time: Date.now(), ip: opts.remoteAddress || null };
            await redis.hsetBuffer(`${REDIS_PREFIX}tokens:access`, hashedToken, msgpack.encode(accessData));
        }

        tokenData.created = new Date(tokenData.created);

        return Object.assign({ id: hashedToken }, tokenData);
    },

    async delete(token, opts) {
        if (!/^[0-9a-f]{64}$/i.test(token)) {
            let err = new Error('Invalid token format');
            err.code = 'InvalidToken';
            throw err;
        }

        opts = opts || {};

        let tokenData;
        try {
            tokenData = await module.exports.get(token, true);
        } catch (err) {
            try {
                tokenData = await module.exports.get(token);
            } catch (err) {
                return false;
            }
        }

        let req = redis.multi().hdel(`${REDIS_PREFIX}tokens`, tokenData.id).hdel(`${REDIS_PREFIX}tokens:access`, tokenData.id);
        if (tokenData.account) {
            req = req.srem(`${REDIS_PREFIX}iat:${tokenData.account}`, tokenData.id);
        } else {
            // root token
            req = req.srem(`${REDIS_PREFIX}iat`, tokenData.id);
        }

        let res = await req.exec();

        for (let entry of res) {
            if (entry[0]) {
                throw entry[0];
            }
        }

        logger.info(Object.assign({}, tokenData, { msg: 'Deleted an access token', remoteAddress: opts.remoteAddress }));

        return true;
    },

    async getRawData(token) {
        if (!/^[0-9a-f]{64}$/i.test(token)) {
            let err = new Error('Invalid token format');
            err.code = 'InvalidToken';
            throw err;
        }

        let tokenData;
        try {
            tokenData = await module.exports.get(token, true);
        } catch (err) {
            try {
                tokenData = await module.exports.get(token);
            } catch (err) {
                return false;
            }
        }

        return tokenData;
    },

    async setRawData(tokenData) {
        if (!/^[0-9a-f]{64}$/i.test(tokenData.id)) {
            let err = new Error('Invalid token format');
            err.code = 'InvalidToken';
            throw err;
        }

        let hashedToken = tokenData.id;
        delete tokenData.id;

        try {
            let existingTokenData = await module.exports.get(hashedToken, true);
            if (existingTokenData) {
                return false;
            }
        } catch (err) {
            // ignore
        }

        tokenData.created = Date.now();

        let req = redis
            .multi()
            .hsetBuffer(`${REDIS_PREFIX}tokens`, hashedToken, msgpack.encode(tokenData))
            .hsetBuffer(`${REDIS_PREFIX}tokens:access`, hashedToken, msgpack.encode({}));

        if (tokenData.account) {
            req = req.sadd(`${REDIS_PREFIX}iat:${tokenData.account}`, hashedToken);
        } else {
            // root token
            req = req.sadd(`${REDIS_PREFIX}iat`, hashedToken);
        }

        let res = await req.exec();

        for (let entry of res) {
            if (entry[0]) {
                throw entry[0];
            }
        }

        return tokenData;
    },

    async list(account, page, pageSize) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let list;
        if (account) {
            list = await redis.smembers(`${REDIS_PREFIX}iat:${account}`);
        } else {
            list = await redis.smembers(`${REDIS_PREFIX}iat`);
        }

        list = [].concat(list || []).sort((a, b) => -a.localeCompare(b));

        let response = {
            account: account || null,
            total: list.length,
            pages: Math.ceil(list.length / pageSize),
            page,
            tokens: []
        };

        if (!list || !list.length || list.length <= startPos) {
            return response;
        }

        list = list.slice(startPos, startPos + pageSize);

        let req = redis.multi();

        for (let tokenHash of list) {
            req = req.hgetBuffer(`${REDIS_PREFIX}tokens`, tokenHash);
            req = req.hgetBuffer(`${REDIS_PREFIX}tokens:access`, tokenHash);
        }

        let detailList = await req.exec();

        let lastEntry = false;
        for (let i = 0; i < detailList.length; i++) {
            let entry = detailList[i];
            if (i % 2 === 0) {
                lastEntry = false;
                if (entry[1]) {
                    try {
                        let tokenData = msgpack.decode(entry[1]);
                        tokenData.created = new Date(tokenData.created);
                        lastEntry = Object.assign({ id: list[response.tokens.length] }, tokenData);
                        response.tokens.push(lastEntry);
                    } catch (err) {
                        logger.error({ msg: 'Failed to process token data', hash: list[response.tokens.length], err });
                    }
                }
            } else if (lastEntry && entry[1]) {
                try {
                    let accessData = msgpack.decode(entry[1]);
                    accessData.time = accessData.time ? new Date(accessData.time) : null;
                    lastEntry.access = accessData;
                } catch (err) {
                    logger.error({ msg: 'Failed to process token data', hash: list[i], err });
                }
            }
        }

        return response;
    }
};
