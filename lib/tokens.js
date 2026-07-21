'use strict';

const { redis } = require('./db');
const crypto = require('crypto');
const msgpack = require('msgpack5')();
const Boom = require('@hapi/boom');
const logger = require('./logger');
const settings = require('./settings');
const { REDIS_PREFIX } = require('./consts');
const { constantTimeEqual, filterListPage } = require('./tools');

const SESS_PREFIX = 'sess_';

module.exports = {
    async getSessionToken(sessionId, account, ttl) {
        const token = crypto.randomBytes(32);
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const signature = crypto.createHmac('sha256', sessionId).update(token).digest('hex');

        const key = `${REDIS_PREFIX}sess:token:${hashedToken}`;

        const results = await redis
            .multi()
            .set(key, signature + ':' + account)
            .expire(key, ttl)
            .exec();

        // Check for errors
        for (const [err] of results) {
            if (err) throw err;
        }

        return SESS_PREFIX + token.toString('hex');
    },

    async validateSessionToken(sessionId, token, expectedAccount, ttl) {
        // Validate token format: prefix + 64 hex chars (32 bytes = 64 hex chars)
        if (!token || typeof token !== 'string') {
            return false;
        }

        if (!token.startsWith(SESS_PREFIX)) {
            return false;
        }

        const hexPart = token.substring(SESS_PREFIX.length);

        // Validate hex part: must be exactly 64 characters and valid hex
        if (hexPart.length !== 64 || !/^[0-9a-f]{64}$/i.test(hexPart)) {
            return false;
        }

        // Now we know it's valid format, proceed with validation
        const tokenBuffer = Buffer.from(hexPart, 'hex');
        const hashedToken = crypto.createHash('sha256').update(tokenBuffer).digest('hex');
        const expectedSignature = crypto.createHmac('sha256', sessionId).update(tokenBuffer).digest('hex');

        const key = `${REDIS_PREFIX}sess:token:${hashedToken}`;

        const results = await redis.multi().get(key).expire(key, ttl).exec();

        const [[errGet, storedSignatureValue], [errExpire]] = results;

        if (errGet || errExpire) {
            throw errGet || errExpire;
        }

        const [storedSignature, storedAccount] = storedSignatureValue.split(':');

        if (!storedSignature || !constantTimeEqual(storedSignature, expectedSignature)) {
            // Delete invalid tokens
            await redis.del(key);
            return false;
        }

        if (storedAccount && expectedAccount !== storedAccount) {
            // Delete invalid tokens
            await redis.del(key);
            return false;
        }

        return true;
    },

    /**
     * Provisions a new access token.
     *
     * @param {Object} opts - Token options. May originate from a request payload.
     * @param {Object} [context] - Caller context. Deliberately a SEPARATE argument from `opts`,
     *   because POST /v1/token spreads `request.payload` into `opts` - anything honoured there is
     *   reachable by an unauthenticated caller if a route is ever validated with `allowUnknown`.
     * @param {Boolean} [context.allowWithoutAdminAuth] - Bypass the admin-password requirement.
     * @returns {String} The token value (only ever returned here - it is stored hashed)
     */
    async provision(opts, { allowWithoutAdminAuth } = {}) {
        opts = opts || {};
        const { account, restrictions, ip, remoteAddress, description, metadata, scopes, nolog } = opts;

        // Nothing invalidates access tokens when the first admin password is set, so a token minted
        // while the instance was unprotected would outlive that window silently. Mirrors the
        // condition gating `server.auth.default('session')` in workers/api.js.
        //
        // The CLI is exempt - reaching it needs shell access, which already grants more than a
        // token would. setRawData() is likewise unguarded, keeping EENGINE_PREPARED_TOKEN working.
        if (!allowWithoutAdminAuth) {
            const authData = await settings.get('authData');
            if (!authData) {
                throw Boom.forbidden('Can not provision an access token before an admin password has been set');
            }
        }

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

    async list(account, page, pageSize, query) {
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

        // Without a query only the visible page's details are fetched; with a query
        // all details are loaded so the filter can run before pagination
        if (!query) {
            list = list.slice(startPos, startPos + pageSize);
        }

        if (!list.length) {
            return response;
        }

        let req = redis.multi();

        for (let tokenHash of list) {
            req = req.hgetBuffer(`${REDIS_PREFIX}tokens`, tokenHash);
            req = req.hgetBuffer(`${REDIS_PREFIX}tokens:access`, tokenHash);
        }

        let detailList = await req.exec();

        let lastEntry = false;
        for (let i = 0; i < detailList.length; i++) {
            let entry = detailList[i];
            // Each token occupies two consecutive multi results (data + access info)
            let tokenHash = list[Math.floor(i / 2)];
            if (i % 2 === 0) {
                lastEntry = false;
                if (entry[1]) {
                    try {
                        let tokenData = msgpack.decode(entry[1]);
                        tokenData.created = new Date(tokenData.created);
                        lastEntry = Object.assign({ id: tokenHash }, tokenData);
                        response.tokens.push(lastEntry);
                    } catch (err) {
                        logger.error({ msg: 'Failed to process token data', hash: tokenHash, err });
                    }
                }
            } else if (lastEntry && entry[1]) {
                try {
                    let accessData = msgpack.decode(entry[1]);
                    accessData.time = accessData.time ? new Date(accessData.time) : null;
                    lastEntry.access = accessData;
                } catch (err) {
                    logger.error({ msg: 'Failed to process token data', hash: tokenHash, err });
                }
            }
        }

        if (query) {
            let paged = filterListPage(response.tokens, ['id', 'description', 'account'], query, startPos, pageSize);
            response.tokens = paged.entries;
            response.total = paged.total;
            response.pages = paged.pages;
        }

        return response;
    }
};
