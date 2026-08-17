'use strict';

const { redis } = require('./db');
const crypto = require('crypto');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const { constantTimeEqual, filterListPage } = require('./tools');

const SESS_PREFIX = 'sess_';

// Best-effort removal of an expired token record. Fired from both of the places that can
// notice the expiry - get(), when someone presents the token, and list(), when someone views
// the token list. Both are needed: a token that is minted and then never used is never
// resolved through get(), so before list() also reaped, such a record sat in Redis forever
// even though it could no longer authenticate.
//
// Done with raw commands rather than through delete(), which resolves the token through
// get() and would recurse back into the expiry check.
function reapExpiredToken(hashedToken, account) {
    redis
        .multi()
        .hdel(`${REDIS_PREFIX}tokens`, hashedToken)
        .hdel(`${REDIS_PREFIX}tokens:access`, hashedToken)
        .srem(account ? `${REDIS_PREFIX}iat:${account}` : `${REDIS_PREFIX}iat`, hashedToken)
        .exec()
        .catch(err => logger.error({ msg: 'Failed to clean up an expired access token', hash: hashedToken, err }));
}

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
     * Deliberately unguarded. The admin-password requirement belongs to the routes, not here,
     * because only they can tell whether the caller actually presented a credential. Gating this
     * function instead refused headless deployments too (EENGINE_PREPARED_TOKEN with no admin
     * password is a supported configuration), and the CLI needs shell access anyway.
     *
     * Both HTTP callers gate themselves: POST /admin/tokens/new unconditionally, since
     * `server.auth.default('session')` leaves it open while authData is unset; POST /v1/token only
     * for the `preauth` caller that the `disableTokens` setting lets through without a credential.
     *
     * @param {Object} opts - Token options. May originate from a request payload.
     * @returns {String} The token value (only ever returned here - it is stored hashed)
     */
    async provision(opts) {
        opts = opts || {};
        const { account, restrictions, permissions, ip, remoteAddress, description, metadata, scopes, nolog, expires } = opts;

        const token = crypto.randomBytes(32);
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        let now = new Date();

        let tokenData = {
            created: now.getTime()
        };

        // Optional lifetime. Tokens live in a Redis hash, whose fields cannot carry their
        // own TTL, so expiry is stored on the record and enforced in get() below - which
        // is the single validation point for every token consumer.
        if (expires) {
            const expiresAt = expires instanceof Date ? expires.getTime() : Number(expires);
            // Reject rather than coerce: Number('soon') is NaN, and NaN is falsy at the
            // check in get(), so a malformed value would silently mean "never expires" -
            // fail-open on the one field that limits a credential's lifetime.
            if (!Number.isFinite(expiresAt)) {
                let err = new Error('Invalid token expiry');
                err.code = 'InvalidExpiry';
                throw err;
            }
            tokenData.expires = expiresAt;
        }

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

        // Narrowing below the scope. Absent means "not narrowed", which is every token issued
        // before this existed, so the field is only written when it was asked for - see the absent
        // vs empty vs malformed distinction in lib/token-permissions.js.
        if (permissions) {
            tokenData.permissions = permissions;
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

        // Expiry check. This is the only place tokens are validated (lib/auth-token.js for
        // SMTP/IMAP-proxy auth and the api-token strategy in workers/api.js are the two
        // callers), so an expired token stops working everywhere at once.
        //
        // `allowExpired` exists for delete(), which resolves a token through this function:
        // without it an expired token could never be removed, only accumulate.
        if (tokenData.expires && Date.now() >= tokenData.expires && !opts.allowExpired) {
            reapExpiredToken(hashedToken, tokenData.account);

            let err = new Error('Expired token');
            err.code = 'ExpiredToken';
            throw err;
        }

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
            // allowExpired: an expired token must still be removable and inspectable,
            // otherwise it could only accumulate
            tokenData = await module.exports.get(token, true, { allowExpired: true });
        } catch (err) {
            try {
                tokenData = await module.exports.get(token, false, { allowExpired: true });
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
            // allowExpired: an expired token must still be removable and inspectable,
            // otherwise it could only accumulate
            tokenData = await module.exports.get(token, true, { allowExpired: true });
        } catch (err) {
            try {
                tokenData = await module.exports.get(token, false, { allowExpired: true });
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

                        // An expired token cannot authenticate, so listing it is noise. This
                        // is also where a minted-but-never-used token finally gets collected.
                        if (tokenData.expires && Date.now() >= tokenData.expires) {
                            reapExpiredToken(tokenHash, tokenData.account);
                            response.total = Math.max(0, response.total - 1);
                            continue;
                        }

                        tokenData.created = new Date(tokenData.created);
                        if (tokenData.expires) {
                            tokenData.expires = new Date(tokenData.expires);
                        }
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
