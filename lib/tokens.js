'use strict';

const { redis } = require('./db');
const crypto = require('crypto');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const { constantTimeEqual, filterListPage } = require('./tools');
const tokenAuditLog = require('./token-audit-log');

const SESS_PREFIX = 'sess_';

/**
 * The id a token is listed and stored under: the SHA-256 of its raw bytes.
 *
 * Derivable from the token value, which is why provision() does not have to return it - but only if
 * you know the hex string is decoded to bytes before hashing rather than hashed as text. Exported so
 * callers get that right by construction instead of reimplementing it.
 *
 * @param {String} token - the 64-char hex token value
 * @returns {String} SHA-256 hex id
 */
function tokenId(token) {
    return crypto.createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex');
}

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

// Reads one `{prefix}tokens:access` value into the shape both readers publish. Shared because the
// listing and the single-token getter feed the same joi schema and had already drifted: the listing
// assigned the decoded object as-is, so a token that had never authenticated came back as `{time:
// null}` with no `ip` key at all, and the admin view carries a `|| {}` guard for the case where the
// field is missing entirely. One shape means the getter's promise to match the listing is true.
function decodeAccessData(encoded, hashedToken) {
    let accessData = {};

    if (encoded) {
        try {
            accessData = msgpack.decode(encoded);
        } catch (err) {
            // An unreadable last-use entry must not fail the read of the token it belongs to
            logger.error({ msg: 'Failed to process token access data', hash: hashedToken, err });
        }
    }

    return { time: accessData.time ? new Date(accessData.time) : null, ip: accessData.ip || null };
}

module.exports = {
    tokenId,

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
     * `server.auth.default('session')` leaves it open while authData is unset; POST /v1/tokens only
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

        const hashedToken = hashed ? token : tokenId(token);

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

    /**
     * Last-use record for a token, in the shape the listings report it.
     *
     * Kept apart from get(), which every authenticated request runs: the last-use record lives in a
     * second hash and nothing on the auth path reads it, so folding it in would put an extra Redis
     * round trip on every API call to serve one page.
     *
     * @param {String} tokenId - SHA-256 hash of the token, the id the listings report
     * @returns {Promise<{time: (Date|null), ip: (String|null)}>}
     */
    async getAccess(tokenId) {
        return decodeAccessData(await redis.hgetBuffer(`${REDIS_PREFIX}tokens:access`, tokenId), tokenId);
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

        // The audit log goes with the token. It describes a credential that no longer exists, so
        // keeping it would outlive the thing it is a record of - and the key is named after the
        // token id, so nothing would ever collect it.
        let req = redis
            .multi()
            .hdel(`${REDIS_PREFIX}tokens`, tokenData.id)
            .hdel(`${REDIS_PREFIX}tokens:access`, tokenData.id)
            .del(tokenAuditLog.logKey(tokenData.id));
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

    /**
     * Lists tokens.
     *
     * @param {String} [account] - list tokens bound to this account
     * @param {Number} [page] - zero-based page
     * @param {Number} [pageSize] - entries per page
     * @param {String} [query] - filter on id, description or account
     * @param {Object} [opts]
     * @param {Boolean} [opts.all] - every token on the instance, bound or not. Reads the token hash
     *   directly rather than walking one index per account: the account is stored on each record, so
     *   the union is already there, and enumerating accounts would be a round trip each.
     */
    async list(account, page, pageSize, query, opts) {
        page = Math.max(Number(page) || 0, 0);
        pageSize = Math.max(Number(pageSize) || 20, 1);

        let startPos = page * pageSize;

        let list;
        if (opts && opts.all) {
            list = await redis.hkeys(`${REDIS_PREFIX}tokens`);
        } else if (account) {
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

        // A pipeline rather than a transaction: this is a read, so it needs no atomicity, and the
        // `all` listing plus a query reads every token on the instance in one go. Inside MULTI that
        // is a single atomic block during which Redis serves nobody else - including the IMAP and
        // webhook workers on the same server - for as long as it takes.
        let req = redis.pipeline();

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
                        // `account` is absent on the record for an unbound token, so it is filled in
                        // explicitly: a listing that mixes bound and unbound tokens should report one
                        // shape, not two, and `null` is the answer to "which account" for a token
                        // that is not bound to one.
                        lastEntry = Object.assign({ id: tokenHash, account: null }, tokenData);
                        response.tokens.push(lastEntry);
                    } catch (err) {
                        logger.error({ msg: 'Failed to process token data', hash: tokenHash, err });
                    }
                }
            } else if (lastEntry && entry[1]) {
                lastEntry.access = decodeAccessData(entry[1], tokenHash);
            }
        }

        if (query) {
            let paged = filterListPage(response.tokens, ['id', 'description', 'account'], query, startPos, pageSize);
            response.tokens = paged.entries;
            response.total = paged.total;
        }

        // Derived last, from whichever total survived. The loop above reaps expired tokens and
        // decrements `total` as it goes, so a count taken before it describes a listing that no
        // longer exists - three tokens with the first expired reported `{total: 2, pages: 3}`. Only
        // the visible page is inspected, so an expired token further along is still counted until a
        // later call reaches it; what this guarantees is that `pages` and `total` in one response
        // are two views of one number. Same formula filterListPage() applies to the filtered set.
        response.pages = Math.ceil(response.total / pageSize);

        return response;
    }
};
