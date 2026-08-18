'use strict';

const { redis } = require('./db');
const crypto = require('crypto');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const { constantTimeEqual, matchesListQuery } = require('./tools');
const tokenAuditLog = require('./token-audit-log');

const SESS_PREFIX = 'sess_';

// Fields the listing search box matches on, and how many tokens one Redis command covers - a batch
// of ids per command rather than a command per token, in both the listing reads and the per-account
// delete. The bound matters twice over: a search over the whole instance would otherwise come back
// as one reply carrying every record on the server, and an id list spread as call arguments
// overflows the stack rather than failing cleanly once it is long enough.
const LIST_QUERY_FIELDS = ['id', 'description', 'account'];
const TOKEN_BATCH_SIZE = 1000;

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
    TOKEN_BATCH_SIZE,

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

    /**
     * Removes every access token bound to an account.
     *
     * Called from Account.delete(). Deleting an account used to unlink only its token index, which
     * left the token records themselves in the global hash - and a record there authenticates
     * regardless of whether the account it names still exists, so the credentials of a deleted
     * account kept working. Since an account ID can be registered again, they would even come back
     * pointed at whoever took the name.
     *
     * Owns the index too, rather than leaving it to the caller: it is the only mapping from an
     * account to its tokens, so it must outlive a failure here - otherwise the records it names are
     * live with nothing left pointing at them.
     *
     * @param {String} account - account ID
     * @returns {Promise<Number>} how many tokens the account index listed
     */
    async deleteForAccount(account) {
        let hashedTokens = await redis.smembers(`${REDIS_PREFIX}iat:${account}`);
        if (!hashedTokens || !hashedTokens.length) {
            return 0;
        }

        // The same three keys delete() removes for a single token, a batch of ids per command.
        //
        // UNLINK for the audit logs: each is a list of up to EENGINE_TOKEN_LOG_ENTRIES entries, and
        // freeing those inline would hold up every other worker - the same reason Account.delete()
        // unlinks throughout. SREM rather than dropping the index outright, so a token minted
        // between the read above and this write keeps its index entry instead of being left in the
        // hash with nothing pointing at it.
        //
        // A transaction, so the commands reach Redis as one block: a connection lost mid-send then
        // revokes nothing and leaves the index to try again from, rather than revoking some.
        let req = redis.multi();
        for (let pos = 0; pos < hashedTokens.length; pos += TOKEN_BATCH_SIZE) {
            let batch = hashedTokens.slice(pos, pos + TOKEN_BATCH_SIZE);
            req = req
                .hdel(`${REDIS_PREFIX}tokens`, ...batch)
                .hdel(`${REDIS_PREFIX}tokens:access`, ...batch)
                .unlink(...batch.map(hashedToken => tokenAuditLog.logKey(hashedToken)))
                .srem(`${REDIS_PREFIX}iat:${account}`, ...batch);
        }

        let res = await req.exec();

        for (let entry of res) {
            if (entry[0]) {
                throw entry[0];
            }
        }

        logger.info({ msg: 'Deleted the access tokens of an account', account, tokens: hashedTokens.length });

        return hashedTokens.length;
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

        // Byte order rather than localeCompare: the ids are hex, where the two agree, and in the
        // `all` listing this is every token on the instance - a locale-aware comparison over a list
        // that size costs more than the read it precedes.
        list = [].concat(list || []).sort((a, b) => (a < b ? 1 : a > b ? -1 : 0));

        let response = {
            account: account || null,
            total: list.length,
            pages: Math.ceil(list.length / pageSize),
            page,
            tokens: []
        };

        // Without a query only the visible page's records are read; with one every record has to be
        // read, because the fields the filter matches on live on the record and nowhere else.
        if (!query) {
            list = list.slice(startPos, startPos + pageSize);
        }

        if (!list.length) {
            return response;
        }

        let entries = [];
        let reaped = 0;

        // Read in batches, and keep only what the query matches. A search reads every token on the
        // instance: as a single read that was one reply carrying every record, with all of them held
        // decoded until the filter ran at the end. The search is still O(every token) - nothing
        // indexes the fields it matches on - but what is in memory at once is now one batch plus the
        // matches.
        for (let pos = 0; pos < list.length; pos += TOKEN_BATCH_SIZE) {
            let batch = list.slice(pos, pos + TOKEN_BATCH_SIZE);
            let records = await redis.hmgetBuffer(`${REDIS_PREFIX}tokens`, batch);

            for (let i = 0; i < batch.length; i++) {
                let tokenHash = batch[i];
                let encoded = records && records[i];
                if (!encoded) {
                    continue;
                }

                try {
                    let tokenData = msgpack.decode(encoded);

                    // An expired token cannot authenticate, so listing it is noise. This
                    // is also where a minted-but-never-used token finally gets collected.
                    if (tokenData.expires && Date.now() >= tokenData.expires) {
                        reapExpiredToken(tokenHash, tokenData.account);
                        reaped++;
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
                    let entry = Object.assign({ id: tokenHash, account: null }, tokenData);

                    if (query && !matchesListQuery(entry, LIST_QUERY_FIELDS, query)) {
                        continue;
                    }

                    entries.push(entry);
                } catch (err) {
                    logger.error({ msg: 'Failed to process token data', hash: tokenHash, err });
                }
            }
        }

        if (query) {
            // The matches are what the caller is paging through, so they are what `total` counts -
            // the same answer filterListPage() gave when it did the filtering here.
            response.total = entries.length;
            entries = entries.slice(startPos, startPos + pageSize);
        } else {
            response.total = Math.max(0, response.total - reaped);
        }

        // Last-use records for the returned page only. They live in a second hash and nothing
        // filters, sorts or counts on them, so reading one alongside every record above spent a
        // command per token on data that at most one page of tokens would ever show.
        if (entries.length) {
            let accessRecords = await redis.hmgetBuffer(
                `${REDIS_PREFIX}tokens:access`,
                entries.map(entry => entry.id)
            );

            for (let i = 0; i < entries.length; i++) {
                let encoded = accessRecords && accessRecords[i];
                if (encoded) {
                    entries[i].access = decodeAccessData(encoded, entries[i].id);
                }
            }
        }

        response.tokens = entries;

        // Derived last, from whichever total the branches above settled on. A count taken before the
        // loop describes a listing that no longer exists, because the loop reaps expired tokens as
        // it goes - three tokens with the first expired reported `{total: 2, pages: 3}`. Only the
        // records actually read are inspected, so an expired token beyond this call's reach is still
        // counted until a later call gets to it; what this guarantees is that `pages` and `total` in
        // one response are two views of one number.
        response.pages = Math.ceil(response.total / pageSize);

        return response;
    }
};
