'use strict';

// Per-token audit trail: which credential made which request, and whether it was allowed.
//
// EmailEngine already logs the token id on every API request line (workers/api.js binds it to the
// request logger), so the raw material existed - but answering "what has this token been doing" meant
// grepping the log stream, and `{prefix}tokens:access` keeps only the last use, overwritten each
// time. This makes the question answerable per credential.
//
// Off by default. It adds a write to the hot path of every authenticated request and most instances
// will never read it, so the compliance case is served by the log being available rather than by
// every deployment paying for it.

const { redis } = require('./db');
const logger = require('./logger');
const msgpack = require('./msgpack');
const settings = require('./settings');
const { REDIS_PREFIX } = require('./consts');
const { extractMultiError } = require('./redis-operations');

// How many entries to keep per token. A log of who read whose mail carries the sensitivity of the
// mail itself, so the default is low and the cap is a hard trim rather than a target.
const LOG_ENTRIES = Number(process.env.EENGINE_TOKEN_LOG_ENTRIES) || 200;

// How long a token's log survives its last use, in seconds. Refreshed on every write, so this bounds
// how long a log outlives the credential's activity rather than how long each entry lives - which is
// the useful bound, because a token nobody has used is a log nobody needs.
const LOG_AGE = Number(process.env.EENGINE_TOKEN_LOG_AGE) || 7 * 24 * 3600;

// The setting is read per request, and the request path already makes several Redis round trips, so
// a short in-process cache keeps the steady state at zero extra reads. The window is the longest a
// deployment waits for a change to the setting to take effect, per API worker.
const FLAG_CACHE_MS = 10 * 1000;

let flagCachedAt = 0;
let flagValue = false;

async function isEnabled() {
    const now = Date.now();
    if (now - flagCachedAt < FLAG_CACHE_MS) {
        return flagValue;
    }

    try {
        flagValue = !!(await settings.get('tokenAuditLog'));
    } catch (err) {
        // Never let a settings read decide a request. Failing closed here means "do not log", which
        // loses a record rather than refusing a call the token was entitled to make.
        flagValue = false;
    }
    flagCachedAt = now;

    return flagValue;
}

// Exposed so a test can drop the cache rather than wait it out
function resetFlagCache() {
    flagCachedAt = 0;
    flagValue = false;
}

function logKey(tokenId) {
    return `${REDIS_PREFIX}tokens:log:${tokenId}`;
}

/**
 * Records one request against a token, if the audit log is enabled.
 *
 * Deliberately not awaited by its callers: the entry is a record OF the request, not part of
 * serving it, so a slow or unavailable Redis must not add latency to a call that already succeeded.
 * The promise handles its own failure for the same reason - an unhandled rejection here would reach
 * the worker's global handler and kill it over a log line.
 *
 * A list rather than a Redis stream: the only reader is "show me this token's recent requests", which
 * a capped list answers directly, and it leaves the cheap last-use lookup in `{prefix}tokens:access`
 * that tokens.list() already reads alone.
 *
 * @param {Object} entry
 * @param {String} entry.tokenId - SHA-256 hash of the token, the same id tokens.list() reports
 * @param {String} [entry.ip] - calling address
 * @param {String} [entry.method] - HTTP method, or the surface name for SMTP and the IMAP proxy
 * @param {String} [entry.path] - request path, or the surface name
 * @param {String} [entry.action] - resolved permission action
 * @param {String} [entry.group] - resolved permission group
 * @param {String} [entry.account] - account the request addressed
 * @param {String} entry.status - 'allowed' or 'denied'
 * @param {String} [entry.reason] - why it was denied
 */
function record(entry) {
    if (!entry || !entry.tokenId) {
        return;
    }

    isEnabled()
        .then(async enabled => {
            if (!enabled) {
                return;
            }

            const key = logKey(entry.tokenId);

            // The route TEMPLATE, not the resolved URL - `/v1/account/{account}/messages` rather
            // than the request line. That is the deliberate boundary: the resolved URL would carry
            // search terms and message ids out of the query string into a second store with its own
            // retention, and the template plus the account answers what the credential reached.
            const stored = {
                time: Date.now(),
                ip: entry.ip || null,
                method: entry.method || null,
                path: entry.path || null,
                action: entry.action || null,
                group: entry.group || null,
                account: entry.account || null,
                status: entry.status,
                reason: entry.reason || null
            };

            const results = await redis
                .multi()
                .lpushBuffer(key, msgpack.encode(stored))
                .ltrim(key, 0, LOG_ENTRIES - 1)
                .expire(key, LOG_AGE)
                .exec();

            const err = extractMultiError(results);
            if (err) {
                throw err;
            }
        })
        .catch(err => logger.error({ msg: 'Failed to record a token audit entry', tokenId: entry.tokenId, err }));
}

/**
 * Reads a token's audit log, newest first.
 *
 * @param {String} tokenId - SHA-256 hash of the token
 * @param {Object} [opts]
 * @param {Number} [opts.page] - zero-based page
 * @param {Number} [opts.pageSize] - entries per page
 * @returns {Promise<Object>} { total, page, pages, entries }
 */
async function list(tokenId, opts) {
    const { page: rawPage, pageSize: rawPageSize } = opts || {};

    const page = Math.max(Number(rawPage) || 0, 0);
    const pageSize = Math.min(Math.max(Number(rawPageSize) || 20, 1), LOG_ENTRIES);

    const key = logKey(tokenId);
    const startPos = page * pageSize;

    const [total, encoded] = await Promise.all([redis.llen(key), redis.lrangeBuffer(key, startPos, startPos + pageSize - 1)]);

    const entries = [];
    for (const buf of encoded || []) {
        try {
            const decoded = msgpack.decode(buf);
            decoded.time = decoded.time ? new Date(decoded.time) : null;
            entries.push(decoded);
        } catch (err) {
            // One unreadable entry must not hide the rest of the trail
            logger.error({ msg: 'Failed to decode a token audit entry', tokenId, err });
        }
    }

    return {
        total,
        page,
        pages: Math.ceil(total / pageSize),
        entries
    };
}

// logKey is exported so lib/tokens.js can drop the log inside the same multi() that removes the
// token, rather than spelling the key a second time.
/**
 * Records an accepted request. Thin wrapper so the 'allowed'/'denied' vocabulary lives here rather
 * than being spelled at every call site in the two enforcement points.
 */
function allowed(entry) {
    record(Object.assign({ status: 'allowed' }, entry));
}

/**
 * Records a refused request, with the reason it was refused.
 */
function denied(entry, reason) {
    record(Object.assign({ status: 'denied', reason }, entry));
}

module.exports = { record, allowed, denied, list, logKey, resetFlagCache, LOG_ENTRIES };
