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
//
// A recent-activity view, not a tamper-evident trail. One capped list holds a token's allowed and
// denied requests together, so a holder that keeps making permitted calls eventually pushes its own
// refusals off the end. That is deliberate - splitting the two would double the read path to protect
// a record that is not the authoritative one anyway: both enforcement points write every refusal to
// the application log as well, and that stream is the one an instance ships off the box. What this
// module adds is being able to ask the question per credential instead of grepping for a token id.

const { redis } = require('./db');
const logger = require('./logger');
const msgpack = require('./msgpack');
const settings = require('./settings');
const { REDIS_PREFIX, MAX_ACCOUNT_ID_LENGTH } = require('./consts');
const { extractMultiError } = require('./redis-operations');

// Both overrides below are whole counts that have to be at least 1, and anything else falls back to
// the default rather than being clamped towards it - "0" is not a request for the smallest possible
// log, it is a value this module has no reading for. Each has its own way of going wrong: the entry
// cap floors the log route's `pageSize` ceiling, so a value below 1 left `min(1).max(0)` on the
// query schema and no request could satisfy it, and Redis DELETES a key given a non-positive
// EXPIRE, so a negative age would drop each entry in the transaction that wrote it.
function positiveInt(value, fallback) {
    const parsed = Math.floor(Number(value));
    return Number.isFinite(parsed) && parsed >= 1 ? parsed : fallback;
}

// How many entries to keep per token. The cap is a hard trim rather than a target, and it is what
// bounds the whole feature: every write trims, so total storage is a function of how many tokens are
// in use rather than of request volume. A full log of typical entries costs roughly 170KB of Redis
// per token, so a thousand active tokens cost about 170MB - entries carrying a maximum-length
// account run some three times that. Raise it against those figures, and against the fact that a log
// of who read whose mail carries the sensitivity of the mail itself.
const LOG_ENTRIES = positiveInt(process.env.EENGINE_TOKEN_LOG_ENTRIES, 1000);

// How long a token's log survives its last use, in seconds. Refreshed on every write, so this bounds
// how long a log outlives the credential's activity rather than how long each entry lives - which is
// the useful bound, because a token nobody has used is a log nobody needs.
const LOG_AGE = positiveInt(process.env.EENGINE_TOKEN_LOG_AGE, 7 * 24 * 3600);

// The largest page the log route will serve. Deliberately not the retention cap: one bounds a single
// response, the other bounds stored data, and while they were the same constant raising retention
// also multiplied the work one request could ask for - an LRANGE, a msgpack decode and a joi
// response validation per entry, on an API worker that is single-threaded by default. Floored by the
// entry cap so an instance that keeps fewer entries than this cannot be asked for a page it could
// never fill, which is also what keeps the route's `min(1).max()` satisfiable.
const MAX_PAGE_SIZE = Math.min(LOG_ENTRIES, 200);

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
                // The one field here that is unvalidated client input: both enforcement points build
                // their entry before route validation runs, so this is whatever arrived in the path
                // segment or the `?account=` query argument. Truncating to the longest id that could
                // be real bounds an entry the cap above then multiplies by a thousand, and keeps the
                // stored value inside the `accountIdSchema` the log endpoint types it as.
                account: entry.account ? entry.account.slice(0, MAX_ACCOUNT_ID_LENGTH) : null,
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
    const pageSize = Math.min(Math.max(Number(rawPageSize) || 20, 1), MAX_PAGE_SIZE);

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

module.exports = { record, allowed, denied, list, logKey, resetFlagCache, LOG_ENTRIES, MAX_PAGE_SIZE };
