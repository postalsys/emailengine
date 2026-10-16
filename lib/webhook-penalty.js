'use strict';

// A delivery penalty per webhook target.
//
// The webhook queue is one queue with a small concurrency, and every attempt against a target
// that accepts the connection and never answers costs the whole attempt timeout (30 seconds by
// default). One account pointing its own webhook URL at such a target, and generating a dozen
// events a minute, kept the queue busy with timeouts and delayed every other account's
// deliveries behind them, indefinitely. So a target that just failed with a network-level
// error (a timeout, a refused or reset connection, a name that does not resolve) is penalised:
// for a short while, deliveries to the same origin are moved back to the delayed set instead of
// being attempted, and the queue spends its time on targets that answer. The penalised
// delivery is not lost, it is tried again once the penalty is over, with its attempt count
// unchanged.
//
// A target answering with an HTTP status, any status, is not penalised: it answered quickly, so
// it is not holding the queue, and the retry schedule already spaces those out. Nor is an egress
// or redirect refusal, which fails the job for good anyway.

const { createHash } = require('crypto');
const { REDIS_PREFIX, TRANSIENT_NETWORK_CODES } = require('./consts');

// At most this long per penalty, whatever the attempt timeout is set to
const MAX_PENALTY_MS = 5 * 60 * 1000;

/**
 * Redis key of the penalty for a target, by its origin: a receiver is one host, whatever paths
 * its URLs have, and the credentials in the URL are not part of what identifies it.
 *
 * @param {String} url - the delivery URL
 * @returns {String|null} the key, or null for a URL that does not parse
 */
function penaltyKey(url) {
    let origin;
    try {
        origin = new URL(url).origin;
    } catch (err) {
        return null;
    }
    if (!origin || origin === 'null') {
        return null;
    }
    return `${REDIS_PREFIX}webhook:penalty:${createHash('sha256').update(origin).digest('base64url').slice(0, 32)}`;
}

/**
 * How long a target is penalised after a failed attempt, in milliseconds; 0 when the failure is
 * not the kind that holds the queue.
 *
 * @param {Error} err - the failure
 * @param {Number} attemptTimeout - the per-attempt wall clock cap, in milliseconds
 * @returns {Number}
 */
function penaltyFor(err, attemptTimeout) {
    if (!err || typeof err !== 'object') {
        return 0;
    }
    let code = err.code || (err.cause && err.cause.code);
    if (!code || !TRANSIENT_NETWORK_CODES.has(code)) {
        return 0;
    }
    // twice the attempt cap: long enough that a dozen events a minute to a dead target no
    // longer each cost a full timeout, short enough that a target that comes back is not
    // kept waiting for long
    let penalty = 2 * (Number(attemptTimeout) || 0);
    return Math.min(Math.max(penalty, 1000), MAX_PENALTY_MS);
}

module.exports = { penaltyKey, penaltyFor, MAX_PENALTY_MS };
