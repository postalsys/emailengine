'use strict';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

// Fixed epoch for the window bucket arithmetic: "2000-01-01T00:00:00.000Z"
const EPOCH_TIME = 946684800000;

const DEFAULT_WINDOW_SIZE = 180;

// Derives the Redis counter key for a rate-limit window. The window size is part of the key, so
// the same subject can be limited over several windows at once (e.g. per-minute login attempts
// and the 12 minute TOTP code replay guard) without the counters interfering.
//
// The normalization lives here rather than in the caller so that every consumer of the key
// derives the same bucket: a missing window would otherwise produce an "rl:undefined:NaN:" key
// while checkRateLimit() counted under the 180 second one, and the two would never meet.
// The end of the bucket is computed here too, so the bucket arithmetic and its inverse stay in
// one place instead of the caller reconstructing it from a leaked bucket number.
const rateLimitWindowKey = (key, windowSize, now) => {
    windowSize = Math.abs(Number(windowSize) || DEFAULT_WINDOW_SIZE);
    let timeBucket = Math.floor(((now || Date.now()) - EPOCH_TIME) / (windowSize * 1000));
    return {
        windowKey: `${REDIS_PREFIX}rl:${windowSize}:${timeBucket}:${key}`,
        windowSize,
        windowEnds: (timeBucket + 1) * windowSize * 1000 + EPOCH_TIME
    };
};

// INCRBY and EXPIRE as one transaction, returning the new count. The counter behind
// checkRateLimit(), and behind the exact counters that are not windows at all (the failed
// second-factor codes of one password-stage session), so both spell the write the same way.
const incrementCounter = async (key, count, ttl) => {
    let [[resErr, resVal], [expireErr]] = await redis.multi().incrby(key, count).expire(key, ttl).exec();
    if (resErr || expireErr) {
        throw resErr || expireErr;
    }
    return resVal;
};

const checkRateLimit = async (key, count, allowed, windowSize) => {
    // The lower bound is what keeps a negative cost from DECREMENTING the counter, i.e. from
    // buying back attempts against a brute-force guard. Math.max() with a single argument is a
    // no-op and passed one straight through.
    count = Math.max(Number(count) || 1, 1);

    let now = Date.now();
    let { windowKey, windowSize: normalizedWindowSize, windowEnds } = rateLimitWindowKey(key, windowSize, now);

    let resVal = await incrementCounter(windowKey, count, normalizedWindowSize);

    // Inclusive: the request that was just counted is admitted up to and including the limit
    return windowResult({ key, count: resVal, success: resVal <= allowed, allowed, now, windowEnds });
};

// A failure budget over one window, in the shape reserveAttempts() takes: the counter is the
// window's key, the limit is inclusive, and the counter lives for the window
const windowBudget = (key, allowed, windowSize, now) => {
    let { windowKey, windowSize: normalizedWindowSize } = rateLimitWindowKey(key, windowSize, now);
    return { key: windowKey, limit: allowed, ttl: normalizedWindowSize };
};

/**
 * Reserves one attempt in every budget at once, or in none of them.
 *
 * For guards that count failures only: the attempt is reserved before it is checked and given
 * back with releaseAttempts() when it is accepted, so only a refusal stays counted. Reserving is
 * what a look-then-record check left open: parallel attempts all read the same count and each
 * went ahead. A refused reservation is taken back by the script, so a spent budget holds at its
 * limit rather than growing with every refused attempt (lib/lua/ee-reserve-attempts.lua).
 *
 * @param {Array<{key: String, limit: Number, ttl: Number}>} budgets - Full Redis key, inclusive
 *   limit and counter lifetime in seconds of each budget, see windowBudget()
 * @returns {Promise<{admitted: Boolean, counts: Number[]}>} The counts include the reservation
 *   when it was admitted, and are the counts as they were when it was not
 */
const reserveAttempts = async budgets => {
    let limitsAndTtls = [];
    for (let budget of budgets) {
        limitsAndTtls.push(budget.limit, budget.ttl);
    }
    let [admitted, ...counts] = await redis.eeReserveAttempts(budgets.length, ...budgets.map(budget => budget.key), ...limitsAndTtls);
    return { admitted: !!admitted, counts };
};

/**
 * Gives back a reservation for an attempt that was accepted. Best effort by design: the caller
 * does not wait for it, and a release that fails only costs that client one attempt of its budget.
 *
 * @param {String[]} keys - The counters that were reserved
 * @returns {Promise<void>}
 */
const releaseAttempts = async keys => {
    if (!keys.length) {
        return;
    }
    await redis.eeReleaseAttempts(keys.length, ...keys);
};

// One result shape for the window check, so a field added to it is added in one place
function windowResult({ key, count, success, allowed, now, windowEnds }) {
    return {
        key,
        success,
        count,
        allowed,
        ttl: (windowEnds - now) / 1000,
        ttlReset: new Date(windowEnds).toISOString()
    };
}

module.exports = { checkRateLimit, rateLimitWindowKey, windowBudget, reserveAttempts, releaseAttempts, incrementCounter };
