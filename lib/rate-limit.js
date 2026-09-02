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

const checkRateLimit = async (key, count, allowed, windowSize) => {
    // The lower bound is what keeps a negative cost from DECREMENTING the counter, i.e. from
    // buying back attempts against a brute-force guard. Math.max() with a single argument is a
    // no-op and passed one straight through.
    count = Math.max(Number(count) || 1, 1);

    let now = Date.now();
    let { windowKey, windowSize: normalizedWindowSize, windowEnds } = rateLimitWindowKey(key, windowSize, now);

    let [[resErr, resVal], [expireErr]] = await redis.multi().incrby(windowKey, count).expire(windowKey, normalizedWindowSize).exec();
    if (resErr || expireErr) {
        throw resErr || expireErr;
    }

    // Inclusive: the request that was just counted is admitted up to and including the limit
    return windowResult({ key, count: resVal, success: resVal <= allowed, allowed, now, windowEnds });
};

// Reads a window's counter without adding to it. For guards that count failures only: the check
// ahead of an authentication attempt must not spend the budget of the client making it, so it
// only looks, and only a refusal is recorded (through checkRateLimit) afterwards.
const peekRateLimit = async (key, allowed, windowSize) => {
    let now = Date.now();
    let { windowKey, windowEnds } = rateLimitWindowKey(key, windowSize, now);

    let count = Number(await redis.get(windowKey)) || 0;

    // Exclusive: nothing was counted, so the question is whether one more attempt still fits
    return windowResult({ key, count, success: count < allowed, allowed, now, windowEnds });
};

// One result shape for both reads, so a field added to one cannot silently miss the other
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

module.exports = { checkRateLimit, peekRateLimit, rateLimitWindowKey };
