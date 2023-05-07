'use strict';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

const checkRateLimit = async (key, count, allowed, windowSize) => {
    count = Math.max(Number(count) || 1);
    windowSize = Math.abs(Number(windowSize) || 180);

    let now = Date.now();
    let epochTime = 946684800000; // "2000-01-01T00:00:00.000Z"
    let timeBucket = Math.floor((now - epochTime) / (windowSize * 1000));
    let ttl = new Date((timeBucket + 1) * windowSize * 1000 + epochTime);

    let windowKey = `${REDIS_PREFIX}rl:${windowSize}:${timeBucket}:${key}`;

    let [[resErr, resVal], [expireErr]] = await redis.multi().incrby(windowKey, count).expire(windowKey, windowSize).exec();
    if (resErr || expireErr) {
        throw resErr || expireErr;
    }

    return {
        key,
        success: resVal <= allowed,
        count: resVal,
        allowed,
        ttl: (ttl.getTime() - now) / 1000,
        ttlReset: new Date(ttl.getTime()).toISOString()
    };
};

module.exports = { checkRateLimit };
