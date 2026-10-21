'use strict';

// Where the IDLE intervals lib/email-client/imap/adaptive-idle.js learns are kept: one hash for the
// instance, a field per server host, so every account on a host shares what any of them saw.
// Two workers recording at once can lose one observation; the learning is a running estimate and
// recovers on the next one.

const { REDIS_PREFIX } = require('../../consts');
const { observe, observationFor } = require('./adaptive-idle');

const LEARNED_KEY = `${REDIS_PREFIX}idle:learned`;

const hostKey = host => (host || '').toString().trim().toLowerCase();

async function readState(redis, host) {
    const raw = await redis.hget(LEARNED_KEY, hostKey(host));
    if (!raw) {
        return null;
    }
    try {
        return JSON.parse(raw);
    } catch (err) {
        return null;
    }
}

/**
 * The interval learned for a host, or null
 * @param {Object} redis - ioredis client
 * @param {string} host - IMAP server host
 * @returns {Promise<number|null>} Milliseconds
 */
async function learnedInterval(redis, host) {
    if (!hostKey(host)) {
        return null;
    }
    const state = await readState(redis, host);
    return (state && state.interval) || null;
}

/**
 * Records what a closed primary connection tells about its server
 * @param {Object} redis - ioredis client
 * @param {string} host - IMAP server host
 * @param {Object} imapClient - The closed ImapFlow client
 * @param {number} [now] - Epoch ms
 * @returns {Promise<Object|null>} `{ before, after }` intervals when something was recorded
 */
async function recordClose(redis, host, imapClient, now = Date.now()) {
    const observation = observationFor(imapClient, now);
    if (!observation || !hostKey(host)) {
        return null;
    }
    const state = await readState(redis, host);
    const next = observe(state, observation, now);
    await redis.hset(LEARNED_KEY, hostKey(host), JSON.stringify(next));
    return { before: (state && state.interval) || null, after: next.interval, observation };
}

module.exports = { learnedInterval, recordClose, LEARNED_KEY };
