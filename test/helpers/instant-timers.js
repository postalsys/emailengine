'use strict';

// Runs fn with the promise-based setTimeout of node:timers/promises resolving at once, recording
// the delays that were asked for. This is the wait lib/email-client/api-retry.js and the Graph
// batch retry sleep on, looked up on the module at call time, so a suite can drive the real retry
// loops without their one-to-five second waits and still assert the delay each retry computed.

const timers = require('node:timers/promises');

/**
 * @param {Function} fn - Async function to run under the stubbed wait
 * @returns {Promise<{ result: *, error: Error|undefined, delays: number[] }>} what fn resolved or
 *     rejected with, and every delay (ms) that was requested in the meantime
 */
async function withInstantTimers(fn) {
    const realSetTimeout = timers.setTimeout;
    const delays = [];

    timers.setTimeout = async (delay, value) => {
        delays.push(delay);
        return value;
    };

    let result;
    let error;
    try {
        result = await fn();
    } catch (err) {
        error = err;
    } finally {
        timers.setTimeout = realSetTimeout;
    }

    return { result, error, delays };
}

/**
 * Runs fn with the global setTimeout answering at once for the callers in one source file, and
 * Date.now() moved on by every delay skipped that way. The IMAP retry loops wait with
 * `new Promise(r => setTimeout(r, delay))` and measure their budget with Date.now(), so a suite can
 * drive them through many retries in no time. Every other timer (the Redis client's, the test
 * runner's) is left alone: only a call whose stack names `file` is answered early
 * @param {string} file - Path fragment of the module whose waits are skipped, e.g. 'imap/mailbox.js'
 * @param {Function} fn - Async function to run under the stubbed wait
 * @param {Object} [opts]
 * @param {Function} [opts.onSleep] - Called with the delay as each wait starts, to change the world
 *     the way it could change while the loop waits
 * @returns {Promise<{ result: *, error: Error|undefined, delays: number[] }>}
 */
async function withInstantSleeps(file, fn, { onSleep } = {}) {
    const realSetTimeout = global.setTimeout;
    const realNow = Date.now;
    const delays = [];
    let skipped = 0;

    global.setTimeout = function (callback, delay, ...args) {
        if (typeof callback === 'function' && (new Error().stack || '').includes(file)) {
            delays.push(delay);
            skipped += delay || 0;
            if (onSleep) {
                onSleep(delay);
            }
            return realSetTimeout(callback, 0, ...args);
        }
        return realSetTimeout(callback, delay, ...args);
    };
    Date.now = () => realNow() + skipped;

    let result;
    let error;
    try {
        result = await fn();
    } catch (err) {
        error = err;
    } finally {
        global.setTimeout = realSetTimeout;
        Date.now = realNow;
    }

    return { result, error, delays };
}

module.exports = { withInstantTimers, withInstantSleeps };
