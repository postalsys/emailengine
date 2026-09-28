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

module.exports = { withInstantTimers };
