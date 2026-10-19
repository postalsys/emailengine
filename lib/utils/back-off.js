'use strict';

// Retries an async operation with capped exponential delays. Replaces the exponential-backoff
// package and keeps its semantics for the options EmailEngine uses:
//
// - the delay before attempt n (0-based) is startingDelay * timeMultiple^(n - 1), capped at
//   maxDelay, and the first attempt runs immediately. With delayFirstAttempt the exponent is n
//   instead, so the first attempt waits startingDelay as well.
// - after each failure retry(err, failures) is awaited; a falsy answer rethrows that error.
// - numOfAttempts bounds the total number of attempts (Infinity keeps going); the last error is
//   rethrown once it is reached.
//
// The wait is node:timers/promises setTimeout, looked up at call time, so a suite can drive the
// loop with test/helpers/instant-timers.js like the other retry loops.

const timers = require('node:timers/promises');

// setTimeout() fires after 1 ms for any delay above this, which would turn an uncapped backoff
// into a busy loop
const MAX_TIMER_DELAY = 2 ** 31 - 1;

const DEFAULTS = {
    delayFirstAttempt: false,
    maxDelay: Infinity,
    numOfAttempts: 10,
    retry: () => true,
    startingDelay: 100,
    timeMultiple: 2
};

function getDelay(options, attempt) {
    const exponent = options.delayFirstAttempt ? attempt : attempt - 1;
    if (exponent < 0) {
        return 0;
    }
    const delay = Math.min(options.startingDelay * Math.pow(options.timeMultiple, exponent), options.maxDelay);
    return Math.min(delay, MAX_TIMER_DELAY);
}

/**
 * @template T
 * @param {() => Promise<T>} request The operation to run
 * @param {Object} [options]
 * @param {boolean} [options.delayFirstAttempt=false] Wait startingDelay before the first attempt too
 * @param {number} [options.startingDelay=100] First delay in ms
 * @param {number} [options.timeMultiple=2] Growth factor between delays
 * @param {number} [options.maxDelay=Infinity] Upper bound for a single delay in ms
 * @param {number} [options.numOfAttempts=10] Maximum number of attempts, at least 1
 * @param {(err: Error, failures: number) => boolean|Promise<boolean>} [options.retry] Whether to try again after a failure
 * @returns {Promise<T>}
 */
async function backOff(request, options) {
    // an option passed as undefined keeps its default instead of turning the delay into NaN
    const settings = Object.assign({}, DEFAULTS);
    for (const [key, value] of Object.entries(options || {})) {
        if (value !== undefined) {
            settings[key] = value;
        }
    }
    options = settings;

    const maxAttempts = Math.max(options.numOfAttempts, 1);

    for (let attempt = 0; ; attempt++) {
        const delay = getDelay(options, attempt);
        if (delay > 0) {
            await timers.setTimeout(delay);
        }

        try {
            return await request();
        } catch (err) {
            const failures = attempt + 1;
            const shouldRetry = await options.retry(err, failures);
            if (!shouldRetry || failures >= maxAttempts) {
                throw err;
            }
        }
    }
}

module.exports = { backOff, getDelay };
