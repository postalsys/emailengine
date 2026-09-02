'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it) for the failed-login throttle
// tests of the SMTP and IMAP-proxy auth handlers (lib/auth-token.js withAuthFailureBudget).
//
// The failure counters live in fixed time buckets. A test that records a failure and then reads
// the counter back has to stay inside one bucket, so trackedWindow() waits out a window that is
// about to roll over rather than flake once every few thousand runs, and cleans the counter up
// when the test ends.

const { redis } = require('../../lib/db');
const { authFailureKey, AUTH_FAILURE_LIMIT, AUTH_FAILURE_WINDOW } = require('../../lib/auth-token');
const { rateLimitWindowKey } = require('../../lib/rate-limit');

const ROLLOVER_MARGIN = 3000;

/**
 * Resolves the Redis key of the current failure window for a client, waiting for a fresh window
 * when the current one is about to end, and deletes it after the test.
 *
 * @param {Object} t - node:test context of the test that owns the counter
 * @param {string} remoteAddress - client IP
 * @param {string} account - username the client authenticates as
 * @returns {Promise<string>} the window key
 */
async function trackedWindow(t, remoteAddress, account) {
    const key = authFailureKey(remoteAddress, account);

    const { windowEnds } = rateLimitWindowKey(key, AUTH_FAILURE_WINDOW);
    const remaining = windowEnds - Date.now();
    if (remaining < ROLLOVER_MARGIN) {
        await new Promise(resolve => setTimeout(resolve, remaining + 50));
    }

    const { windowKey } = rateLimitWindowKey(key, AUTH_FAILURE_WINDOW);
    t.after(() => redis.del(windowKey).catch(() => false));
    return windowKey;
}

/**
 * Sets a window's counter to the limit, as if the client had spent its whole budget.
 *
 * @param {string} windowKey - from trackedWindow()
 * @param {number} [count] - counter value, defaults to the limit
 */
async function exhaustBudget(windowKey, count) {
    await redis.set(windowKey, typeof count === 'number' ? count : AUTH_FAILURE_LIMIT, 'EX', AUTH_FAILURE_WINDOW);
}

module.exports = { trackedWindow, exhaustBudget };
