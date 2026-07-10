'use strict';

// Unit tests for the shared ReconnectBackoff helper
// (lib/email-client/reconnect-backoff.js). The three consumers replaced
// hand-rolled counters with it, so the exact delay sequences are pinned here:
// any change to the curve silently changes reconnect pacing everywhere.

const test = require('node:test');
const assert = require('node:assert').strict;

const { ReconnectBackoff } = require('../lib/email-client/reconnect-backoff');

test('ReconnectBackoff', async t => {
    await t.test('produces the capped exponential sequence and increments per call', () => {
        const backoff = new ReconnectBackoff({ baseDelay: 2000, maxDelay: 30000 });

        const delays = Array.from({ length: 9 }, () => backoff.nextDelay());

        assert.deepEqual(delays, [2000, 3000, 4500, 6750, 10125, 15187.5, 22781.25, 30000, 30000], 'compute-then-increment from the base delay, capped');
        assert.equal(backoff.attempts, 9);
    });

    await t.test('matches the primary error-retry curve with base 3000', () => {
        // The old error handler multiplied its stored 2000 start by 1.5 before
        // the first use; base 3000 with compute-then-increment is the identical
        // sequence, including the value right after a reset
        const backoff = new ReconnectBackoff({ baseDelay: 3000, maxDelay: 30000 });

        const delays = Array.from({ length: 7 }, () => backoff.nextDelay());

        assert.deepEqual(delays, [3000, 4500, 6750, 10125, 15187.5, 22781.25, 30000]);

        backoff.reset();
        assert.equal(backoff.nextDelay(), 3000, 'first delay after a reset must match the first-ever delay');
    });

    await t.test('adds bounded jitter after the cap', t2 => {
        t2.mock.method(Math, 'random', () => 0.5);

        const backoff = new ReconnectBackoff({ baseDelay: 2000, maxDelay: 30000, jitter: 1000 });

        assert.equal(backoff.nextDelay(), 2000 + 500, 'jitter is random() * jitter on top of the computed delay');

        backoff.attempts = 100;
        assert.equal(backoff.nextDelay(), 30000 + 500, 'jitter applies after the cap, and a huge attempt count stays capped');
    });

    await t.test('reset() restarts the sequence', () => {
        const backoff = new ReconnectBackoff({ baseDelay: 1000, maxDelay: 30000 });

        backoff.nextDelay();
        backoff.nextDelay();
        assert.equal(backoff.attempts, 2);

        backoff.reset();

        assert.equal(backoff.attempts, 0);
        assert.equal(backoff.nextDelay(), 1000);
    });
});
