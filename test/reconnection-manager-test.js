'use strict';

// Unit tests for lib/reconnection-manager.js - the capped exponential backoff
// with jitter that governs IMAP reconnection pacing. A regression here drives
// either reconnect storms (delay too small / never grows) or stuck accounts
// (delay never resets after success). Previously untested.
//
// Note: the constructor uses `options.x || default`, so 0 is falsy and replaced
// by the default. We therefore use jitterMs: 1 (jitter in [0, 1)) and compare
// with Math.floor for deterministic delay assertions.

const test = require('node:test');
const assert = require('node:assert').strict;

const { ReconnectionManager } = require('../lib/reconnection-manager');

test('ReconnectionManager', async t => {
    await t.test('produces an exponential backoff sequence', () => {
        const mgr = new ReconnectionManager({ baseDelay: 1000, maxDelay: 8000, backoffMultiplier: 2, jitterMs: 1 });
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 1000); // 1000 * 2^0
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 2000); // 1000 * 2^1
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 4000); // 1000 * 2^2
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 8000); // 1000 * 2^3
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 8000); // capped at maxDelay
    });

    await t.test('counts attempts', () => {
        const mgr = new ReconnectionManager({ jitterMs: 1 });
        assert.strictEqual(mgr.attempts, 0);
        mgr.getNextDelay();
        mgr.getNextDelay();
        assert.strictEqual(mgr.attempts, 2);
    });

    await t.test('keeps the delay capped at maxDelay over many attempts', () => {
        const mgr = new ReconnectionManager({ baseDelay: 2000, maxDelay: 30000, backoffMultiplier: 1.5, jitterMs: 1 });
        let last = 0;
        for (let i = 0; i < 50; i++) {
            last = mgr.getNextDelay();
            assert.ok(last < 30001, `delay ${last} must never exceed maxDelay (+jitter)`);
        }
        assert.strictEqual(Math.floor(last), 30000, 'delay should be pinned at maxDelay after many attempts');
    });

    await t.test('adds jitter within [currentDelay, currentDelay + jitterMs)', () => {
        // backoffMultiplier 1 keeps currentDelay constant so we can bound the jitter.
        const mgr = new ReconnectionManager({ baseDelay: 1000, maxDelay: 60000, backoffMultiplier: 1, jitterMs: 500 });
        for (let i = 0; i < 200; i++) {
            const delay = mgr.getNextDelay();
            assert.ok(delay >= 1000 && delay < 1500, `delay ${delay} must be within [1000, 1500)`);
        }
    });

    await t.test('reset() returns to the base delay', () => {
        const mgr = new ReconnectionManager({ baseDelay: 1000, maxDelay: 8000, backoffMultiplier: 2, jitterMs: 1 });
        mgr.getNextDelay();
        mgr.getNextDelay();
        assert.strictEqual(mgr.attempts, 2);

        mgr.reset();
        assert.strictEqual(mgr.attempts, 0);
        assert.strictEqual(Math.floor(mgr.getNextDelay()), 1000, 'after reset the first delay is the base delay again');
    });

    await t.test('waitAndReconnect resets the backoff on success', async () => {
        const mgr = new ReconnectionManager({ baseDelay: 1, maxDelay: 1, jitterMs: 1 });
        mgr.getNextDelay();
        mgr.getNextDelay();
        assert.ok(mgr.attempts >= 2);

        const result = await mgr.waitAndReconnect(async () => 'connected');
        assert.strictEqual(result, 'connected');
        assert.strictEqual(mgr.attempts, 0, 'a successful reconnect resets the attempt counter');
    });

    await t.test('waitAndReconnect keeps incrementing on failure', async () => {
        const mgr = new ReconnectionManager({ baseDelay: 1, maxDelay: 1, jitterMs: 1 });

        await assert.rejects(() =>
            mgr.waitAndReconnect(async () => {
                throw new Error('still down');
            })
        );

        // The failed attempt is counted and not reset.
        assert.ok(mgr.attempts >= 1, 'a failed reconnect must not reset the counter');
    });

    await t.test('getState exposes the current attempt count', () => {
        const mgr = new ReconnectionManager({ baseDelay: 1000, maxDelay: 8000, backoffMultiplier: 2, jitterMs: 1 });
        mgr.getNextDelay();
        const before = mgr.attempts;
        const state = mgr.getState();
        assert.strictEqual(state.attempts, before);
        assert.strictEqual(typeof state.nextDelay, 'number');
        // Note: getState() calls getNextDelay() internally, so it advances the counter.
        assert.strictEqual(mgr.attempts, before + 1);
    });
});
