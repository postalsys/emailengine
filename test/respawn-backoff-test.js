'use strict';

// Unit tests for lib/respawn-backoff.js. The supervisor lives in server.js, which a test cannot
// import (requiring it boots the whole application), so the pacing logic is extracted here.

const test = require('node:test');
const assert = require('node:assert').strict;

const { RespawnTracker, retryWithBackoff, DEFAULT_BASE_DELAY, DEFAULT_MAX_DELAY, DEFAULT_STABLE_UPTIME } = require('../lib/respawn-backoff');

// Jitter off and a fixed random source, so delays are exact
const makeTracker = opts => new RespawnTracker(Object.assign({ jitter: 0, random: () => 0.5 }, opts));

test('RespawnTracker', async t => {
    await t.test('keeps the historical 1s delay for a first crash', () => {
        const tracker = makeTracker();
        assert.strictEqual(tracker.recordExit('imap', 0), DEFAULT_BASE_DELAY);
    });

    await t.test('doubles the delay while a worker type keeps crashing on startup', () => {
        const tracker = makeTracker();
        const delays = [];
        for (let i = 0; i < 5; i++) {
            delays.push(tracker.recordExit('imap', 100));
        }
        assert.deepStrictEqual(delays, [1000, 2000, 4000, 8000, 16000]);
    });

    await t.test('caps the delay so a crashing worker is still retried regularly', () => {
        const tracker = makeTracker();
        let delay;
        for (let i = 0; i < 40; i++) {
            delay = tracker.recordExit('imap', 100);
        }
        assert.strictEqual(delay, DEFAULT_MAX_DELAY);
    });

    await t.test('resets the streak once a worker survives long enough to be healthy', () => {
        const tracker = makeTracker();
        tracker.recordExit('imap', 100);
        tracker.recordExit('imap', 100);
        assert.strictEqual(tracker.streakFor('imap'), 2);

        // A worker that ran past the stability threshold is not crash looping
        assert.strictEqual(tracker.recordExit('imap', DEFAULT_STABLE_UPTIME), DEFAULT_BASE_DELAY);
        assert.strictEqual(tracker.streakFor('imap'), 0);

        // ...and the next failure starts over from the base delay
        assert.strictEqual(tracker.recordExit('imap', 100), DEFAULT_BASE_DELAY);
    });

    await t.test('tracks worker types independently', () => {
        // This is the property that keeps it from behaving like a circuit breaker: a wedged
        // worker type must never slow down the respawn of a healthy one.
        const tracker = makeTracker();
        for (let i = 0; i < 4; i++) {
            tracker.recordExit('imap', 100);
        }

        assert.strictEqual(tracker.recordExit('webhooks', 100), DEFAULT_BASE_DELAY);
        assert.strictEqual(tracker.streakFor('imap'), 4);
        assert.strictEqual(tracker.streakFor('webhooks'), 1);
    });

    await t.test('never stops respawning', () => {
        const tracker = makeTracker();
        for (let i = 0; i < 100; i++) {
            const delay = tracker.recordExit('imap', 0);
            assert.ok(Number.isFinite(delay) && delay > 0, 'delay must stay finite and positive');
            assert.ok(delay <= DEFAULT_MAX_DELAY, 'delay must stay bounded');
        }
    });

    await t.test('applies jitter within the expected band', () => {
        // Spreads a fleet-wide respawn so workers do not all reconnect in lockstep
        const low = new RespawnTracker({ jitter: 0.2, random: () => 0 });
        const high = new RespawnTracker({ jitter: 0.2, random: () => 1 });
        const mid = new RespawnTracker({ jitter: 0.2, random: () => 0.5 });

        assert.strictEqual(low.recordExit('imap', 0), Math.round(DEFAULT_BASE_DELAY * 0.8));
        assert.strictEqual(high.recordExit('imap', 0), Math.round(DEFAULT_BASE_DELAY * 1.2));
        assert.strictEqual(mid.recordExit('imap', 0), DEFAULT_BASE_DELAY);
    });

    await t.test('counts streaks per respawn slot, so exits of sibling workers do not compound (WORK-7)', () => {
        // server.js keys the tracker by spawn slot. Keyed by type, four IMAP workers each exiting
        // once in quick succession pushed the fourth respawn to 8s, and the next ones past the 10s
        // failsafe reassignment that leaves a late worker with no accounts.
        const tracker = makeTracker();
        const delays = ['imap:1', 'imap:2', 'imap:3', 'imap:4'].map(slot => tracker.recordExit(slot, 100));
        assert.deepStrictEqual(delays, [1000, 1000, 1000, 1000]);

        // A slot that itself keeps crashing still backs off
        assert.strictEqual(tracker.recordExit('imap:1', 100), 2000);
        assert.strictEqual(tracker.streakFor('imap:1'), 2);
        assert.strictEqual(tracker.streakFor('imap:2'), 1);
    });

    await t.test('treats an uptime at the stability threshold as healthy', () => {
        const tracker = makeTracker();
        tracker.recordExit('imap', 100);
        tracker.recordExit('imap', DEFAULT_STABLE_UPTIME);
        assert.strictEqual(tracker.streakFor('imap'), 0);
    });
});

test('retryWithBackoff', async t => {
    const noSleep = () => Promise.resolve();
    const refused = () => Object.assign(new Error("OOM command not allowed when used memory > 'maxmemory'."), { name: 'ReplyError' });

    await t.test('returns what the call resolved with', async () => {
        assert.strictEqual(await retryWithBackoff(async () => 42, { delayFor: () => 0, sleep: noSleep }), 42);
    });

    await t.test('retries a failed read with the given delays until it succeeds', async () => {
        let calls = 0;
        const errors = [];
        const slept = [];
        const result = await retryWithBackoff(
            async () => {
                if (++calls < 3) {
                    throw refused();
                }
                return 'enabled';
            },
            {
                delayFor: attempt => attempt * 100,
                onError: (err, delay) => errors.push([err.name, delay]),
                sleep: async ms => slept.push(ms)
            }
        );
        assert.strictEqual(result, 'enabled');
        assert.strictEqual(calls, 3);
        assert.deepStrictEqual(errors, [
            ['ReplyError', 100],
            ['ReplyError', 200]
        ]);
        assert.deepStrictEqual(slept, [100, 200]);
    });

    await t.test('waits on a real timer by default', async () => {
        let calls = 0;
        const result = await retryWithBackoff(
            async () => {
                if (++calls < 2) {
                    throw refused();
                }
                return 'ok';
            },
            { delayFor: () => 1 }
        );
        assert.strictEqual(result, 'ok');
    });

    await t.test('stops retrying once the process is closing', async () => {
        let calls = 0;
        let closing = false;
        const result = await retryWithBackoff(
            async () => {
                calls++;
                throw refused();
            },
            {
                delayFor: () => 0,
                shouldStop: () => closing,
                sleep: async () => {
                    closing = true;
                }
            }
        );
        assert.strictEqual(result, undefined);
        assert.strictEqual(calls, 1);
    });

    await t.test('does not retry a failure that arrives while closing', async () => {
        let closing = false;
        await assert.rejects(
            retryWithBackoff(
                async () => {
                    closing = true;
                    throw refused();
                },
                { delayFor: () => 0, shouldStop: () => closing, sleep: noSleep }
            ),
            /OOM/
        );
    });

    await t.test('makes no call at all when already closing', async () => {
        let calls = 0;
        const result = await retryWithBackoff(async () => ++calls, { delayFor: () => 0, shouldStop: () => true });
        assert.strictEqual(result, undefined);
        assert.strictEqual(calls, 0);
    });
});
