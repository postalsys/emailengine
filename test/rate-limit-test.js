'use strict';

// Rate limiter (lib/rate-limit.js) - the brute-force and replay guard for the admin surface.
//
// Every call site is a security control and none of them had a test:
//   * admin login, per IP (30/min) and per username (10/min)   - lib/ui-routes/auth-routes.js
//   * TOTP verification attempts, per user (10/min)
//   * TOTP code REPLAY (allowed = 1 per 12 min) - a limiter that returns success twice for the
//     same code makes an intercepted 2FA code reusable
//   * passkey register/auth options and verify, per IP (10/min)
//
// Runs against the test Redis db (config/test.toml -> db 13) so the real INCRBY/EXPIRE
// transaction and the real time-bucket key derivation are exercised. Each test uses a unique
// key suffix, so a re-run inside the same time bucket starts from a clean counter.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { checkRateLimit, rateLimitWindowKey } = require('../lib/rate-limit');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Every subject is unique per run and every counter carries a TTL of at most its window size,
// so the keys clean themselves up - no teardown bookkeeping needed.
function uniqueKey(label) {
    return `unit-test:${label}:${crypto.randomBytes(8).toString('hex')}`;
}

// Uses the production key builder rather than re-deriving the bucket, so a change to the key
// format can not silently make the "did Redis really get a TTL" assertions vacuous.
function windowKeyFor(key, windowSize) {
    return rateLimitWindowKey(key, windowSize).windowKey;
}

registerRedisTeardown(redis);

test('Rate limiter', async t => {
    await t.test('a first request is under the limit and counts as one', async () => {
        const key = uniqueKey('first');

        const res = await checkRateLimit(key, 1, 10, 60);

        assert.strictEqual(res.success, true);
        assert.strictEqual(res.count, 1);
        assert.strictEqual(res.allowed, 10);
        assert.strictEqual(res.key, key);
    });

    await t.test('the counter accumulates across calls and trips exactly at the limit', async () => {
        const key = uniqueKey('accumulate');
        const ALLOWED = 3;

        const results = [];
        for (let i = 0; i < 5; i++) {
            results.push(await checkRateLimit(key, 1, ALLOWED, 60));
        }

        assert.deepStrictEqual(
            results.map(r => r.count),
            [1, 2, 3, 4, 5]
        );
        assert.deepStrictEqual(
            results.map(r => r.success),
            [true, true, true, false, false],
            'the Nth request must still pass and the (N+1)th must be refused'
        );
    });

    await t.test('a single-use limit refuses the second attempt (TOTP code replay)', async () => {
        // auth-routes.js uses allowed = 1 over a 12 minute window so an observed TOTP code
        // cannot be presented twice while it is still valid.
        const key = uniqueKey('totp-replay');

        const first = await checkRateLimit(key, 1, 1, 12 * 60);
        const second = await checkRateLimit(key, 1, 1, 12 * 60);

        assert.strictEqual(first.success, true, 'the first use of a code must be accepted');
        assert.strictEqual(second.success, false, 'replaying the same code must be refused');
    });

    await t.test('different keys are counted independently', async () => {
        // Otherwise one user (or one IP) locking itself out would lock out everybody else
        const keyA = uniqueKey('independent-a');
        const keyB = uniqueKey('independent-b');

        await checkRateLimit(keyA, 1, 1, 60);
        const aSecond = await checkRateLimit(keyA, 1, 1, 60);
        const bFirst = await checkRateLimit(keyB, 1, 1, 60);

        assert.strictEqual(aSecond.success, false);
        assert.strictEqual(bFirst.success, true, 'a second identity must not inherit the first one lockout');
        assert.strictEqual(bFirst.count, 1);
    });

    await t.test('the same key in different window sizes uses separate counters', async () => {
        // The window size is part of the Redis key, so the per-minute attempt limiter and the
        // 12-minute replay limiter can share a key name without interfering.
        const key = uniqueKey('window-split');

        await checkRateLimit(key, 1, 1, 60);
        const otherWindow = await checkRateLimit(key, 1, 1, 600);

        assert.strictEqual(otherWindow.count, 1, 'the wider window must start its own counter');
        assert.strictEqual(otherWindow.success, true);
    });

    await t.test('a cost greater than one is charged in full', async () => {
        const key = uniqueKey('weighted');

        const res = await checkRateLimit(key, 5, 10, 60);

        assert.strictEqual(res.count, 5);
        assert.strictEqual(res.success, true);
        assert.strictEqual((await checkRateLimit(key, 6, 10, 60)).success, false, 'crossing the limit in one weighted call must be refused');
    });

    await t.test('the counter key expires so the window actually resets', async () => {
        // Without the EXPIRE the counter would be permanent and the first burst would lock the
        // account out forever.
        const key = uniqueKey('expiry');
        const windowKey = windowKeyFor(key, 60);

        await checkRateLimit(key, 1, 10, 60);
        const ttl = await redis.ttl(windowKey);

        assert.ok(ttl > 0, `the window key must carry a TTL, got ${ttl}`);
        assert.ok(ttl <= 60, `the TTL must not exceed the window size, got ${ttl}`);
    });

    await t.test('the reported ttl matches the end of the current window', async () => {
        const key = uniqueKey('ttl-report');

        const res = await checkRateLimit(key, 1, 10, 60);

        assert.ok(res.ttl > 0 && res.ttl <= 60, `ttl should fall inside the window, got ${res.ttl}`);
        const reset = new Date(res.ttlReset).getTime();
        assert.ok(!Number.isNaN(reset), 'ttlReset must be a parseable ISO timestamp');
        assert.ok(reset > Date.now(), 'ttlReset must be in the future');
        // ttl is the distance to ttlReset, so the two must agree within a second of clock drift
        assert.ok(Math.abs((reset - Date.now()) / 1000 - res.ttl) < 1, 'ttl and ttlReset must describe the same instant');
    });

    await t.test('a missing or zero window size falls back to the 180 second default', async () => {
        const key = uniqueKey('default-window');
        const defaultWindowKey = windowKeyFor(key, 180);

        const res = await checkRateLimit(key, 1, 10);

        assert.strictEqual(res.count, 1);
        assert.strictEqual(await redis.exists(defaultWindowKey), 1, 'the default window must be 180 seconds');
        assert.ok(res.ttl > 0 && res.ttl <= 180);
    });

    await t.test('a negative window size is treated as its magnitude', async () => {
        const key = uniqueKey('negative-window');
        const windowKey = windowKeyFor(key, 60);

        await checkRateLimit(key, 1, 10, -60);

        assert.strictEqual(await redis.exists(windowKey), 1, 'Math.abs() keeps a negative window from producing a bogus key');
    });

    await t.test('a missing or zero cost is charged as one', async () => {
        const key = uniqueKey('default-count');

        assert.strictEqual((await checkRateLimit(key, 0, 10, 60)).count, 1, 'a zero cost must not make requests free');
        assert.strictEqual((await checkRateLimit(key, undefined, 10, 60)).count, 2);
    });

    await t.test('a negative cost can not buy attempts back', async () => {
        // Math.max() with one argument returns its input unchanged, so a negative cost used to
        // DECREMENT the counter - an attacker who reaches a call site that forwards a
        // caller-controlled cost could undo their own failed attempts against the login limiter.
        const key = uniqueKey('negative-count');

        assert.strictEqual((await checkRateLimit(key, 1, 10, 60)).count, 1);
        assert.strictEqual((await checkRateLimit(key, -100, 10, 60)).count, 2, 'a negative cost must be charged as one, not subtracted');
    });

    await t.test('the key builder and the limiter normalize the window the same way', async () => {
        // Both sides have to agree on the bucket, otherwise the counter is written under one key
        // and read (or expired) under another. The normalization lives in the key builder so a
        // caller that skips checkRateLimit() can not derive a different key.
        const key = uniqueKey('window-normalize');

        assert.strictEqual(windowKeyFor(key, undefined), windowKeyFor(key, 180), 'a missing window must resolve to the default');
        assert.strictEqual(windowKeyFor(key, 0), windowKeyFor(key, 180), 'a zero window must resolve to the default');
        assert.strictEqual(windowKeyFor(key, -60), windowKeyFor(key, 60), 'a negative window must resolve to its magnitude');
        assert.doesNotMatch(windowKeyFor(key, undefined), /undefined|NaN/, 'an unnormalized window leaks into the key');

        // and the limiter really does count under that same key
        await checkRateLimit(key, 1, 10);
        assert.strictEqual(await redis.exists(windowKeyFor(key, undefined)), 1);
    });

    await t.test('concurrent requests are all counted (no lost updates)', async () => {
        // The check runs as a Redis MULTI, so 20 simultaneous login attempts must all be
        // charged - a read-then-write limiter would let most of them through.
        const key = uniqueKey('concurrent');
        const ALLOWED = 5;

        const results = await Promise.all(Array.from({ length: 20 }, () => checkRateLimit(key, 1, ALLOWED, 60)));

        assert.strictEqual(results.filter(r => r.success).length, ALLOWED, 'exactly `allowed` concurrent requests may be admitted');
        assert.deepStrictEqual(
            results.map(r => r.count).sort((a, b) => a - b),
            Array.from({ length: 20 }, (unused, i) => i + 1),
            'every concurrent request must receive a distinct, contiguous counter value'
        );
    });
});
