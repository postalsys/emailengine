'use strict';

// Unit tests for the license-validation feature beacon (lib/license-beacon.js).
//
// Covers the pure helpers (tier bucketing, stable serialization, timeout) and the live collector
// against the test Redis (DB 13). The collector is best-effort and must never throw, so the shape
// assertions double as a "does not throw on a real but mostly-empty database" check. These tests
// are read-only: they never mutate settings, so they are safe to run in the parallel unit tier.
//
// Requiring lib/license-beacon transitively opens Redis/BullMQ handles (via lib/db), so the test
// force-exits after cleanup, mirroring test/tokens-test.js and test/ui-routes-table-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const logger = require('../lib/logger');
const { collectBeacon, withTimeout, tier, stableStringify } = require('../lib/license-beacon');

test('license beacon', async t => {
    t.after(() => {
        redis.quit();
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('tier() maps counts to coarse magnitude buckets', () => {
        const cases = [
            [0, 0],
            [1, 1],
            [2, 2],
            [9, 2],
            [10, 3],
            [99, 3],
            [100, 4],
            [999, 4],
            [1000, 5],
            [9999, 5],
            [10000, 6],
            [123456, 6]
        ];
        for (const [input, expected] of cases) {
            assert.equal(tier(input), expected, `tier(${input}) should be ${expected}`);
        }
        // defensive: non-numeric input collapses to 0
        assert.equal(tier(undefined), 0);
        assert.equal(tier(-5), 0);
    });

    await t.test('stableStringify() is key-order independent but content sensitive', () => {
        const a = stableStringify({ b: 2, a: [1, 2], c: { y: 1, x: 2 } });
        const b = stableStringify({ a: [1, 2], c: { x: 2, y: 1 }, b: 2 });
        assert.equal(a, b, 'reordered object keys must serialize identically');

        assert.notEqual(stableStringify({ feat: ['a'] }), stableStringify({ feat: ['a', 'b'] }), 'different content must serialize differently');
    });

    await t.test('withTimeout() resolves fast work and rejects slow work', async () => {
        assert.equal(await withTimeout(Promise.resolve('ok'), 1000), 'ok');
        await assert.rejects(
            () => withTimeout(new Promise(resolve => setTimeout(resolve, 1000).unref()), 50),
            /timed out/i,
            'should reject when the work outlasts the timeout'
        );
    });

    await t.test('collectBeacon() returns a well-formed, presence-only snapshot', async () => {
        const result = await collectBeacon({ redis, logger });

        assert.ok(result && typeof result === 'object', 'collector returns an object');
        assert.match(result.fh, /^[0-9a-f]{12}$/, 'fh is a 12-char hex digest');
        assert.equal(result.diag.v, 1, 'schema version is present');

        for (const key of ['feat', 'prov', 'oapp', 'use', 'dep', 'flags']) {
            assert.ok(Array.isArray(result.diag[key]), `${key} is an array`);
        }

        // feat/dep/etc. are presence-only: every entry is a non-empty string code, never a boolean.
        for (const key of ['feat', 'prov', 'oapp', 'use', 'dep', 'flags']) {
            for (const entry of result.diag[key]) {
                assert.equal(typeof entry, 'string', `${key} entries are strings`);
                assert.ok(entry.length, `${key} entries are non-empty`);
            }
        }

        // tiers are coarse ordinals (0..6), never raw counts.
        for (const key of ['acct', 'oapp', 'gw', 'wh', 'tpl', 'bl']) {
            const value = result.diag.tiers[key];
            assert.equal(typeof value, 'number', `tiers.${key} is a number`);
            assert.ok(Number.isInteger(value) && value >= 0 && value <= 6, `tiers.${key} is an ordinal in 0..6`);
        }

        assert.equal(typeof result.diag.dist, 'string');
        assert.equal(result.diag.node, process.versions.node);
        assert.equal(result.diag.arch, process.arch);
    });

    await t.test('collectBeacon() digest is stable across calls when nothing changes', async () => {
        const first = await collectBeacon({ redis, logger });
        const second = await collectBeacon({ redis, logger });
        assert.equal(first.fh, second.fh, 'identical state must produce an identical digest');
    });
});
