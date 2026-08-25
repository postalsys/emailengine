'use strict';

// Unit tests for the license-validation feature beacon (lib/license-beacon.js).
//
// Covers the pure helpers (tier bucketing, stable serialization, timeout) and the live collector
// against a real Redis. The collector is best-effort and must never throw, so the shape assertions
// double as a "does not throw against a live database" check. collectBeacon() itself never writes;
// the one test below that does writes inside this file's own keyspace and cleans up after itself.
//
// The keyspace is load-bearing, not housekeeping. The digest-stability check asserts that two
// consecutive snapshots of unchanged state agree, and the snapshot it hashes counts accounts and
// OAuth2 apps and reads instance settings - exactly what sibling files in the parallel tier create,
// delete and toggle. Two calls straddling one of those writes disagree, and the assertion then fails
// for a reason that has nothing to do with the collector being deterministic.
//
// A prefix rather than a database of this file's own, because only part of the snapshot travels over
// the client collectBeacon() is handed: settings.getMulti(), oauth2Apps.list() and
// passkeys.hasPasskeys() each hold lib/db's own connection and go on reading the tier's data
// whatever client is passed in. All four read paths compose REDIS_PREFIX into their keys, so the
// prefix isolates every one of them where a second connection isolates one. It is also how the rest
// of the suite claims a keyspace - see test/tokens-test.js and test/settings-coupling-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_license_beacon';

const { redis } = require('../lib/db');
const logger = require('../lib/logger');
const settings = require('../lib/settings');
const { REDIS_PREFIX } = require('../lib/consts');
const { collectBeacon, withTimeout, tier, stableStringify } = require('../lib/license-beacon');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring lib/license-beacon transitively opens Redis/BullMQ handles (via lib/db), which would
// otherwise keep the runner alive after the tests have passed.
registerRedisTeardown(redis);

test('license beacon', async t => {
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

        for (const key of ['feat', 'prov', 'oapp', 'use', 'dep']) {
            assert.ok(Array.isArray(result.diag[key]), `${key} is an array`);
        }

        // feat/dep/etc. are presence-only: every entry is a non-empty string code, never a boolean.
        for (const key of ['feat', 'prov', 'oapp', 'use', 'dep']) {
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

    await t.test('the collector reads the keyspace this file claims, which is what isolates it from the tier', async () => {
        // EENGINE_REDIS_PREFIX only takes effect when it is set before lib/consts is first required.
        // Nothing enforces that ordering, and getting it wrong costs nothing visible: REDIS_PREFIX
        // falls back to empty, the collector reads the keyspace the whole parallel tier writes to,
        // and the stability check below starts failing at random instead of failing here.
        assert.ok(REDIS_PREFIX.startsWith('test_license_beacon'), 'the beacon tests must run in a keyspace of their own');

        // settings.getMulti() is one of the three snapshot inputs that never travel over the client
        // passed to collectBeacon() - it, oauth2Apps.list() and passkeys.hasPasskeys() each reach
        // Redis through lib/db's own connection. Handing the collector a separate connection
        // therefore isolates none of them, and only the shared prefix does. This is what holds them
        // to it: a settings write inside this keyspace has to reach the digest.
        const before = (await collectBeacon({ redis, logger })).fh;
        await settings.set('webhooksEnabled', true);
        try {
            const after = (await collectBeacon({ redis, logger })).fh;
            assert.notEqual(after, before, 'a settings change in this keyspace must reach the digest');
        } finally {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'webhooksEnabled');
        }
    });

    await t.test('collectBeacon() digest is stable across calls when nothing changes', async () => {
        // Nothing else in the run writes to this file's keyspace, so "nothing changes" holds for
        // real between the two calls - see the note at the top of the file.
        const first = await collectBeacon({ redis, logger });
        const second = await collectBeacon({ redis, logger });
        assert.equal(first.fh, second.fh, 'identical state must produce an identical digest');
    });
});
