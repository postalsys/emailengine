'use strict';

// Export concurrency limits - drives the REAL limiter against a live Redis.
//
// tryAddToActiveSet() in lib/export.js guards two limits at once (per-account and global) with a
// single EVAL, because a read-then-write would let two concurrent export requests both observe
// "under the limit" and both start. The check and the SADD therefore have to happen inside one
// script.
//
// This used to be covered by a JS re-implementation of the script inside export-test.js, which
// could not fail when the real script changed (and had already drifted - the copy never checked
// the global limit at all). These tests call tryAddToActiveSet() itself, so the shipped Lua, the
// entry encoding and the TooManyExports error are all exercised.
//
// Uses the test Redis db (config/test.toml -> db 13) with a scoped active-set key so a parallel
// unit-test run cannot observe (or clobber) these entries.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { tryAddToActiveSet, buildActiveEntry, parseActiveEntry, generateExportId, ACTIVE_EXPORTS_KEY } = require('../lib/export');
const registerRedisTeardown = require('./helpers/redis-teardown');

const TEST_ACTIVE_KEY = `${ACTIVE_EXPORTS_KEY}:unit-test`;

// Returns true when the export was admitted, false when the limiter refused it. The refusal is
// asserted to be the documented TooManyExports/429 so a different failure cannot masquerade as a
// clean rejection.
async function admit(maxConcurrent, maxGlobal, account, exportId) {
    try {
        await tryAddToActiveSet(account, exportId, { activeKey: TEST_ACTIVE_KEY, maxConcurrent, maxGlobalConcurrent: maxGlobal });
        return true;
    } catch (err) {
        assert.strictEqual(err.code, 'TooManyExports', `unexpected failure: ${err.message}`);
        assert.strictEqual(err.statusCode, 429);
        return false;
    }
}

async function activeEntries() {
    return (await redis.smembers(TEST_ACTIVE_KEY)).sort();
}

registerRedisTeardown(redis, async () => {
    await redis.del(TEST_ACTIVE_KEY);
});

test('Export concurrency limits', async t => {
    t.beforeEach(async () => {
        await redis.del(TEST_ACTIVE_KEY);
    });

    await t.test('an export under both limits is admitted and recorded in the active set', async () => {
        assert.strictEqual(await admit(3, 10, 'account1', 'exp_1'), true);
        assert.deepStrictEqual(await activeEntries(), ['account1:exp_1']);
    });

    await t.test('the per-account limit rejects once the account is at its cap', async () => {
        assert.strictEqual(await admit(3, 10, 'account1', 'exp_1'), true);
        assert.strictEqual(await admit(3, 10, 'account1', 'exp_2'), true);
        assert.strictEqual(await admit(3, 10, 'account1', 'exp_3'), true);

        assert.strictEqual(await admit(3, 10, 'account1', 'exp_4'), false, 'the fourth export must be rejected');
        assert.strictEqual((await activeEntries()).length, 3, 'a rejected export must not be added to the active set');
    });

    await t.test('other accounts do not count against an account limit', async () => {
        await admit(3, 10, 'account2', 'exp_1');
        await admit(3, 10, 'account2', 'exp_2');
        await admit(3, 10, 'account2', 'exp_3');

        assert.strictEqual(await admit(3, 10, 'account1', 'exp_1'), true, 'account1 is still idle and must be admitted');
    });

    await t.test('the global limit rejects even when the account is idle', async () => {
        assert.strictEqual(await admit(5, 2, 'a', 'exp_1'), true);
        assert.strictEqual(await admit(5, 2, 'b', 'exp_1'), true);

        assert.strictEqual(await admit(5, 2, 'c', 'exp_1'), false, 'the global cap applies to a brand new account too');
        assert.deepStrictEqual(await activeEntries(), ['a:exp_1', 'b:exp_1']);
    });

    await t.test('check and add are atomic - a burst of concurrent requests can not overshoot the limit', async () => {
        // The TOCTOU regression this guards: with a separate SMEMBERS + SADD, every one of these
        // 20 in-flight requests reads an empty set and all 20 start.
        const results = await Promise.all(Array.from({ length: 20 }, (unused, i) => admit(1, 10, 'account1', `exp_${i}`)));

        const admitted = results.filter(Boolean);
        assert.strictEqual(admitted.length, 1, `exactly one export may be admitted with maxConcurrent 1, got ${admitted.length}`);
        assert.strictEqual((await activeEntries()).length, 1);
    });

    await t.test('the global limit is atomic across accounts too', async () => {
        const results = await Promise.all(Array.from({ length: 20 }, (unused, i) => admit(10, 3, `account${i}`, 'exp_1')));

        assert.strictEqual(results.filter(Boolean).length, 3, 'exactly maxGlobal exports may be admitted no matter how many accounts request at once');
        assert.strictEqual((await activeEntries()).length, 3);
    });

    await t.test('the account prefix is anchored, so a longer account name is not counted', async () => {
        await admit(1, 10, 'account10', 'exp_1');

        // "account1:" is not a prefix of "account10:exp_1" - the trailing colon anchors the match
        assert.strictEqual(await admit(1, 10, 'account1', 'exp_1'), true, 'account1 must not be charged for account10 exports');
    });

    await t.test('an account id that is a colon-prefix of another keeps its own budget', async () => {
        // Colons are legal in account ids (accountIdSchema is a free-form string), so the entry
        // "user:sub:exp_1" starts with the prefix of the account "user". The limiter requires the
        // remainder to be the export id, which is the same boundary parseActiveEntry() splits on -
        // otherwise "user" would be throttled by an unrelated account's exports.
        await admit(1, 10, 'user:sub', 'exp_1');

        assert.strictEqual(await admit(1, 10, 'user', 'exp_1'), true, '"user" must not be charged for the "user:sub" export');
        assert.deepStrictEqual(await activeEntries(), ['user:exp_1', 'user:sub:exp_1']);
    });

    await t.test('the limiter and the interrupted-export scan agree on who owns an entry', async () => {
        // The bug this pins: the Lua counted by raw prefix while markInterruptedAsFailed() splits
        // on the last ':exp_'. The two disagreed for colon-containing account ids, so an export
        // could be counted against one account and recovered as another.
        for (const account of ['plain', 'user:sub', 'a:b:c']) {
            const entry = buildActiveEntry(account, 'exp_abc123');
            assert.deepStrictEqual(parseActiveEntry(entry), { account, exportId: 'exp_abc123' });
        }

        assert.strictEqual(parseActiveEntry('no-export-id-here'), false);
        assert.strictEqual(parseActiveEntry(':exp_orphan'), false, 'an entry with no account is not usable');
    });

    await t.test('an explicit limit of 0 admits nothing', async () => {
        // A stored setting of 0 never reaches the script - tryAddToActiveSet() falls back to the
        // default for any falsy stored value, because 0 would refuse every export in the
        // deployment forever. An explicit override still has to fail closed.
        assert.strictEqual(await admit(0, 10, 'account1', 'exp_1'), false);
        assert.strictEqual(await admit(10, 0, 'account1', 'exp_1'), false);
        assert.deepStrictEqual(await activeEntries(), []);
    });

    await t.test('the limiter counts real generated export ids', async () => {
        // The ownership boundary the script checks comes from EXPORT_ID_PREFIX, passed in as an
        // argument. Driving this with generateExportId() rather than a hand-written "exp_1" is
        // what makes a change to that constant fail here instead of silently leaving the
        // per-account limit counting nothing - a limit that fails OPEN, with no error and no log.
        assert.strictEqual(await admit(1, 10, 'account1', generateExportId()), true);
        assert.strictEqual(await admit(1, 10, 'account1', generateExportId()), false, 'the second export is charged to the same account');
        assert.strictEqual((await activeEntries()).length, 1);
    });

    await t.test('every entry the limiter writes can be parsed back by the cleanup path', async () => {
        // The stale-entry sweep in workers/export.js and markInterruptedAsFailed() both remove
        // entries through parseActiveEntry(). An entry that does not round trip is never removed:
        // the active set grows monotonically until globalCount >= maxGlobal is permanently true
        // and every export in the deployment is refused with 429.
        for (const account of ['plain', 'user:sub', 'a:b:c']) {
            assert.strictEqual(await admit(10, 10, account, generateExportId()), true);
        }

        const stored = await activeEntries();
        assert.strictEqual(stored.length, 3);

        for (const entry of stored) {
            const parsed = parseActiveEntry(entry);
            assert.ok(parsed, `the cleanup must be able to parse ${entry}`);
            assert.strictEqual(buildActiveEntry(parsed.account, parsed.exportId), entry, 'the encoding and the split must be exact inverses');
        }
    });
});
