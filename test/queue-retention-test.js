'use strict';

// Unit tests for lib/queue-retention.js. The module is pure and dependency-free, so this suite
// needs no Redis and no force-exit teardown.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    buildRetentionPolicy,
    COMPLETED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_AGE_DEFAULT: FAILED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_COUNT_DEFAULT: FAILED_JOB_RETENTION_COUNT
} = require('../lib/queue-retention');

// The bounds getFailedJobRetention() resolves when neither the environment nor a setting is set
const DEFAULT_RETENTION = { age: FAILED_JOB_RETENTION_AGE, count: FAILED_JOB_RETENTION_COUNT };

test('buildRetentionPolicy', async t => {
    await t.test('maps a numeric queueKeep to an age+count completed policy', () => {
        const { removeOnComplete } = buildRetentionPolicy(250, DEFAULT_RETENTION);
        assert.deepStrictEqual(removeOnComplete, { age: COMPLETED_JOB_RETENTION_AGE, count: 250 });
    });

    await t.test('never drops failed entries on arrival for the default queueKeep of 0', () => {
        // This is the regression the module exists for: queueKeep defaults to 0, and applying that
        // to removeOnFail deleted every exhausted job the moment it failed, so a webhook endpoint
        // that was down long enough to burn all 10 attempts left no record of the lost events.
        const { removeOnComplete, removeOnFail } = buildRetentionPolicy(0, DEFAULT_RETENTION);

        assert.deepStrictEqual(removeOnComplete, { age: COMPLETED_JOB_RETENTION_AGE, count: 0 });
        assert.deepStrictEqual(removeOnFail, { age: FAILED_JOB_RETENTION_AGE, count: FAILED_JOB_RETENTION_COUNT });
        assert.ok(removeOnFail.count > 0, 'failed entries must be retained');
    });

    await t.test('widens the failed floor when the operator wants to keep more', () => {
        const large = FAILED_JOB_RETENTION_COUNT * 4;
        const { removeOnFail } = buildRetentionPolicy(large, DEFAULT_RETENTION);
        assert.strictEqual(removeOnFail.count, large);
    });

    await t.test('keeps the floor when the operator wants to keep fewer', () => {
        const { removeOnFail } = buildRetentionPolicy(1, DEFAULT_RETENTION);
        assert.strictEqual(removeOnFail.count, FAILED_JOB_RETENTION_COUNT);
    });

    await t.test('removes completed entries but retains failures for a true queueKeep', () => {
        // true is the `?? true` fallback used before the setting is materialized in Redis
        const { removeOnComplete, removeOnFail } = buildRetentionPolicy(true, DEFAULT_RETENTION);
        assert.strictEqual(removeOnComplete, true);
        assert.deepStrictEqual(removeOnFail, { age: FAILED_JOB_RETENTION_AGE, count: FAILED_JOB_RETENTION_COUNT });
    });

    await t.test('retains failures longer than completed entries', () => {
        assert.ok(
            FAILED_JOB_RETENTION_AGE > COMPLETED_JOB_RETENTION_AGE,
            'a lost delivery must outlive a successful one, otherwise the record is gone before anyone looks'
        );
    });

    await t.test('returns only the two retention keys so it can be spread into job options', () => {
        assert.deepStrictEqual(Object.keys(buildRetentionPolicy(0, DEFAULT_RETENTION)).sort(), ['removeOnComplete', 'removeOnFail']);
    });
});

test('selectFailedContentToDrop', async t => {
    const { selectFailedContentToDrop } = require('../lib/queue-retention');

    const NOW = 1000000000000;
    const DAY = 24 * 3600;
    const entry = (queueId, ageSeconds, size) => ({ account: 'acc', queueId, size, finishedOn: NOW - ageSeconds * 1000 });
    const limits = extra => Object.assign({ maxCount: 3, maxBytes: 1000, maxAge: 7 * DAY, now: NOW }, extra);

    await t.test('keeps everything that fits', () => {
        const entries = [entry('a', 10, 100), entry('b', 20, 100), entry('c', 30, 100)];
        assert.deepStrictEqual(selectFailedContentToDrop(entries, limits()), []);
    });

    await t.test('drops the oldest beyond the count bound, oldest first, whatever the input order', () => {
        const entries = [entry('c', 30, 1), entry('a', 10, 1), entry('d', 40, 1), entry('b', 20, 1), entry('e', 50, 1)];
        assert.deepStrictEqual(
            selectFailedContentToDrop(entries, limits()).map(item => item.queueId),
            ['e', 'd']
        );
    });

    await t.test('drops whatever pushes the newest-first running total over the size bound', () => {
        const entries = [entry('a', 10, 600), entry('b', 20, 300), entry('c', 30, 200), entry('d', 40, 50)];
        // a (600) + b (300) = 900 fit; c would make 1100; d is only 50 but comes after c and still
        // fits - the bound is a total, so a small old entry survives a large one being dropped
        assert.deepStrictEqual(
            selectFailedContentToDrop(entries, limits()).map(item => item.queueId),
            ['c']
        );
    });

    await t.test('never keeps a content larger than the whole size bound', () => {
        assert.deepStrictEqual(
            selectFailedContentToDrop([entry('big', 10, 5000)], limits()).map(item => item.queueId),
            ['big']
        );
    });

    await t.test('drops what has aged out', () => {
        const entries = [entry('fresh', DAY, 1), entry('stale', 8 * DAY, 1)];
        assert.deepStrictEqual(
            selectFailedContentToDrop(entries, limits()).map(item => item.queueId),
            ['stale']
        );
    });

    await t.test('a bound of zero keeps nothing', () => {
        const entries = [entry('a', 10, 1), entry('b', 20, 1)];
        assert.deepStrictEqual(selectFailedContentToDrop(entries, limits({ maxCount: 0 })).length, 2);
        assert.deepStrictEqual(selectFailedContentToDrop(entries, limits({ maxBytes: 0 })).length, 2);
    });
});

test('queueCleanAges', async t => {
    const { queueCleanAges } = require('../lib/queue-retention');

    await t.test('uses the retention ages, converted to the milliseconds clean() takes', () => {
        assert.deepStrictEqual(queueCleanAges(DEFAULT_RETENTION), {
            completed: COMPLETED_JOB_RETENTION_AGE * 1000,
            failed: FAILED_JOB_RETENTION_AGE * 1000
        });
    });

    await t.test('follows the failed-job retention in effect (regression: the clean was fixed at 7 days)', () => {
        assert.strictEqual(queueCleanAges({ age: 30 * 24 * 3600, count: 500 }).failed, 30 * 24 * 3600 * 1000);
    });

    await t.test('refuses to guess when the bounds are missing, which would ignore the setting', () => {
        for (const value of [undefined, null, {}, { age: null, count: 500 }, { age: 60, count: 0 }]) {
            assert.throws(() => queueCleanAges(value), TypeError);
            assert.throws(() => buildRetentionPolicy(0, value), TypeError);
        }
    });

    await t.test('server.js cleans with these ages, not literals of its own', () => {
        const source = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'server.js'), 'utf-8');
        const calls = source.match(/\.clean\([^)]*\)/g) || [];
        assert.ok(calls.length >= 2, 'the periodic clean is still in server.js');
        for (const call of calls) {
            assert.doesNotMatch(call, /\.clean\(\s*\d/, `literal age in ${call}`);
        }
    });
});
