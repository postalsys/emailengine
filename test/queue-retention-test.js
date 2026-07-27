'use strict';

// Unit tests for lib/queue-retention.js. The module is pure and dependency-free, so this suite
// needs no Redis and no force-exit teardown.

const test = require('node:test');
const assert = require('node:assert').strict;

const { buildRetentionPolicy, COMPLETED_JOB_RETENTION_AGE, FAILED_JOB_RETENTION_AGE, FAILED_JOB_RETENTION_COUNT } = require('../lib/queue-retention');

test('buildRetentionPolicy', async t => {
    await t.test('maps a numeric queueKeep to an age+count completed policy', () => {
        const { removeOnComplete } = buildRetentionPolicy(250);
        assert.deepStrictEqual(removeOnComplete, { age: COMPLETED_JOB_RETENTION_AGE, count: 250 });
    });

    await t.test('never drops failed entries on arrival for the default queueKeep of 0', () => {
        // This is the regression the module exists for: queueKeep defaults to 0, and applying that
        // to removeOnFail deleted every exhausted job the moment it failed, so a webhook endpoint
        // that was down long enough to burn all 10 attempts left no record of the lost events.
        const { removeOnComplete, removeOnFail } = buildRetentionPolicy(0);

        assert.deepStrictEqual(removeOnComplete, { age: COMPLETED_JOB_RETENTION_AGE, count: 0 });
        assert.deepStrictEqual(removeOnFail, { age: FAILED_JOB_RETENTION_AGE, count: FAILED_JOB_RETENTION_COUNT });
        assert.ok(removeOnFail.count > 0, 'failed entries must be retained');
    });

    await t.test('widens the failed floor when the operator wants to keep more', () => {
        const large = FAILED_JOB_RETENTION_COUNT * 4;
        const { removeOnFail } = buildRetentionPolicy(large);
        assert.strictEqual(removeOnFail.count, large);
    });

    await t.test('keeps the floor when the operator wants to keep fewer', () => {
        const { removeOnFail } = buildRetentionPolicy(1);
        assert.strictEqual(removeOnFail.count, FAILED_JOB_RETENTION_COUNT);
    });

    await t.test('removes completed entries but retains failures for a true queueKeep', () => {
        // true is the `?? true` fallback used before the setting is materialized in Redis
        const { removeOnComplete, removeOnFail } = buildRetentionPolicy(true);
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
        assert.deepStrictEqual(Object.keys(buildRetentionPolicy(0)).sort(), ['removeOnComplete', 'removeOnFail']);
    });
});
