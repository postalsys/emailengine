'use strict';

// The guard scripts under lib/lua/ against a real Redis: h-del-if-equals.lua, and the three that
// fold a read-decide-write sequence into one step (ee-reserve-attempts.lua,
// ee-release-attempts.lua, ee-export-queue-add.lua).
//
// h-del-if-equals.lua exists because a caller reads a hash field, decides something about the
// value it read, and then writes based on that decision - with awaits in between, so the field
// can have been replaced by the time the write lands. The compare is what makes the decision and
// the write one step. Its only caller (BaseClient.clearStoredErrorState, reached from the Outlook
// subscription recovery) is tested against a stubbed Redis, so nothing else runs the script
// itself, and a typo in it would only surface the first time an account recovered. Its sibling
// h-set-if-equals.lua needs no suite of its own: lib/tls/store.js calls it, and
// test/tls-store-test.js drives that call against a real Redis, race included.
//
// The budget scripts are driven through lib/rate-limit.js by test/rate-limit-test.js and the
// auth suites; the cases here are the script-level edges those callers never reach.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_lua_guards';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

const KEY = `${REDIS_PREFIX}guarded-hash`;
const BUDGET_KEYS = [`${REDIS_PREFIX}budget-a`, `${REDIS_PREFIX}budget-b`];
const EXPORT_KEY = `${REDIS_PREFIX}export-record`;
const EXPORT_QUEUE_KEY = `${REDIS_PREFIX}export-queue`;

registerRedisTeardown(redis, async () => {
    await redis.del(KEY, ...BUDGET_KEYS, EXPORT_KEY, EXPORT_QUEUE_KEY);
});

test('hDelIfEquals', async t => {
    t.beforeEach(async () => {
        await redis.del(KEY);
    });

    await t.test('drops every named field while the guard still matches', async () => {
        await redis.hset(KEY, { lastErrorState: 'the failure', lastErrorEvent: 'connectError', count: '3', unrelated: 'kept' });

        assert.equal(await redis.hDelIfEquals(KEY, 'lastErrorState', 'the failure', 'lastErrorState', 'lastErrorEvent', 'count'), 1);
        assert.deepEqual(await redis.hgetall(KEY), { unrelated: 'kept' });
    });

    await t.test('leaves everything alone once the guard has moved on', async () => {
        await redis.hset(KEY, { lastErrorState: 'a newer failure', lastErrorEvent: 'authenticationError' });

        assert.equal(await redis.hDelIfEquals(KEY, 'lastErrorState', 'the failure', 'lastErrorState', 'lastErrorEvent'), 0);
        assert.deepEqual(await redis.hgetall(KEY), { lastErrorState: 'a newer failure', lastErrorEvent: 'authenticationError' });
    });

    await t.test('accepts an absent guard as the empty string', async () => {
        // What a caller that read no error state passes: there was nothing to judge, and the
        // leftovers of an earlier run are still cleared
        await redis.hset(KEY, 'count', '3');

        assert.equal(await redis.hDelIfEquals(KEY, 'lastErrorState', '', 'lastErrorState', 'count'), 1);
        assert.deepEqual(await redis.hgetall(KEY), {});
    });

    await t.test('is happy to delete fields that are not there', async () => {
        assert.equal(await redis.hDelIfEquals(KEY, 'lastErrorState', '', 'lastErrorState', 'count'), 1);
    });
});

test('eeReserveAttempts / eeReleaseAttempts', async t => {
    t.beforeEach(async () => {
        await redis.del(...BUDGET_KEYS);
    });

    await t.test('gives each budget its own limit and TTL', async () => {
        const [a, b] = BUDGET_KEYS;

        assert.deepEqual(await redis.eeReserveAttempts(2, a, b, 1, 60, 5, 3600), [1, 1, 1]);
        assert.ok((await redis.ttl(a)) <= 60);
        assert.ok((await redis.ttl(b)) > 60, 'the second budget lives for its own window');

        // the first budget is spent, so neither is charged
        assert.deepEqual(await redis.eeReserveAttempts(2, a, b, 1, 60, 5, 3600), [0, 1, 1]);
        assert.equal(await redis.get(b), '1');
    });

    await t.test('a limit already exceeded from outside still refuses and does not go lower', async () => {
        const [a] = BUDGET_KEYS;
        await redis.set(a, '7');

        assert.deepEqual(await redis.eeReserveAttempts(1, a, 3, 60), [0, 7]);
        assert.equal(await redis.get(a), '7');
    });

    await t.test('a release never creates a counter or takes one below zero', async () => {
        const [a, b] = BUDGET_KEYS;
        await redis.set(a, '1');

        assert.equal(await redis.eeReleaseAttempts(2, a, b), 1);
        assert.equal(await redis.exists(a), 0, 'a counter back at zero is deleted');
        assert.equal(await redis.exists(b), 0, 'a counter that was not there is not created');
    });
});

test('eeExportQueueAdd', async t => {
    t.beforeEach(async () => {
        await redis.del(EXPORT_KEY, EXPORT_QUEUE_KEY);
    });

    await t.test('queues a message once, counts it once, and keeps the queue alive with the record', async () => {
        await redis.hset(EXPORT_KEY, { exportId: 'exp_1', messagesQueued: '0' });
        await redis.expire(EXPORT_KEY, 600);

        assert.equal(await redis.eeExportQueueAdd(EXPORT_KEY, EXPORT_QUEUE_KEY, 10, 'm1', 'messagesQueued'), 1);
        // the retry of a folder that already queued this message
        assert.equal(await redis.eeExportQueueAdd(EXPORT_KEY, EXPORT_QUEUE_KEY, 10, 'm1', 'messagesQueued'), 0);
        assert.equal(await redis.eeExportQueueAdd(EXPORT_KEY, EXPORT_QUEUE_KEY, 11, 'm2', 'messagesQueued'), 1);

        assert.equal(await redis.hget(EXPORT_KEY, 'messagesQueued'), '2');
        assert.equal(await redis.zcard(EXPORT_QUEUE_KEY), 2);
        const ttl = await redis.ttl(EXPORT_QUEUE_KEY);
        assert.ok(ttl > 0 && ttl <= 600, 'the queue expires with the record');
    });

    await t.test('a record without an expiry leaves the queue without one', async () => {
        await redis.hset(EXPORT_KEY, { exportId: 'exp_1' });

        assert.equal(await redis.eeExportQueueAdd(EXPORT_KEY, EXPORT_QUEUE_KEY, 10, 'm1', 'messagesQueued'), 1);
        assert.equal(await redis.ttl(EXPORT_QUEUE_KEY), -1);
        assert.equal(await redis.hget(EXPORT_KEY, 'messagesQueued'), '1');
    });

    await t.test('a deleted record is not brought back as a bare counter', async () => {
        assert.equal(await redis.eeExportQueueAdd(EXPORT_KEY, EXPORT_QUEUE_KEY, 10, 'm1', 'messagesQueued'), 1);
        assert.equal(await redis.exists(EXPORT_KEY), 0);
    });
});
