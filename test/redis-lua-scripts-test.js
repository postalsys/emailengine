'use strict';

// The hash and listing Lua scripts in lib/lua/ against a real Redis. Every caller of these is
// tested against a stubbed client, so without this a typo, or a Lua error on an unexpected stored
// value, would first show up in production - and a Lua error inside a MULTI fails every command
// queued with it.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_lua_scripts';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

async function cleanup() {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
}

registerRedisTeardown(redis, cleanup);

const HASH = `${REDIS_PREFIX}hash`;

test('hSetBigger', async t => {
    t.beforeEach(async () => {
        await redis.del(HASH);
    });

    await t.test('does nothing when the hash does not exist', async () => {
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '5'), 0);
        assert.equal(await redis.exists(HASH), 0);
    });

    await t.test('creates the field on an existing hash', async () => {
        await redis.hset(HASH, 'account', 'a');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '5'), 2);
        assert.equal(await redis.hget(HASH, 'runIndex'), '5');
    });

    await t.test('replaces only with a bigger value', async () => {
        await redis.hset(HASH, 'runIndex', '5');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '4'), 1);
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '5'), 1);
        assert.equal(await redis.hget(HASH, 'runIndex'), '5');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '12'), 3);
        assert.equal(await redis.hget(HASH, 'runIndex'), '12', 'compared as numbers, not strings');
    });

    await t.test('replaces a stored value that is not a number instead of raising an error', async () => {
        await redis.hset(HASH, 'runIndex', 'garbage');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', '3'), 3);
        assert.equal(await redis.hget(HASH, 'runIndex'), '3');
    });

    await t.test('never stores a new value that is not a number', async () => {
        await redis.hset(HASH, 'runIndex', '3');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', 'NaN-ish'), 1);
        assert.equal(await redis.hget(HASH, 'runIndex'), '3');

        await redis.hdel(HASH, 'runIndex');
        assert.equal(await redis.hSetBigger(HASH, 'runIndex', 'NaN-ish'), 1);
        assert.equal(await redis.hexists(HASH, 'runIndex'), 0);
    });

    await t.test('an error in a MULTI no longer fails the neighbouring commands', async () => {
        await redis.hset(HASH, 'runIndex', 'garbage');
        const results = await redis.multi().hSetBigger(HASH, 'runIndex', '7').hset(HASH, 'other', 'x').exec();
        assert.deepEqual(
            results.map(([err]) => err),
            [null, null]
        );
        assert.equal(await redis.hget(HASH, 'other'), 'x');
    });
});

test('hUpdateBigger', async t => {
    t.beforeEach(async () => {
        await redis.del(HASH);
    });

    await t.test('creates a missing field', async () => {
        assert.equal(await redis.hUpdateBigger(HASH, 'uidNext', '10', '10'), 1);
        assert.equal(await redis.hget(HASH, 'uidNext'), '10');
    });

    await t.test('updates only while the stored value is below the threshold', async () => {
        await redis.hset(HASH, 'uidNext', '10');
        assert.equal(await redis.hUpdateBigger(HASH, 'uidNext', '10', '20'), 0);
        assert.equal(await redis.hget(HASH, 'uidNext'), '10');
        assert.equal(await redis.hUpdateBigger(HASH, 'uidNext', '11', '20'), 2);
        assert.equal(await redis.hget(HASH, 'uidNext'), '20');
    });

    await t.test('treats a stored value that is not a number as lower', async () => {
        await redis.hset(HASH, 'uidNext', 'garbage');
        assert.equal(await redis.hUpdateBigger(HASH, 'uidNext', '1', '5'), 2);
        assert.equal(await redis.hget(HASH, 'uidNext'), '5');
    });
});

test('hIncrbyExists', async t => {
    await redis.del(HASH);

    await t.test('does not create a deleted hash', async () => {
        assert.equal(await redis.hIncrbyExists(HASH, 'count', '1'), 0);
        assert.equal(await redis.exists(HASH), 0);
    });

    await t.test('increments on an existing hash', async () => {
        await redis.hset(HASH, 'account', 'a');
        assert.equal(await redis.hIncrbyExists(HASH, 'count', '2'), 2);
        assert.equal(await redis.hIncrbyExists(HASH, 'count', '3'), 5);
    });
});

test('eeGetIdempotency', async t => {
    const prefix = `${REDIS_PREFIX}idempotency:bucket:`;
    const buckets = '20260101,20260102';

    t.beforeEach(async () => {
        await redis.del(`${prefix}20260101`, `${prefix}20260102`);
    });

    await t.test('creates a pending entry in the newest bucket', async () => {
        const result = JSON.parse(await redis.eeGetIdempotency(prefix, 'key-1', 3, 7, buckets));
        assert.deepEqual(result, { status: 'new', runIndex: 3, threadId: 7, bucketKey: `${prefix}20260102` });

        const stored = JSON.parse(await redis.hget(`${prefix}20260102`, 'key-1'));
        assert.deepEqual(stored, { status: 'pending', runIndex: 3, threadId: 7 });
        assert.ok((await redis.ttl(`${prefix}20260102`)) > 0);
    });

    await t.test('returns an entry of the same run as it is', async () => {
        await redis.hset(`${prefix}20260101`, 'key-1', JSON.stringify({ status: 'completed', runIndex: 3, threadId: 7, result: 'ok' }));
        const result = JSON.parse(await redis.eeGetIdempotency(prefix, 'key-1', 3, 7, buckets));
        assert.equal(result.status, 'completed');
        assert.equal(result.result, 'ok');
        assert.equal(result.bucketKey, `${prefix}20260101`);
    });

    await t.test('replaces a pending entry of an earlier run', async () => {
        await redis.hset(`${prefix}20260102`, 'key-1', JSON.stringify({ status: 'pending', runIndex: 2, threadId: 7 }));
        const result = JSON.parse(await redis.eeGetIdempotency(prefix, 'key-1', 3, 7, buckets));
        assert.equal(result.status, 'new');
    });

    await t.test('replaces an unreadable entry instead of raising an error', async () => {
        await redis.hset(`${prefix}20260102`, 'key-1', '{not json');
        const result = JSON.parse(await redis.eeGetIdempotency(prefix, 'key-1', 3, 7, buckets));
        assert.equal(result.status, 'new');
        assert.deepEqual(JSON.parse(await redis.hget(`${prefix}20260102`, 'key-1')), { status: 'pending', runIndex: 3, threadId: 7 });
    });

    await t.test('replaces a pending entry without a numeric run index', async () => {
        await redis.hset(`${prefix}20260102`, 'key-1', JSON.stringify({ status: 'pending', threadId: 7 }));
        const result = JSON.parse(await redis.eeGetIdempotency(prefix, 'key-1', 3, 7, buckets));
        assert.equal(result.status, 'new');
    });
});

test('sListAccounts', async t => {
    const listKey = `${REDIS_PREFIX}ia:accounts`;
    const accounts = [
        { account: 'acc-01', name: 'Alice', email: 'alice@example.com', state: 'connected' },
        { account: 'acc-02', name: 'Bob', email: 'bob@example.com', state: 'authenticationError' },
        { account: 'acc-03', name: 'Carol', email: 'carol@example.com', state: 'connected' },
        { account: 'acc-04', name: 'Dave', email: 'dave@example.org', state: 'connectError' },
        { account: 'acc-05', name: 'Eve', email: 'eve@example.org', state: 'connected' }
    ];

    await redis.del(listKey);
    for (const entry of accounts) {
        await redis.sadd(listKey, entry.account);
        await redis.hset(`${REDIS_PREFIX}iad:${entry.account}`, entry);
    }

    const list = async (state, skip, count, search) => {
        const [total, usedSkip, rows] = await redis.sListAccounts(listKey, state, skip, count, REDIS_PREFIX, search || '');
        const ids = rows.map(row => {
            const obj = {};
            for (let i = 0; i < row.length; i += 2) {
                obj[row[i]] = row[i + 1];
            }
            return obj.account;
        });
        return { total, skip: usedSkip, ids };
    };

    await t.test('pages through every account in id order', async () => {
        assert.deepEqual(await list('*', 0, 2), { total: 5, skip: 0, ids: ['acc-01', 'acc-02'] });
        assert.deepEqual(await list('*', 2, 2), { total: 5, skip: 2, ids: ['acc-03', 'acc-04'] });
        assert.deepEqual(await list('*', 4, 2), { total: 5, skip: 4, ids: ['acc-05'] });
    });

    await t.test('filters by one state or a list of states', async () => {
        assert.deepEqual(await list('connected', 0, 10), { total: 3, skip: 0, ids: ['acc-01', 'acc-03', 'acc-05'] });
        assert.deepEqual(await list('authenticationError,connectError', 0, 10), { total: 2, skip: 0, ids: ['acc-02', 'acc-04'] });
        assert.deepEqual(await list('connected', 1, 1), { total: 3, skip: 1, ids: ['acc-03'] });
    });

    await t.test('searches account id, name and address, case-insensitively', async () => {
        assert.deepEqual(await list('*', 0, 10, 'EXAMPLE.ORG'), { total: 2, skip: 0, ids: ['acc-04', 'acc-05'] });
        assert.deepEqual(await list('*', 0, 10, 'carol'), { total: 1, skip: 0, ids: ['acc-03'] });
        assert.deepEqual(await list('connected', 0, 10, 'example.org'), { total: 1, skip: 0, ids: ['acc-05'] });
    });

    await t.test('a page past the end reports the matching total, not every account', async () => {
        assert.deepEqual(await list('*', 10, 2), { total: 5, skip: 10, ids: [] });
        assert.deepEqual(await list('connected', 10, 2), { total: 3, skip: 10, ids: [] });
        assert.deepEqual(await list('*', 10, 2, 'example.org'), { total: 2, skip: 10, ids: [] });
    });
});
