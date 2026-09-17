'use strict';

// The one-time sweep of the bounce store that fed the removed `bounces` response field. It runs
// against the test Redis, because what it exercises is the walk over the account set.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { sweepBounceStore, SWEEP_KEY } = require('../lib/account/bounce-store-sweep');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

const ACCOUNTS_KEY = `${REDIS_PREFIX}ia:accounts`;
const accounts = ['sweep-test-a', 'sweep-test-b'];
const storeKey = account => `${REDIS_PREFIX}iar:b:${account}`;
// A sibling per-account key of the same account that must survive
const bystander = `${REDIS_PREFIX}iar:s:sweep-test-a`;

async function reset() {
    await redis
        .multi()
        .del(SWEEP_KEY, ...accounts.map(storeKey), bystander)
        .srem(ACCOUNTS_KEY, ...accounts)
        .exec();
}

registerRedisTeardown(redis, reset);

test('sweepBounceStore()', async t => {
    t.beforeEach(reset);

    await t.test('deletes the store of every account once and records that it ran', async () => {
        await redis.sadd(ACCOUNTS_KEY, ...accounts);
        for (const account of accounts) {
            await redis.hset(storeKey(account), '<orig@example.com>', 'record');
        }
        await redis.hset(bystander, 'field', 'value');

        assert.equal(await sweepBounceStore({ redis, logger: noopLogger }), accounts.length);

        assert.equal(await redis.exists(...accounts.map(storeKey)), 0);
        assert.equal(await redis.exists(bystander), 1, 'the other per-account keys stay');
        assert.ok(await redis.get(SWEEP_KEY), 'the completion key is set');
    });

    await t.test('does not run again once it has completed', async () => {
        await redis.set(SWEEP_KEY, new Date().toISOString());
        await redis.sadd(ACCOUNTS_KEY, accounts[0]);
        await redis.hset(storeKey(accounts[0]), '<orig@example.com>', 'record');

        assert.equal(await sweepBounceStore({ redis, logger: noopLogger }), 0);

        assert.equal(await redis.exists(storeKey(accounts[0])), 1);
    });
});
