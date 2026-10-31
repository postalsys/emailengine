'use strict';

// The cluster's Redis operations and their Lua scripts (lib/cluster/store.js, lib/lua/cluster-*.lua,
// lib/lua/account-set-state.lua) against a real Redis. These are the compare-and-set steps that keep
// two instances from both believing they own an account.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_cluster_store';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { clusterKeys } = require('../lib/cluster/keys');
const store = require('../lib/cluster/store');
const registerRedisTeardown = require('./helpers/redis-teardown');

async function cleanup() {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
}

registerRedisTeardown(redis, cleanup);

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function createAccount(account, fields = {}) {
    await redis.hset(clusterKeys.account(account), Object.assign({ account, state: 'init' }, fields));
    await redis.sadd(clusterKeys.accounts, account);
}

test('membership records', async t => {
    t.beforeEach(cleanup);

    await t.test('register, renew and list', async () => {
        assert.equal(await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: { ready: 1, runIndex: 4, address: '10.0.0.1:3001' } }), true);
        const live = await store.listLive(redis);
        assert.deepEqual([...live.keys()], ['a']);
        assert.equal(live.get('a').ready, true);
        assert.equal(live.get('a').runIndex, 4);
        assert.equal(live.get('a').address, '10.0.0.1:3001');
        assert.equal(live.get('a').token, undefined, 'the token is never handed out');

        assert.equal(await store.renew(redis, { id: 'a', token: 't1', ttl: 5000, record: { owned: 3, connections: { connected: 2 } } }), true);
        const renewed = (await store.listLive(redis)).get('a');
        assert.equal(renewed.owned, 3);
        assert.deepEqual(renewed.connections, { connected: 2 });
    });

    await t.test('a live record of another run blocks the id; the same run may register again', async () => {
        assert.equal(await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} }), true);
        assert.equal(await store.register(redis, { id: 'a', token: 't2', ttl: 5000, record: {} }), false);
        assert.equal(await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} }), true);
    });

    await t.test('an expired record cannot be renewed, and frees the id', async () => {
        assert.equal(await store.register(redis, { id: 'a', token: 't1', ttl: 100, record: {} }), true);
        await sleep(150);
        assert.equal(await store.renew(redis, { id: 'a', token: 't1', ttl: 5000, record: {} }), false, 'renewal does not bring the record back');
        assert.equal(await store.register(redis, { id: 'a', token: 't2', ttl: 5000, record: {} }), true);
    });

    await t.test('renewal with a stale token is refused', async () => {
        await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} });
        assert.equal(await store.renew(redis, { id: 'a', token: 'other', ttl: 5000, record: {} }), false);
    });

    await t.test('an expired member is pruned from the set, a live one never is', async () => {
        await store.register(redis, { id: 'a', token: 't1', ttl: 100, record: {} });
        await store.register(redis, { id: 'b', token: 't1', ttl: 5000, record: {} });
        await sleep(150);
        const live = await store.listLive(redis);
        assert.deepEqual([...live.keys()], ['b']);
        assert.deepEqual(await redis.smembers(clusterKeys.instances), ['b']);
    });

    await t.test('prune leaves an id whose record came back in between', async () => {
        await redis.sadd(clusterKeys.instances, 'a');
        await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} });
        assert.equal(await redis.clusterPrune(clusterKeys.instance('a'), clusterKeys.instances, 'a'), 0);
        assert.equal(await redis.sismember(clusterKeys.instances, 'a'), 1);
    });

    await t.test('renewal puts a pruned id back into the set', async () => {
        await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} });
        await redis.srem(clusterKeys.instances, 'a');
        await store.renew(redis, { id: 'a', token: 't1', ttl: 5000, record: {} });
        assert.equal(await redis.sismember(clusterKeys.instances, 'a'), 1);
    });

    await t.test('leave removes only its own run', async () => {
        await store.register(redis, { id: 'a', token: 't1', ttl: 5000, record: {} });
        assert.equal(await store.leave(redis, { id: 'a', token: 'other' }), false);
        assert.equal((await store.listLive(redis)).has('a'), true);
        assert.equal(await store.leave(redis, { id: 'a', token: 't1' }), true);
        assert.equal((await store.listLive(redis)).has('a'), false);
    });
});

test('account ownership', async t => {
    t.beforeEach(cleanup);

    await t.test('claim with the expected owner, and record the run', async () => {
        await createAccount('acc');
        const outcome = await store.claim(redis, [{ account: 'acc', expected: '' }], 'a', 7);
        assert.deepEqual(outcome.claimed, ['acc']);
        assert.equal(await store.readOwner(redis, 'acc'), 'a');
        assert.equal(await redis.hget(clusterKeys.account('acc'), 'ownerRun'), '7');
    });

    await t.test('of two claims made from the same view only one wins', async () => {
        await createAccount('acc');
        const [first, second] = await Promise.all([
            store.claim(redis, [{ account: 'acc', expected: '' }], 'a', 1),
            store.claim(redis, [{ account: 'acc', expected: '' }], 'b', 2)
        ]);
        assert.equal(first.claimed.length + second.claimed.length, 1);
        const loser = first.claimed.length ? second : first;
        assert.equal(loser.lost.length, 1);
        assert.equal(loser.lost[0].owner, first.claimed.length ? 'a' : 'b', 'the loser learns who won');
    });

    await t.test('takeover from a dead owner needs that owner to still be recorded', async () => {
        await createAccount('acc');
        await store.claim(redis, [{ account: 'acc', expected: '' }], 'dead', 1);
        assert.deepEqual((await store.claim(redis, [{ account: 'acc', expected: 'other' }], 'b', 2)).claimed, []);
        assert.deepEqual((await store.claim(redis, [{ account: 'acc', expected: 'dead' }], 'b', 2)).claimed, ['acc']);
    });

    await t.test('a deleted account is not claimed, and a stale owner record is removed', async () => {
        await redis.set(clusterKeys.owner('gone'), 'dead');
        const outcome = await store.claim(redis, [{ account: 'gone', expected: 'dead' }], 'a', 1);
        assert.deepEqual(outcome.gone, ['gone']);
        assert.equal(await redis.exists(clusterKeys.owner('gone')), 0);
        assert.equal(await redis.exists(clusterKeys.account('gone')), 0, 'the account record is not recreated');
    });

    await t.test('release only by the owner', async () => {
        await createAccount('acc');
        await store.claim(redis, [{ account: 'acc', expected: '' }], 'a', 1);
        assert.deepEqual(await store.release(redis, ['acc'], 'b'), []);
        assert.equal(await store.readOwner(redis, 'acc'), 'a');
        assert.deepEqual(await store.release(redis, ['acc'], 'a'), ['acc']);
        assert.equal(await store.readOwner(redis, 'acc'), null);
    });

    await t.test('large batches are read and claimed in chunks', async () => {
        const list = Array.from({ length: 1234 }, (_, i) => `bulk${i}`);
        for (const account of list) {
            await createAccount(account);
        }
        const outcome = await store.claim(
            redis,
            list.map(account => ({ account, expected: '' })),
            'a',
            1
        );
        assert.equal(outcome.claimed.length, list.length);
        const owners = await store.readOwners(redis, list);
        assert.equal([...owners.values()].filter(owner => owner === 'a').length, list.length);
    });

    await t.test('the signing secret is created once', async () => {
        const first = await store.ensureSecret(redis);
        const second = await store.ensureSecret(redis);
        assert.equal(first.length, 32);
        assert.deepEqual(first, second);
    });
});

test('account-set-state.lua', async t => {
    t.beforeEach(cleanup);

    const key = clusterKeys.account('acc');

    await t.test('writes the state and the run, and counts it', async () => {
        await createAccount('acc', { 'state:count:connected': '0' });
        assert.deepEqual(await redis.accountSetState(key, 'connected', '5'), [1, '0', 1]);
        assert.equal(await redis.hget(key, 'state'), 'connected');
        assert.equal(await redis.hget(key, 'runIndex'), '5');
        assert.deepEqual(await redis.accountSetState(key, 'connected', '5'), [1, '1', 2]);
    });

    await t.test('a state without a counter yet reports no previous count', async () => {
        await createAccount('acc');
        assert.deepEqual(await redis.accountSetState(key, 'syncing', '5'), [1, null, 1]);
    });

    await t.test('refuses a run that does not own the account', async () => {
        await createAccount('acc', { ownerRun: '9', state: 'connected', runIndex: '9' });
        assert.deepEqual(await redis.accountSetState(key, 'disconnected', '5'), [-1]);
        assert.equal(await redis.hget(key, 'state'), 'connected');
        assert.equal(await redis.hget(key, 'runIndex'), '9');
        assert.deepEqual((await redis.accountSetState(key, 'syncing', '9'))[0], 1);
    });

    await t.test('does not recreate a deleted account', async () => {
        assert.deepEqual(await redis.accountSetState(key, 'connected', '5'), [0]);
        assert.equal(await redis.exists(key), 0);
    });
});
