'use strict';

// lib/lua/h-del-if-equals.lua against a real Redis.
//
// It exists because a caller reads a hash field, decides something about the value it read, and
// then writes based on that decision - with awaits in between, so the field can have been replaced
// by the time the write lands. The compare is what makes the decision and the write one step.
//
// Its only caller (BaseClient.clearStoredErrorState, reached from the Outlook subscription
// recovery) is tested against a stubbed Redis, so nothing else runs the script itself, and a typo
// in it would only surface the first time an account recovered. Its sibling h-set-if-equals.lua
// needs no suite of its own: lib/tls/store.js calls it, and test/tls-store-test.js drives that
// call against a real Redis, race included.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_lua_guards';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

const KEY = `${REDIS_PREFIX}guarded-hash`;

registerRedisTeardown(redis, async () => {
    await redis.del(KEY);
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
