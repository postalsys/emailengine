'use strict';

// Unit tests for lib/redis-memory-warnings.js, the dashboard's Redis memory banners.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redisMemoryWarnings } = require('../lib/redis-memory-warnings');

const MB = 1024 * 1024;
const keys = info => redisMemoryWarnings(info).map(w => `${w.key}:${w.color}`);

test('redisMemoryWarnings', async t => {
    await t.test('reports nothing for a healthy noeviction instance', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: 1000 * MB, used_memory: 100 * MB, evicted_keys: 0 }), []);
    });

    await t.test('reports nothing about the limit when Redis has none', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: 0, used_memory: 900 * MB }), []);
    });

    await t.test('warns once used memory reaches 80% of maxmemory', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: 1000 * MB, used_memory: 799 * MB }), []);
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: 1000 * MB, used_memory: 800 * MB }), ['memory-limit:warning']);
    });

    await t.test('turns red at 95%, where writes are about to be refused', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: 1000 * MB, used_memory: 950 * MB }), ['memory-limit:danger']);
    });

    await t.test('names both sizes and caps the share at 100%', () => {
        let [warning] = redisMemoryWarnings({ maxmemory_policy: 'noeviction', maxmemory: 512 * MB, used_memory: 600 * MB });
        assert.match(warning.details[0], /600 MB of its 512 MB "maxmemory" limit \(100%\)/);
    });

    await t.test('reports evicted keys ahead of the policy', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'allkeys-lru', maxmemory: 1000 * MB, used_memory: 10 * MB, evicted_keys: 3 }), ['evicted-keys:danger']);
        let [warning] = redisMemoryWarnings({ evicted_keys: 1 });
        assert.match(warning.details[0], /evicted 1 key after/);
    });

    await t.test('flags an eviction policy, red only when a limit makes it bite', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'allkeys-lru', maxmemory: 0 }), ['maxmemory-policy:warning']);
        assert.deepStrictEqual(keys({ maxmemory_policy: 'allkeys-lru', maxmemory: 1000 * MB, used_memory: 10 * MB }), ['maxmemory-policy:danger']);
    });

    await t.test('reports the eviction and the limit together', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'volatile-lru', maxmemory: 1000 * MB, used_memory: 990 * MB }), [
            'maxmemory-policy:danger',
            'memory-limit:danger'
        ]);
    });

    await t.test('parses INFO values that arrive as strings and tolerates missing input', () => {
        assert.deepStrictEqual(keys({ maxmemory_policy: 'noeviction', maxmemory: '1000', used_memory: '900' }), ['memory-limit:warning']);
        assert.deepStrictEqual(redisMemoryWarnings(), []);
        assert.deepStrictEqual(redisMemoryWarnings({}), []);
    });
});
