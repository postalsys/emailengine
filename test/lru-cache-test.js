'use strict';

// lib/tools.js LRUCache backs the regex, mailbox path and compiled SubScript caches. It used to be
// first-in-first-out: a hit did not refresh an entry, so the entry used most often was evicted as
// readily as one never read again, and re-setting a present key evicted an unrelated entry.

const test = require('node:test');
const assert = require('node:assert').strict;

const { LRUCache } = require('../lib/tools');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('LRUCache', async t => {
    await t.test('evicts the least recently used entry, not the oldest', () => {
        const cache = new LRUCache(2);
        cache.set('a', 1);
        cache.set('b', 2);
        assert.equal(cache.get('a'), 1);
        cache.set('c', 3);
        assert.equal(cache.has('a'), true, 'the entry read last survives');
        assert.equal(cache.has('b'), false, 'the entry nobody read is evicted');
    });

    await t.test('updating a present key does not evict another entry', () => {
        const cache = new LRUCache(2);
        cache.set('a', 1);
        cache.set('b', 2);
        cache.set('a', 10);
        assert.equal(cache.size, 2);
        assert.equal(cache.get('a'), 10);
        assert.equal(cache.get('b'), 2);
    });

    await t.test('a miss returns undefined without changing the cache', () => {
        const cache = new LRUCache(2);
        cache.set('a', 1);
        assert.equal(cache.get('missing'), undefined);
        assert.equal(cache.size, 1);
    });
});
