'use strict';

// Unit tests for lib/redis-backend-warnings.js, the dashboard's Redis Cluster and ElastiCache banners.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redisBackendWarnings } = require('../lib/redis-backend-warnings');

const keys = info => redisBackendWarnings(info).map(w => `${w.key}:${w.color}`);

// INFO values as an AWS-managed server reports them (seen on Valkey 8.2 and 7.3, 2026-11-25)
const ELASTICACHE = { os: 'Amazon ElastiCache', redis_mode: 'standalone', cluster_enabled: 0 };
const MEMORYDB = { os: 'Amazon MemoryDB', redis_mode: 'cluster', cluster_enabled: 1, role: 'master', connected_slaves: 0 };

test('redisBackendWarnings', async t => {
    await t.test('reports nothing for a standalone self-hosted Redis, with or without replicas', () => {
        assert.deepStrictEqual(keys({ os: 'Linux 6.1.0 x86_64', cluster_enabled: 0, role: 'master', connected_slaves: 0 }), []);
        assert.deepStrictEqual(keys({ os: 'Linux 6.1.0 x86_64', cluster_enabled: 0, role: 'master', connected_slaves: 2 }), []);
    });

    await t.test('reports nothing for missing INFO', () => {
        assert.deepStrictEqual(keys(null), []);
        assert.deepStrictEqual(keys({}), []);
    });

    await t.test('refuses Redis Cluster', () => {
        assert.deepStrictEqual(keys({ os: 'Linux', cluster_enabled: 1, role: 'master', connected_slaves: 1 }), ['cluster:danger']);
    });

    await t.test('refuses MemoryDB through the cluster warning, since it always runs as a cluster', () => {
        assert.deepStrictEqual(keys(MEMORYDB), ['cluster:danger']);
    });

    await t.test('warns about an ElastiCache primary with no replica', () => {
        assert.deepStrictEqual(keys({ ...ELASTICACHE, role: 'master', connected_slaves: 0 }), ['elasticache:danger']);
    });

    await t.test('accepts an ElastiCache primary with a connected replica', () => {
        assert.deepStrictEqual(keys({ ...ELASTICACHE, role: 'master', connected_slaves: 1 }), []);
    });

    await t.test('does not judge a replica it happens to be connected to', () => {
        assert.deepStrictEqual(keys({ ...ELASTICACHE, role: 'slave', connected_slaves: 0 }), []);
    });

    await t.test('reports only the cluster warning for ElastiCache in cluster mode', () => {
        assert.deepStrictEqual(keys({ ...ELASTICACHE, cluster_enabled: 1, role: 'master', connected_slaves: 0 }), ['cluster:danger']);
    });
});
