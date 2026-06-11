'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_webhooks_cache';

const { webhooks } = require('../lib/webhooks');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

// Regression tests for the webhook handler cache in getWebhookHandlers(). The cache version
// marker used to be assigned backwards (v = this.handlerCacheV instead of this.handlerCacheV = v)
// and the per-route version compared a Number against the String from redis, so the cache was
// rebuilt from Redis on every webhook event once any custom route existed.
test('Webhook handler cache', async t => {
    t.after(async () => {
        // Clean up any remaining test keys
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length > 0) {
            await redis.del(keys);
        }

        redis.quit();

        // Force exit after cleanup to prevent hanging on any remaining connections
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('cache version marker syncs after a refresh', async () => {
        await webhooks.create({ name: 'Cache test route', enabled: true, targetUrl: 'http://127.0.0.1:7078/cache-test' }, {});

        const storedV = Number(await redis.hget(webhooks.getWebhooksContentKey(), 'v'));
        assert.ok(storedV >= 1, 'creating a route must bump the version counter');

        const handlers = await webhooks.getWebhookHandlers();
        assert.strictEqual(handlers.length, 1, 'the created route must be loaded into the cache');
        assert.strictEqual(webhooks.handlerCacheV, storedV, 'the cache marker must match the stored version after a refresh');
    });

    await t.test('a second call without changes does not re-fetch from Redis', async () => {
        const originalSmembers = redis.smembers.bind(redis);
        let indexReads = 0;
        redis.smembers = (...args) => {
            indexReads++;
            return originalSmembers(...args);
        };

        try {
            const first = await webhooks.getWebhookHandlers();
            const second = await webhooks.getWebhookHandlers();
            assert.strictEqual(indexReads, 0, 'unchanged cache must not re-read the route index');
            assert.strictEqual(second[0], first[0], 'cached handler instances must be reused');
        } finally {
            delete redis.smembers;
        }
    });

    await t.test('updating a route invalidates only that cached handler', async () => {
        const cached = (await webhooks.getWebhookHandlers())[0];

        await webhooks.update(cached.id, { name: 'Updated cache test route' });

        const refreshed = (await webhooks.getWebhookHandlers())[0];
        assert.notStrictEqual(refreshed, cached, 'the updated route must be rebuilt');
        assert.strictEqual(refreshed.name, 'Updated cache test route');

        const storedV = Number(await redis.hget(webhooks.getWebhooksContentKey(), 'v'));
        assert.strictEqual(webhooks.handlerCacheV, storedV, 'the cache marker must track the bumped version');
    });
});
