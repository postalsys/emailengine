'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Own key prefix, set before any module reads it, so parallel suites never see these routes
process.env.EENGINE_REDIS_PREFIX = 'test_webhook_routes_store';

const { webhooks, ENCRYPTED_ROUTE_FIELDS } = require('../lib/webhooks');
const { redis, notifyQueue } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const msgpack = require('../lib/msgpack');
const getSecret = require('../lib/get-secret');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
});

// Every job pushToQueue() would queue, without reaching BullMQ
const queued = [];
notifyQueue.add = async (name, data) => {
    queued.push({ name, data });
    return { id: String(queued.length) };
};

async function resetRoutes() {
    const keys = await redis.keys(`${REDIS_PREFIX}wh:*`);
    if (keys.length) {
        await redis.del(keys);
    }
    webhooks.handlerCache = [];
    webhooks.handlerCacheV = -1;
    queued.length = 0;
}

async function storedMeta(id) {
    return msgpack.decode(await redis.hgetBuffer(webhooks.getWebhooksContentKey(), `${id}:meta`));
}

test('webhook route credentials are encrypted at rest', async t => {
    assert.ok(await getSecret(), 'config/test.toml is expected to set a service secret');
    assert.deepStrictEqual(ENCRYPTED_ROUTE_FIELDS, ['targetUrl', 'customHeaders']);

    await resetRoutes();

    const targetUrl = 'https://hook:s3cret@example.com/route';
    const customHeaders = [{ key: 'Authorization', value: 'Bearer route-token' }];
    const { id } = await webhooks.create({ name: 'Encrypted route', enabled: true, targetUrl, customHeaders }, { fn: 'return true;' });

    await t.test('stored as ciphertext', async () => {
        const meta = await storedMeta(id);
        assert.ok(meta.targetUrl.startsWith('$wd01$'));
        assert.ok(typeof meta.customHeaders === 'string' && meta.customHeaders.startsWith('$wd01$'));
        assert.strictEqual(meta.name, 'Encrypted route', 'the rest of the entry stays readable');
    });

    await t.test('every reader gets the cleartext', async () => {
        const full = await webhooks.get(id);
        assert.strictEqual(full.targetUrl, targetUrl);
        assert.deepStrictEqual(full.customHeaders, customHeaders);

        const meta = await webhooks.getMeta(id);
        assert.strictEqual(meta.targetUrl, targetUrl);
        assert.deepStrictEqual(meta.customHeaders, customHeaders);

        const list = await webhooks.list(0, 20);
        assert.strictEqual(list.webhooks[0].targetUrl, targetUrl);
        assert.deepStrictEqual(list.webhooks[0].customHeaders, customHeaders);

        // the listing search runs on the decrypted URL
        const found = await webhooks.list(0, 20, 'example.com/route');
        assert.strictEqual(found.total, 1);
    });

    await t.test('an update that leaves the credentials out keeps them encrypted and intact', async () => {
        await webhooks.update(id, { name: 'Renamed route' });
        const meta = await storedMeta(id);
        assert.ok(meta.targetUrl.startsWith('$wd01$'));
        const full = await webhooks.get(id);
        assert.strictEqual(full.name, 'Renamed route');
        assert.strictEqual(full.targetUrl, targetUrl);
        assert.deepStrictEqual(full.customHeaders, customHeaders);
    });

    await t.test('a route stored in the clear before encryption still reads', async () => {
        const legacyId = 'legacy-route';
        await redis.sadd(webhooks.getWebhooksIndexKey(), legacyId);
        await redis.hset(
            webhooks.getWebhooksContentKey(),
            `${legacyId}:meta`,
            msgpack.encode({
                id: legacyId,
                name: 'Legacy',
                enabled: true,
                targetUrl: 'https://legacy.example.com/',
                customHeaders: [{ key: 'X-Key', value: 'v' }]
            })
        );
        await redis.hset(webhooks.getWebhooksContentKey(), `${legacyId}:content`, msgpack.encode({ fn: 'return true;' }));

        const meta = await webhooks.getMeta(legacyId);
        assert.strictEqual(meta.targetUrl, 'https://legacy.example.com/');
        assert.deepStrictEqual(meta.customHeaders, [{ key: 'X-Key', value: 'v' }]);

        await webhooks.del(legacyId);
    });

    await t.test('a value that does not decrypt leaves the route undeliverable rather than failing', async () => {
        const { encrypt } = require('../lib/encrypt');
        const badId = 'bad-secret-route';
        await redis.hset(
            webhooks.getWebhooksContentKey(),
            `${badId}:meta`,
            msgpack.encode({ id: badId, name: 'Bad', enabled: true, targetUrl: encrypt('https://x.example.com/', 'another-secret') })
        );
        const meta = await webhooks.getMeta(badId);
        assert.strictEqual(meta.name, 'Bad');
        assert.ok(!('targetUrl' in meta));
        await redis.hdel(webhooks.getWebhooksContentKey(), `${badId}:meta`);
    });
});

test('deleting a route removes every field it owns', async () => {
    await resetRoutes();
    const { id } = await webhooks.create({ name: 'Doomed', enabled: true, targetUrl: 'https://example.com/doomed' }, { fn: 'return true;' });
    await webhooks.update(id, { name: 'Doomed, updated' });
    await redis.hincrby(webhooks.getWebhooksContentKey(), `${id}:tcount`, 3);
    await redis.hset(webhooks.getWebhooksContentKey(), `${id}:webhookErrorFlag`, JSON.stringify({ message: 'failed' }));

    const result = await webhooks.del(id);
    assert.deepStrictEqual(result, { deleted: true, id });

    const leftover = (await redis.hkeys(webhooks.getWebhooksContentKey())).filter(field => field.startsWith(`${id}:`));
    assert.deepStrictEqual(leftover, []);
});

test('concurrent cache refreshes load a new route once', async () => {
    await resetRoutes();
    await webhooks.create({ name: 'Once', enabled: true, targetUrl: 'https://example.com/once' }, { fn: 'return true;' });

    const [first, second] = await Promise.all([webhooks.getWebhookHandlers(), webhooks.getWebhookHandlers()]);
    assert.strictEqual(first.length, 1);
    assert.strictEqual(second.length, 1);
    assert.strictEqual(webhooks.handlerCache.length, 1);

    await webhooks.pushToQueue('messageNew', { account: 'acc', event: 'messageNew', data: {} }, { routesOnly: true });
    assert.strictEqual(queued.length, 1, 'one event, one job for the route');
});

test('a route with a map script sends the mapped payload or nothing', async t => {
    const payload = { account: 'acc', event: 'messageNew', data: { subject: 'secret subject', id: 'm1' } };

    async function routeWithMap(map) {
        await resetRoutes();
        await webhooks.create({ name: 'Mapped', enabled: true, targetUrl: 'https://example.com/mapped' }, { fn: 'return true;', map });
        await webhooks.pushToQueue('messageNew', payload, { routesOnly: true });
    }

    await t.test('a map that throws skips the route', async () => {
        await routeWithMap('throw new Error("map failed");');
        assert.strictEqual(queued.length, 0, 'the unmapped payload must not be queued');
    });

    await t.test('a map that returns nothing skips the route', async () => {
        await routeWithMap('return null;');
        assert.strictEqual(queued.length, 0);
    });

    await t.test('a working map queues the mapped payload', async () => {
        await routeWithMap('return { id: payload.data.id };');
        assert.strictEqual(queued.length, 1);
        // the object comes from the script's own realm, so compare what gets serialized
        assert.deepStrictEqual(JSON.parse(JSON.stringify(queued[0].data._route.mapping)), { id: 'm1' });
    });

    await t.test('a route without a map queues the payload as before', async () => {
        await resetRoutes();
        await webhooks.create({ name: 'Plain', enabled: true, targetUrl: 'https://example.com/plain' }, { fn: 'return true;' });
        await webhooks.pushToQueue('messageNew', payload, { routesOnly: true });
        assert.strictEqual(queued.length, 1);
        assert.ok(!('mapping' in queued[0].data._route));
    });
});
