'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Own key prefix, set before any module reads it, so parallel suites never see these routes
process.env.EENGINE_REDIS_PREFIX = 'test_webhook_routes_store';

const { webhooks, ENCRYPTED_ROUTE_FIELDS } = require('../lib/webhooks');
const { redis, notifyQueue } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const msgpack = require('../lib/msgpack');
const settings = require('../lib/settings');
const getSecret = require('../lib/get-secret');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
});

// Every job pushToQueue() would queue, without reaching BullMQ. The main webhook job carries no
// _route, so the route deliveries can be told apart from it
const queued = [];
notifyQueue.add = async (name, data, opts) => {
    queued.push({ name, data, opts });
    return { id: String(queued.length) };
};
const routeJobs = () => queued.filter(job => job.data._route);

const mainJobs = () => queued.filter(job => !job.data._route);

// pushToQueue() queues nothing while delivery is off, so the route tests run with it on and every
// event allowed; the gate itself is tested at the end
async function resetRoutes() {
    const keys = await redis.keys(`${REDIS_PREFIX}wh:*`);
    if (keys.length) {
        await redis.del(keys);
    }
    webhooks.handlerCache = [];
    webhooks.handlerCacheV = -1;
    queued.length = 0;
    await settings.set('webhooksEnabled', true);
    await settings.set('webhookEvents', ['*']);
    await settings.set('inboxNewOnly', false);
    await settings.clear('webhooksDeliveryAttempts');
    await settings.clear('webhooksRetryDelay');
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
        assert.ok(meta.targetUrl.startsWith('$wd02$'));
        assert.ok(typeof meta.customHeaders === 'string' && meta.customHeaders.startsWith('$wd02$'));
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
        assert.ok(meta.targetUrl.startsWith('$wd02$'));
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

    await webhooks.pushToQueue('messageNew', { account: 'acc', event: 'messageNew', data: {} });
    assert.strictEqual(routeJobs().length, 1, 'one event, one job for the route');
});

test('a route with a map script sends the mapped payload or nothing', async t => {
    const payload = { account: 'acc', event: 'messageNew', data: { subject: 'secret subject', id: 'm1' } };

    async function routeWithMap(map) {
        await resetRoutes();
        await webhooks.create({ name: 'Mapped', enabled: true, targetUrl: 'https://example.com/mapped' }, { fn: 'return true;', map });
        await webhooks.pushToQueue('messageNew', payload);
    }

    await t.test('a map that throws skips the route', async () => {
        await routeWithMap('throw new Error("map failed");');
        assert.strictEqual(routeJobs().length, 0, 'the unmapped payload must not be queued');
    });

    await t.test('a map that returns nothing skips the route', async () => {
        await routeWithMap('return null;');
        assert.strictEqual(routeJobs().length, 0);
    });

    await t.test('a working map queues the mapped payload', async () => {
        await routeWithMap('return { id: payload.data.id };');
        assert.strictEqual(routeJobs().length, 1);
        // the object comes from the script's own realm, so compare what gets serialized
        assert.deepStrictEqual(JSON.parse(JSON.stringify(routeJobs()[0].data._route.mapping)), { id: 'm1' });
    });

    await t.test('a route without a map queues the payload as before', async () => {
        await resetRoutes();
        await webhooks.create({ name: 'Plain', enabled: true, targetUrl: 'https://example.com/plain' }, { fn: 'return true;' });
        await webhooks.pushToQueue('messageNew', payload);
        assert.strictEqual(routeJobs().length, 1);
        assert.ok(!('mapping' in routeJobs()[0].data._route));
    });
});

test('pushToQueue() queues only what a delivery would send', async t => {
    const inboxMessage = { account: 'acc', path: 'INBOX', event: 'messageNew', data: { id: 'm1' } };
    const sentMessage = { account: 'acc', path: 'Sent', specialUse: '\\Sent', event: 'messageNew', data: { id: 'm2' } };

    await t.test('nothing at all while webhooks are disabled, routes included', async () => {
        await resetRoutes();
        // a route that queues every event it is asked about
        await webhooks.create({ name: 'Never runs', enabled: true, targetUrl: 'https://example.com/never' }, { fn: 'return true;' });
        await settings.set('webhooksEnabled', false);
        await webhooks.pushToQueue('messageNew', inboxMessage);
        assert.deepStrictEqual(queued, []);
    });

    await t.test('the main job follows the webhookEvents allowlist', async () => {
        await resetRoutes();
        await settings.set('webhookEvents', ['messageDeleted']);
        await webhooks.pushToQueue('messageNew', inboxMessage);
        await webhooks.pushToQueue('messageDeleted', { account: 'acc', event: 'messageDeleted', data: {} });
        assert.deepStrictEqual(
            mainJobs().map(job => job.name),
            ['messageDeleted']
        );

        await settings.set('webhookEvents', []);
        await webhooks.pushToQueue('messageDeleted', { account: 'acc', event: 'messageDeleted', data: {} });
        assert.strictEqual(mainJobs().length, 1, 'an empty allowlist delivers nothing');
    });

    await t.test('the main job follows inboxNewOnly', async () => {
        await resetRoutes();
        await settings.set('inboxNewOnly', true);
        await webhooks.pushToQueue('messageNew', sentMessage);
        await webhooks.pushToQueue('messageNew', inboxMessage);
        assert.deepStrictEqual(
            mainJobs().map(job => job.data.data.id),
            ['m1']
        );
    });

    await t.test('routes are not bound by the default route filters', async () => {
        await resetRoutes();
        await webhooks.create({ name: 'All', enabled: true, targetUrl: 'https://example.com/all' }, { fn: 'return true;' });
        await settings.set('webhookEvents', []);
        await settings.set('inboxNewOnly', true);
        await webhooks.pushToQueue('messageNew', sentMessage);
        assert.strictEqual(mainJobs().length, 0);
        assert.strictEqual(routeJobs().length, 1);
    });
});

test('enqueue() formats only what it will queue', async t => {
    const realFormatPayload = webhooks.formatPayload;
    let formatted = 0;
    webhooks.formatPayload = async (event, payload) => {
        formatted++;
        return realFormatPayload.call(webhooks, event, payload);
    };
    t.after(() => {
        webhooks.formatPayload = realFormatPayload;
    });

    const inboxMessage = { account: 'acc', path: 'INBOX', event: 'messageNew', data: { id: 'm1' } };

    await t.test('webhooks disabled: nothing is formatted or queued', async () => {
        await resetRoutes();
        formatted = 0;
        await settings.set('webhooksEnabled', false);
        await webhooks.enqueue('messageNew', inboxMessage);
        assert.strictEqual(formatted, 0);
        assert.deepStrictEqual(queued, []);
    });

    await t.test('webhooks enabled: the formatted payload is queued', async () => {
        await resetRoutes();
        formatted = 0;
        await webhooks.enqueue('messageNew', inboxMessage);
        assert.strictEqual(formatted, 1);
        assert.strictEqual(mainJobs().length, 1);
        assert.ok(mainJobs()[0].data.eventId, 'formatPayload() assigns the event id');
    });
});

test('the retry policy settings reach every queued delivery', async t => {
    const payload = { account: 'acc', event: 'messageNew', data: {} };

    await t.test('without the settings, 10 attempts starting at 5 seconds', async () => {
        await resetRoutes();
        await webhooks.create({ name: 'Policy route', enabled: true, targetUrl: 'https://example.com/policy' }, { fn: 'return true;' });
        await webhooks.pushToQueue('messageNew', payload);
        assert.strictEqual(queued.length, 2, 'the route delivery and the default one');
        for (const job of queued) {
            assert.strictEqual(job.opts.attempts, 10);
            assert.strictEqual(job.opts.backoff.delay, 5000);
        }
    });

    await t.test('the settings apply to the default and the route deliveries alike', async () => {
        await resetRoutes();
        await webhooks.create({ name: 'Policy route', enabled: true, targetUrl: 'https://example.com/policy' }, { fn: 'return true;' });
        await settings.set('webhooksDeliveryAttempts', 3);
        await settings.set('webhooksRetryDelay', 30000);
        await webhooks.pushToQueue('messageNew', payload);
        assert.strictEqual(queued.length, 2);
        for (const job of queued) {
            assert.strictEqual(job.opts.attempts, 3);
            assert.strictEqual(job.opts.backoff.delay, 30000);
            assert.strictEqual(job.opts.backoff.type, 'exponential');
        }
    });
});
