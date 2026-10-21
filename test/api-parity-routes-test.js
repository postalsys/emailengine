'use strict';

// The REST counterparts of admin UI actions, driven through the real route modules on a bare Hapi
// server with a stand-in api-token strategy: verifying a stored SMTP gateway, sending a test
// webhook to a configured target, deleting a whole suppression list, clearing an account's stored
// logs, and the free-text `query` filter of the list endpoints.

const test = require('node:test');

// Own key prefix, set before any module reads it: the test files of the tier run in parallel on one
// database, and a job these put into a queue would otherwise be picked up by another file's worker
process.env.EENGINE_REDIS_PREFIX = 'test_api_parity_routes';

const assert = require('node:assert').strict;
const crypto = require('node:crypto');

const { SMTPServer } = require('smtp-server');

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const settings = require('../lib/settings');
const getSecret = require('../lib/get-secret');
const { getServiceSecret } = require('../lib/tools');
const { Gateway } = require('../lib/gateway');
const { lists } = require('../lib/lists');
const { webhooks: Webhooks } = require('../lib/webhooks');
const { templates } = require('../lib/templates');
const gatewayRoutes = require('../lib/api-routes/gateway-routes');
const webhookRouteRoutes = require('../lib/api-routes/webhook-route-routes');
const blocklistRoutes = require('../lib/api-routes/blocklist-routes');
const templateRoutes = require('../lib/api-routes/template-routes');
const accountRoutes = require('../lib/api-routes/account-routes');
const { startCapturingServer } = require('./helpers/capture-http-server');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createRouteTestServer } = require('./helpers/route-test-server');

const ACCOUNT = 'api-parity-account';
const created = { gateways: [], webhooks: [], templates: [] };

registerRedisTeardown(redis, async () => {
    for (const gateway of created.gateways) {
        await new Gateway({ redis, gateway, secret: await getSecret() }).delete().catch(() => false);
    }
    for (const id of created.webhooks) {
        await Webhooks.del(id).catch(() => false);
    }
    await redis.del(`${REDIS_PREFIX}iad:${ACCOUNT}`, `${REDIS_PREFIX}iam:${ACCOUNT}:g`);
    await settings.clear('webhooks');
    await settings.clear('webhooksCustomHeaders');
});

test('admin parity routes', async t => {
    let server;

    t.before(async () => {
        server = await createRouteTestServer(async routeServer => {
            const args = buildMockArgs(routeServer);
            await gatewayRoutes(args);
            await webhookRouteRoutes(args);
            await blocklistRoutes(args);
            await templateRoutes(args);
            await accountRoutes(args);
        });
    });

    await t.test('POST /v1/gateway/{gateway}/verify checks the stored settings and credentials', async t => {
        const smtp = new SMTPServer({
            allowInsecureAuth: true,
            disabledCommands: ['STARTTLS'],
            logger: false,
            onAuth(auth, session, callback) {
                if (auth.username === 'relay-user' && auth.password === 'relay-pass') {
                    return callback(null, { user: auth.username });
                }
                return callback(new Error('Invalid username or password'));
            }
        });
        await new Promise(resolve => smtp.listen(0, '127.0.0.1', resolve));
        t.after(() => new Promise(resolve => smtp.close(resolve)));
        const port = smtp.server.address().port;

        const secret = await getSecret();
        for (const [gateway, pass] of [
            ['api-parity-good', 'relay-pass'],
            ['api-parity-bad', 'wrong-pass']
        ]) {
            await new Gateway({ redis, secret }).create({
                gateway,
                name: gateway,
                host: '127.0.0.1',
                port,
                secure: false,
                requireTLS: false,
                user: 'relay-user',
                pass
            });
            created.gateways.push(gateway);
        }

        const good = await server.inject({ method: 'POST', url: '/v1/gateway/api-parity-good/verify' });
        assert.equal(good.statusCode, 200);
        assert.equal(good.result.success, true);

        const bad = await server.inject({ method: 'POST', url: '/v1/gateway/api-parity-bad/verify' });
        assert.equal(bad.statusCode, 200);
        assert.equal(bad.result.success, false);
        assert.equal(bad.result.code, 'EAUTH');

        const missing = await server.inject({ method: 'POST', url: '/v1/gateway/no-such-gateway/verify' });
        assert.equal(missing.statusCode, 404);
    });

    await t.test('POST /v1/webhooks/test posts a signed test event to a configured target only', async t => {
        const receiver = await startCapturingServer(res => {
            res.writeHead(200);
            res.end('ok');
        });
        t.after(() => new Promise(resolve => receiver.server.close(resolve)));

        const unset = await server.inject({ method: 'POST', url: '/v1/webhooks/test' });
        assert.equal(unset.result.success, false);
        assert.equal(unset.result.code, 'NoWebhookTarget');

        await settings.set('webhooks', `${receiver.baseUrl}/global`);
        await settings.set('webhooksCustomHeaders', [{ key: 'X-Global', value: 'global-value' }]);

        const global = await server.inject({ method: 'POST', url: '/v1/webhooks/test' });
        assert.equal(global.statusCode, 200);
        assert.equal(global.result.success, true);
        assert.equal(global.result.target, 'global');
        assert.ok(!JSON.stringify(global.result).includes(receiver.baseUrl), 'the target URL is not echoed back');

        const captured = receiver.getCaptured();
        assert.equal(captured.path, '/global');
        assert.equal(captured.headers['x-global'], 'global-value');
        assert.equal(JSON.parse(captured.body.toString()).event, 'test');
        const expected = crypto
            .createHmac('sha256', await getServiceSecret())
            .update(captured.body)
            .digest('base64url');
        assert.equal(captured.headers['x-ee-wh-signature'], expected, 'signed like a real delivery');

        const route = await Webhooks.create(
            { name: 'parity route', enabled: true, targetUrl: `${receiver.baseUrl}/route`, customHeaders: [{ key: 'X-Route', value: 'route-value' }] },
            { fn: 'return true;', map: '' }
        );
        created.webhooks.push(route.id);

        const routed = await server.inject({ method: 'POST', url: '/v1/webhooks/test', payload: { webhookRoute: route.id } });
        assert.equal(routed.result.success, true);
        assert.equal(routed.result.target, 'route');
        const routeCapture = receiver.getCaptured();
        assert.equal(routeCapture.path, '/route');
        assert.equal(routeCapture.headers['x-route'], 'route-value');
        assert.ok(!('x-global' in routeCapture.headers), 'the global headers go to the global target only');

        const unknown = await server.inject({ method: 'POST', url: '/v1/webhooks/test', payload: { webhookRoute: 'no-such-route' } });
        assert.equal(unknown.statusCode, 404);

        const failing = await startCapturingServer(res => {
            res.writeHead(503);
            res.end();
        });
        t.after(() => new Promise(resolve => failing.server.close(resolve)));
        await settings.set('webhooks', `${failing.baseUrl}/down`);
        const down = await server.inject({ method: 'POST', url: '/v1/webhooks/test' });
        assert.equal(down.statusCode, 200, 'a failed delivery is a result, not an error status');
        assert.equal(down.result.success, false);
        assert.equal(down.result.statusCode, 503);
    });

    await t.test('DELETE /v1/blocklists/{listId} removes the whole list', async () => {
        await lists.add('api-parity-list', 'one@example.com', { source: 'api' });
        await lists.add('api-parity-list', 'two@example.com', { source: 'api' });

        const res = await server.inject({ method: 'DELETE', url: '/v1/blocklists/api-parity-list' });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result, { deleted: true });
        assert.equal(await lists.exists('api-parity-list'), false);

        const again = await server.inject({ method: 'DELETE', url: '/v1/blocklists/api-parity-list' });
        assert.equal(again.statusCode, 404);
    });

    await t.test('DELETE /v1/logs/{account} clears the stored log of an existing account', async () => {
        await redis.hset(`${REDIS_PREFIX}iad:${ACCOUNT}`, 'account', ACCOUNT);
        await redis.rpush(`${REDIS_PREFIX}iam:${ACCOUNT}:g`, 'entry 1', 'entry 2');

        const res = await server.inject({ method: 'DELETE', url: `/v1/logs/${ACCOUNT}` });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result, { deleted: true });
        assert.equal(await redis.exists(`${REDIS_PREFIX}iam:${ACCOUNT}:g`), 0);

        const empty = await server.inject({ method: 'DELETE', url: `/v1/logs/${ACCOUNT}` });
        assert.deepEqual(empty.result, { deleted: false }, 'nothing left to remove');

        const missing = await server.inject({ method: 'DELETE', url: '/v1/logs/no-such-account' });
        assert.equal(missing.statusCode, 404);
    });

    await t.test('the list endpoints take a query filter', async () => {
        const first = await templates.create(null, { name: 'Parity welcome', description: 'first' }, { subject: 'Hello' });
        const second = await templates.create(null, { name: 'Parity invoice', description: 'second' }, { subject: 'Invoice' });
        created.templates.push(first.id, second.id);

        const res = await server.inject({ method: 'GET', url: '/v1/templates?query=WELCOME' });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(
            res.result.templates.map(entry => entry.id),
            [first.id]
        );

        const routes = await server.inject({ method: 'GET', url: '/v1/webhookRoutes?query=parity%20route' });
        assert.ok(routes.result.webhooks.every(entry => /parity route/i.test(entry.name)));
        assert.equal(routes.result.webhooks.length, 1);

        const gateways = await server.inject({ method: 'GET', url: '/v1/gateways?query=api-parity-good' });
        assert.deepEqual(
            gateways.result.gateways.map(entry => entry.gateway),
            ['api-parity-good']
        );

        const none = await server.inject({ method: 'GET', url: '/v1/gateways?query=nothing-matches' });
        assert.equal(none.result.total, 0);

        for (const id of created.templates) {
            await templates.del(id).catch(() => false);
        }
    });
});
