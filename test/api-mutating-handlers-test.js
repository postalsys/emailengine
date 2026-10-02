'use strict';

// Behavioural tests for mutating REST handlers that were covered by the route-table guardrail
// only (audit API-9). Each drives the real handler captured from its lib/api-routes module:
//   - PUT /v1/gateway/edit/{gateway} against a real gateway record in the test database
//   - PUT /v1/settings/queue/{queue} against a stand-in queue
//   - PUT /v1/account/{account}/messages/move and .../messages/delete with a recording `call`
//   - PUT /v1/oauth2/{app} refusing the masked secret placeholder (API-6)
// Payloads go through each route's own joi schema first, as hapi would do.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis, QUEUES_BY_NAME } = require('../lib/db');
const { Gateway } = require('../lib/gateway');
const { Account } = require('../lib/account');
const { oauth2Apps } = require('../lib/oauth2-apps');
const getSecret = require('../lib/get-secret');
const gatewayRoutes = require('../lib/api-routes/gateway-routes');
const settingsRoutes = require('../lib/api-routes/settings-routes');
const messageRoutes = require('../lib/api-routes/message-routes');
const oauth2AppRoutes = require('../lib/api-routes/oauth2-app-routes');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const logger = { warn() {}, error() {}, debug() {}, info() {} };

async function capture(init, overrides) {
    const routes = [];
    await init(buildMockArgs({ route: cfg => routes.push(cfg) }, overrides));
    return (method, path) => {
        const route = routes.find(r => r.method === method && r.path === path);
        assert.ok(route, `${method} ${path} is registered`);
        return route;
    };
}

// What hapi hands the handler after validation
function validated(route, part, value) {
    const schema = route.options.validate[part];
    const { value: result, error } = schema.validate(value, route.options.validate.options);
    assert.ifError(error);
    return result;
}

test('PUT /v1/gateway/edit/{gateway}', async t => {
    const find = await capture(gatewayRoutes);
    const route = find('PUT', '/v1/gateway/edit/{gateway}');
    const id = `test-gw-${crypto.randomBytes(4).toString('hex')}`;

    const gateway = new Gateway({ redis, gateway: id, secret: await getSecret() });
    await gateway.create({ gateway: id, name: 'Original', host: 'smtp.example.com', port: 465, secure: true, user: 'u', pass: 'stored-secret' });
    t.after(() => new Gateway({ redis, gateway: id }).delete().catch(() => {}));

    await t.test('updates the fields sent and keeps the stored password', async () => {
        const payload = validated(route, 'payload', { host: 'smtp2.example.com', port: '587', secure: 'false' });
        const result = await route.handler({ params: { gateway: id }, payload, logger });
        assert.deepEqual(result, { gateway: id });

        const stored = await new Gateway({ redis, gateway: id, secret: await getSecret() }).loadGatewayData();
        assert.equal(stored.host, 'smtp2.example.com');
        assert.equal(stored.port, 587);
        assert.equal(stored.secure, false);
        assert.equal(stored.name, 'Original');
        assert.equal(stored.pass, 'stored-secret', 'a field left out of the update is kept');
    });

    await t.test('an unknown gateway is a 404, not a new record', async () => {
        const missing = `${id}-missing`;
        await assert.rejects(route.handler({ params: { gateway: missing }, payload: { name: 'x' }, logger }), err => err.output.statusCode === 404);
        assert.equal(await redis.exists(new Gateway({ redis, gateway: missing }).getGatewayKey()), 0);
    });
});

test('POST /v1/gateway', async t => {
    const find = await capture(gatewayRoutes);
    const route = find('POST', '/v1/gateway');

    // Gateway.create() generates an id for a null gateway, the same way POST /v1/account does for
    // a null account. The schema used to declare the field as required without allowing null, so
    // the generation branch was unreachable over the API.
    await t.test('a null gateway id is generated and returned', async () => {
        const payload = validated(route, 'payload', { gateway: null, name: 'Generated', host: 'smtp.example.com', port: '465' });
        assert.equal(payload.gateway, null);

        const result = await route.handler({ payload, logger });
        t.after(() => new Gateway({ redis, gateway: result.gateway }).delete().catch(() => {}));

        assert.equal(result.state, 'new');
        assert.ok(result.gateway, 'the response carries the generated id');

        const stored = await new Gateway({ redis, gateway: result.gateway, secret: await getSecret() }).loadGatewayData();
        assert.equal(stored.gateway, result.gateway);
        assert.equal(stored.name, 'Generated');
    });

    await t.test('an omitted gateway id is still a validation error', () => {
        const { error } = route.options.validate.payload.validate({ name: 'Generated', host: 'smtp.example.com', port: 465 }, route.options.validate.options);
        assert.ok(error, 'the field has to be sent, as null if no id is chosen');
    });
});

test('PUT /v1/settings/queue/{queue}', async t => {
    const find = await capture(settingsRoutes);
    const route = find('PUT', '/v1/settings/queue/{queue}');

    const original = QUEUES_BY_NAME.notify;
    let paused = false;
    const calls = [];
    QUEUES_BY_NAME.notify = {
        async pause() {
            calls.push('pause');
            paused = true;
        },
        async resume() {
            calls.push('resume');
            paused = false;
        },
        async isPaused() {
            return paused;
        }
    };
    t.after(() => {
        QUEUES_BY_NAME.notify = original;
    });

    await t.test('pauses and resumes the named queue and reports the resulting state', async () => {
        let result = await route.handler({ params: { queue: 'notify' }, payload: validated(route, 'payload', { paused: 'true' }), logger });
        assert.deepEqual(result, { queue: 'notify', paused: true });

        result = await route.handler({ params: { queue: 'notify' }, payload: validated(route, 'payload', { paused: false }), logger });
        assert.deepEqual(result, { queue: 'notify', paused: false });
        assert.deepEqual(calls, ['pause', 'resume']);
    });

    await t.test('an empty payload changes nothing and still reports the state', async () => {
        calls.length = 0;
        const result = await route.handler({ params: { queue: 'notify' }, payload: {}, logger });
        assert.deepEqual(result, { queue: 'notify', paused: false });
        assert.deepEqual(calls, []);
    });

    await t.test('an unknown queue name is refused by the params schema', () => {
        assert.ok(route.options.validate.params.validate({ queue: 'nope' }).error);
    });
});

test('bulk message move and delete', async t => {
    const commands = [];
    let reply = { moved: 3 };
    const find = await capture(messageRoutes, {
        call: async message => {
            commands.push(message);
            return reply;
        }
    });

    const originalLoad = Account.prototype.loadAccountData;
    Account.prototype.loadAccountData = async function () {
        return { account: this.account };
    };
    t.after(() => {
        Account.prototype.loadAccountData = originalLoad;
    });

    const request = extra => Object.assign({ params: { account: 'acc' }, headers: {}, logger }, extra);

    await t.test('move sends the source folder, the search and the target to the worker', async () => {
        const route = find('PUT', '/v1/account/{account}/messages/move');
        commands.length = 0;
        reply = { path: 'Archive', idMap: [], emailIds: [] };
        const query = validated(route, 'query', { path: 'INBOX' });
        const payload = validated(route, 'payload', { search: { seen: true }, path: 'Archive' });

        const result = await route.handler(request({ query, payload }));

        assert.deepEqual(result, reply);
        assert.equal(commands.length, 1);
        assert.equal(commands[0].cmd, 'moveMessages');
        assert.equal(commands[0].account, 'acc');
        assert.equal(commands[0].source, 'INBOX');
        assert.deepEqual(commands[0].target, { path: 'Archive' });
        assert.equal(commands[0].search.seen, true);
    });

    await t.test('move from a folder the backend does not know is a 404', async () => {
        const route = find('PUT', '/v1/account/{account}/messages/move');
        reply = false;
        const query = validated(route, 'query', { path: 'Nope' });
        const payload = validated(route, 'payload', { search: { seen: true }, path: 'Archive' });
        await assert.rejects(route.handler(request({ query, payload })), err => err.output.statusCode === 404);
    });

    await t.test('delete passes force through, including ?force=0', async () => {
        const route = find('PUT', '/v1/account/{account}/messages/delete');
        commands.length = 0;
        reply = { deleted: true };

        for (const [flag, expected] of [
            ['1', true],
            ['0', false]
        ]) {
            const query = validated(route, 'query', { path: 'Trash', force: flag });
            const payload = validated(route, 'payload', { search: { seen: true } });
            await route.handler(request({ query, payload }));
            assert.equal(commands.at(-1).cmd, 'deleteMessages');
            assert.equal(commands.at(-1).path, 'Trash');
            assert.equal(commands.at(-1).force, expected);
        }
    });
});

test('PUT /v1/oauth2/{app} refuses the masked secret placeholder', async t => {
    const find = await capture(oauth2AppRoutes);
    const route = find('PUT', '/v1/oauth2/{app}');

    const originalUpdate = oauth2Apps.update;
    const updates = [];
    oauth2Apps.update = async (app, data) => {
        updates.push({ app, data });
        return { id: app, updated: true };
    };
    t.after(() => {
        oauth2Apps.update = originalUpdate;
    });

    await t.test('an echoed "******" secret is a 400 and nothing is written', async () => {
        const payload = validated(route, 'payload', { name: 'Renamed', clientSecret: '******' });
        await assert.rejects(route.handler({ params: { app: 'app1' }, payload, logger }), err => {
            assert.equal(err.output.statusCode, 400);
            assert.match(err.message, /clientSecret/);
            return true;
        });
        assert.equal(updates.length, 0);
    });

    await t.test('a real secret, or none at all, is written', async () => {
        await route.handler({ params: { app: 'app1' }, payload: validated(route, 'payload', { clientSecret: 'new-secret' }), logger });
        await route.handler({ params: { app: 'app1' }, payload: validated(route, 'payload', { name: 'Renamed' }), logger });
        assert.equal(updates.length, 2);
        assert.equal(updates[0].data.clientSecret, 'new-secret');
    });

    await t.test('the route notes tell the reader about the mask', () => {
        assert.match(route.options.notes, /\*\*\*\*\*\*/);
    });
});
