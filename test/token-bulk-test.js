'use strict';

// POST /admin/tokens/{token}/bulk, the one-token step of the access tokens list's bulk delete
// (lib/ui-routes/token-bulk.js), driven through the captured route handler against real tokens.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const tokens = require('../lib/tokens');
const { registerPostTokensBulk } = require('../lib/ui-routes/token-bulk');
const registerRedisTeardown = require('./helpers/redis-teardown');
const exitWhenStandalone = require('./helpers/exit-standalone');

registerRedisTeardown(redis);
exitWhenStandalone();

const logger = { warn() {}, error() {}, debug() {}, info() {}, trace() {} };

test('bulk token delete', async () => {
    const routes = [];
    registerPostTokensBulk({ route: cfg => routes.push(cfg) });
    const [route] = routes;
    const run = token => route.handler({ params: { token }, payload: { action: 'delete' }, logger, app: { ip: '127.0.0.1' } });

    const raw = await tokens.provision({ description: 'bulk delete test', scopes: ['api'], nolog: true });
    const id = (await tokens.get(raw)).id;

    assert.deepEqual(await run(id), { result: 'done' });
    assert.equal(await tokens.get(raw).catch(() => null), null);
    assert.deepEqual(await run(id), { result: 'missing' });

    // only delete, only a token id
    assert.ok(route.options.validate.payload.validate({ action: 'rotate' }).error);
    assert.ok(route.options.validate.params.validate({ token: 'not-an-id' }).error);
});
