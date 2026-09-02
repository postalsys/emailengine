'use strict';

// Drives the real POST /v1/settings handler from lib/api-routes/settings-routes.js against a
// recording mock server, the way test/helpers/capture-api-routes.js registers routes. Nothing is
// written to Redis: settings.set is stubbed, which is also how the mid-request failure is staged.

const test = require('node:test');
const assert = require('node:assert').strict;

const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const settingsRoutes = require('../lib/api-routes/settings-routes');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

const logger = { warn() {}, error() {}, debug() {} };

async function captureSettingsPost(notify) {
    const routes = [];
    await settingsRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }, { notify }));
    return routes.find(route => route.method === 'POST' && route.path === '/v1/settings');
}

test('POST /v1/settings', async t => {
    // lib/settings pulls in lib/db, whose handles would keep the process alive
    registerRedisTeardown(redis);

    const originalSet = settings.set;
    const written = [];

    t.beforeEach(() => {
        written.length = 0;
        settings.set = async (key, value) => {
            if (key === 'pageBrandName') {
                throw new Error('Redis is unavailable');
            }
            written.push(key);
            return 1;
        };
    });

    t.afterEach(() => {
        settings.set = originalSet;
    });

    await t.test('broadcasts every written key once and reports them', async () => {
        const broadcasts = [];
        const route = await captureSettingsPost(async (cmd, data) => broadcasts.push({ cmd, data }));

        const response = await route.handler({ payload: { serviceUrl: 'https://ee.example.com', notifyText: true }, logger });

        assert.deepEqual(response, { updated: ['serviceUrl', 'notifyText'] });
        assert.deepEqual(broadcasts, [{ cmd: 'settings', data: { serviceUrl: 'https://ee.example.com', notifyText: true } }]);
    });

    await t.test('still broadcasts the keys written before a later key failed', async () => {
        // Keys are written one at a time, so the ones before the failure are already in Redis and
        // the other workers have to reload for them even though the request itself fails
        const broadcasts = [];
        const route = await captureSettingsPost(async (cmd, data) => broadcasts.push({ cmd, data }));

        await assert.rejects(route.handler({ payload: { serviceUrl: 'https://ee.example.com', pageBrandName: 'Mail', notifyText: true }, logger }), err => {
            assert.ok(err.isBoom);
            assert.equal(err.output.statusCode, 500);
            return true;
        });

        assert.deepEqual(written, ['serviceUrl'], 'the loop stops at the failing key');
        assert.deepEqual(broadcasts, [{ cmd: 'settings', data: { serviceUrl: 'https://ee.example.com' } }]);
    });
});
