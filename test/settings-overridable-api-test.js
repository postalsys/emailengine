'use strict';

// POST /v1/settings for the settings an environment variable can override (queueKeepFailed*,
// tokenLog*, disableThreadCollapse). Regression: the schema refused null and the route wrote with
// settings.set(), so a value set through the API could never be cleared again, and the environment
// value or the default never applied after it. A null now clears the setting.

const test = require('node:test');
const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const settings = require('../lib/settings');
const settingsRoutes = require('../lib/api-routes/settings-routes');
const overrides = require('../lib/env-setting-overrides');
const { FAILED_JOB_RETENTION_COUNT_DEFAULT } = require('../lib/queue-retention');

const KEYS = ['queueKeepFailed', 'tokenLogAge', 'disableThreadCollapse'];

registerRedisTeardown(redis, () => Promise.all(KEYS.map(key => settings.clear(key))));

let server;

async function post(payload) {
    const res = await server.inject({ method: 'POST', url: '/v1/settings', payload, headers: { 'x-test-token': '{}' } });
    assert.strictEqual(res.statusCode, 200, JSON.stringify(res.result));
    return res.result;
}

async function inEffect(key) {
    overrides.resetOverridableSettingsCache();
    return (await overrides.getOverridableSettings(key))[key];
}

test('overridable settings through POST /v1/settings', async t => {
    t.before(async () => {
        server = Hapi.server({});
        server.auth.scheme('test-token', () => ({
            authenticate: (request, h) => h.authenticated({ credentials: { token: 'test' }, artifacts: {} })
        }));
        server.auth.strategy('api-token', 'test-token');
        server.ext('onRequest', (request, h) => {
            request.logger = { info() {}, error() {}, debug() {}, warn() {}, child: () => request.logger };
            // the validation failAction translates its message
            request.app.gt = { gettext: text => text };
            return h.continue;
        });
        await settingsRoutes({ server, call: async () => ({}), notify: () => {}, CORS_CONFIG: false });
        await server.initialize();
    });

    t.beforeEach(async () => {
        delete process.env.EENGINE_QUEUE_KEEP_FAILED;
        await Promise.all(KEYS.map(key => settings.clear(key)));
    });

    await t.test('a value set through the API applies, and null clears it back to the default', async () => {
        await post({ queueKeepFailed: 1234, tokenLogAge: 3600, disableThreadCollapse: true });
        assert.strictEqual(await inEffect('queueKeepFailed'), 1234);
        assert.strictEqual(await inEffect('tokenLogAge'), 3600);
        assert.strictEqual(await inEffect('disableThreadCollapse'), true);

        const result = await post({ queueKeepFailed: null, tokenLogAge: null, disableThreadCollapse: null });
        assert.deepStrictEqual(result.updated.sort(), KEYS.slice().sort());
        for (const key of KEYS) {
            assert.strictEqual(await settings.get(key), null, `${key} is no longer stored`);
        }
        assert.strictEqual(await inEffect('queueKeepFailed'), FAILED_JOB_RETENTION_COUNT_DEFAULT);
        assert.strictEqual(await inEffect('disableThreadCollapse'), false);
    });

    await t.test('the process that wrote it sees the change at once, not after the cache window', async () => {
        await post({ queueKeepFailed: 2222 });
        // read without dropping the cache first
        assert.strictEqual((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, 2222);
        await post({ queueKeepFailed: null });
        assert.strictEqual((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, FAILED_JOB_RETENTION_COUNT_DEFAULT);
    });

    await t.test('with the environment variable set, the API still stores the value and the environment wins', async () => {
        process.env.EENGINE_QUEUE_KEEP_FAILED = '777';
        try {
            await post({ queueKeepFailed: 1234 });
            assert.strictEqual(await settings.get('queueKeepFailed'), 1234, 'stored, for when the variable is removed');
            assert.strictEqual(await inEffect('queueKeepFailed'), 777);

            await post({ queueKeepFailed: null });
            assert.strictEqual(await settings.get('queueKeepFailed'), null);
            assert.strictEqual(await inEffect('queueKeepFailed'), 777);
        } finally {
            delete process.env.EENGINE_QUEUE_KEEP_FAILED;
        }
    });

    await t.test('a value outside the bounds is still refused', async () => {
        const res = await server.inject({ method: 'POST', url: '/v1/settings', payload: { queueKeepFailed: 0 }, headers: { 'x-test-token': '{}' } });
        assert.strictEqual(res.statusCode, 400);
    });
});

test('getOverridableSettings() shares one read between concurrent callers', async () => {
    overrides.resetOverridableSettingsCache();
    const originalGetMulti = settings.getMulti;
    let reads = 0;
    settings.getMulti = async (...keys) => {
        reads++;
        await new Promise(resolve => setTimeout(resolve, 20));
        return originalGetMulti.apply(settings, keys);
    };
    try {
        const results = await Promise.all(Array.from({ length: 10 }, () => overrides.getOverridableSettings('queueKeepFailed', 'tokenLogAge')));
        assert.strictEqual(reads, 1);
        assert.ok(results.every(result => result.queueKeepFailed === results[0].queueKeepFailed));
    } finally {
        settings.getMulti = originalGetMulti;
        overrides.resetOverridableSettingsCache();
    }
});

test('a failed read is not cached', async () => {
    overrides.resetOverridableSettingsCache();
    const originalGetMulti = settings.getMulti;
    let reads = 0;
    settings.getMulti = async () => {
        reads++;
        throw new Error('Redis is unavailable');
    };
    try {
        const first = await overrides.getOverridableSettings('queueKeepFailed');
        assert.strictEqual(first.queueKeepFailed, FAILED_JOB_RETENTION_COUNT_DEFAULT, 'the default applies while the read fails');
        await overrides.getOverridableSettings('queueKeepFailed');
        assert.strictEqual(reads, 2, 'the next call asks again');
    } finally {
        settings.getMulti = originalGetMulti;
        overrides.resetOverridableSettingsCache();
    }
});
