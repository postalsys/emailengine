'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const Joi = require('joi');

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_settings_page';

const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { registerSettingsPage } = require('../lib/ui-routes/settings-page');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length > 0) {
        await redis.del(keys);
    }
});

// The shared settings-form helper (lib/ui-routes/settings-page.js). Registers a page on a stub
// server and renders through a stub `h` to inspect the view context.
test('registerSettingsPage', async t => {
    const routes = {};
    registerSettingsPage(
        { route: def => (routes[def.method] = def) },
        {
            path: '/admin/config/example',
            view: 'config/example',
            pageTitle: 'Example',
            menuKey: 'menuConfigExample',
            schema: { webhooks: Joi.string().allow(''), notifyText: Joi.boolean() },
            loadValues: async () => ({ webhooks: 'https://example.com/hook', notifyText: false }),
            applySettings: async () => {}
        }
    );

    const render = async () => {
        let rendered;
        await routes.GET.handler({}, { view: (view, context) => (rendered = { view, context }) });
        return rendered;
    };

    await t.test('flags the fields EENGINE_SETTINGS re-applies on every boot', async () => {
        // `notifyText` is not part of this form and `serviceUrl` is not a form field at all
        await settings.set('preparedSettingsKeys', ['webhooks', 'serviceUrl']);

        const { view, context } = await render();

        assert.equal(view, 'config/example');
        assert.equal(context.pageTitle, 'Example');
        assert.equal(context.menuConfig, true);
        assert.equal(context.menuConfigExample, true);
        assert.deepEqual(context.values, { webhooks: 'https://example.com/hook', notifyText: false });
        assert.deepEqual(context.envManagedKeys, ['webhooks']);
    });

    await t.test('flags nothing once the prepared settings are gone', async () => {
        await settings.clear('preparedSettingsKeys');

        const { context } = await render();

        assert.deepEqual(context.envManagedKeys, []);
    });

    await t.test('a page with no overridable field never lists one', async () => {
        const { context } = await render();
        assert.deepEqual(context.envOverriddenSettings, []);
    });
});

test('registerSettingsPage flags fields their own environment variable pins', async t => {
    const routes = {};
    registerSettingsPage(
        { route: def => (routes[def.method] = def) },
        {
            path: '/admin/config/overridable',
            view: 'config/overridable',
            pageTitle: 'Overridable',
            menuKey: 'menuConfigOverridable',
            schema: { queueKeepFailed: Joi.number(), tokenLogAge: Joi.number(), queueKeep: Joi.number() },
            loadValues: async () => ({}),
            applySettings: async () => {}
        }
    );
    const render = async () => {
        let rendered;
        await routes.GET.handler({}, { view: (view, context) => (rendered = { view, context }) });
        return rendered.context;
    };

    await t.test('nothing is pinned while the variables are unset', async () => {
        assert.deepEqual((await render()).envOverriddenSettings, []);
    });

    await t.test('a set variable pins its own field, and only on a page that has the field', async () => {
        process.env.EENGINE_QUEUE_KEEP_FAILED = '2500';
        // set, but not for a field of this page
        process.env.EENGINE_TOKEN_LOG_ENTRIES = '10';
        try {
            assert.deepEqual((await render()).envOverriddenSettings, [{ key: 'queueKeepFailed', env: 'EENGINE_QUEUE_KEEP_FAILED' }]);
        } finally {
            delete process.env.EENGINE_QUEUE_KEEP_FAILED;
            delete process.env.EENGINE_TOKEN_LOG_ENTRIES;
        }
    });
});
