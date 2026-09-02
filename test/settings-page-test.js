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
});
