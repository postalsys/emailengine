'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const FUTURE = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();

const trialLicense = key => ({ application: '@postalsys/emailengine-app', key, licensedTo: 'Test', trial: true, expires: FUTURE });
const fullLicense = key => ({ application: '@postalsys/emailengine-app', key, licensedTo: 'Test' });

async function cleanup() {
    await redis.hdel(`${REDIS_PREFIX}settings`, 'sentryEnabled', 'sentryAutoEnabled', 'license', 'tract', 'subexp');
}

test('Trial default for Sentry error reporting', async t => {
    t.beforeEach(cleanup);
    t.afterEach(cleanup);

    await t.test('trial activation enables reporting when the setting was never touched', async () => {
        await settings.setLicense(trialLicense('trial-key-1'), 'TEST-LICENSE');

        assert.equal(await settings.get('sentryEnabled'), true, 'reporting enabled');
        assert.equal(await settings.get('sentryAutoEnabled'), true, 'marker set');

        // re-activating the same trial is a no-op
        await settings.setLicense(trialLicense('trial-key-1'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryAutoEnabled'), true);
    });

    await t.test('trial activation respects an explicit operator choice', async () => {
        await settings.set('sentryEnabled', false);

        await settings.setLicense(trialLicense('trial-key-2'), 'TEST-LICENSE');

        assert.equal(await settings.get('sentryEnabled'), false, 'stays disabled');
        assert.equal(await settings.get('sentryAutoEnabled'), null, 'no marker');
    });

    await t.test('a full license clears the trial default', async () => {
        await settings.setLicense(trialLicense('trial-key-3'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryEnabled'), true);

        await settings.setLicense(fullLicense('full-key-1'), 'TEST-LICENSE');

        assert.equal(await settings.get('sentryEnabled'), null, 'default cleared');
        assert.equal(await settings.get('sentryAutoEnabled'), null, 'marker cleared');
    });

    await t.test('a full license keeps a manually enabled configuration', async () => {
        await settings.set('sentryEnabled', true);

        await settings.setLicense(fullLicense('full-key-2'), 'TEST-LICENSE');

        assert.equal(await settings.get('sentryEnabled'), true, 'manual choice survives');
    });

    await t.test('an explicit sentryEnabled write ends the trial-managed state', async () => {
        await settings.setLicense(trialLicense('trial-key-4'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryAutoEnabled'), true);

        // operator confirms reporting through the API or the admin UI form
        await settings.set('sentryEnabled', true);
        assert.equal(await settings.get('sentryAutoEnabled'), null, 'set() drops the marker');

        // a later full license no longer touches the now manual configuration
        await settings.setLicense(fullLicense('full-key-3'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryEnabled'), true);
    });

    await t.test('setMulti() with sentryEnabled ends the trial-managed state too', async () => {
        await settings.setLicense(trialLicense('trial-key-5'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryAutoEnabled'), true);

        // the admin UI logging form writes through setMulti()
        await settings.setMulti({ sentryEnabled: true, sentryDsn: '' });
        assert.equal(await settings.get('sentryAutoEnabled'), null, 'setMulti() drops the marker');
    });

    await t.test('removing the license clears the trial default', async () => {
        await settings.setLicense(trialLicense('trial-key-6'), 'TEST-LICENSE');
        assert.equal(await settings.get('sentryEnabled'), true);

        await settings.removeLicense();

        assert.equal(await settings.get('license'), null, 'license removed');
        assert.equal(await settings.get('sentryEnabled'), null, 'default cleared');
        assert.equal(await settings.get('sentryAutoEnabled'), null, 'marker cleared');
    });

    await t.test('removing the license keeps a manual Sentry configuration', async () => {
        await settings.set('sentryEnabled', true);

        await settings.removeLicense();

        assert.equal(await settings.get('sentryEnabled'), true, 'manual choice survives');
    });
});
