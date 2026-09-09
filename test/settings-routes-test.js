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

async function captureSettingsPost(notify, call) {
    const routes = [];
    await settingsRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }, call ? { notify, call } : { notify }));
    return routes.find(route => route.method === 'POST' && route.path === '/v1/settings');
}

// The route with its worker commands recorded, for the settings that decide what the TLS listeners
// serve
async function captureWithCommands() {
    const commands = [];
    const route = await captureSettingsPost(
        async () => {},
        async message => {
            commands.push(message.cmd);
            return {};
        }
    );
    return { route, commands };
}

test('POST /v1/settings', async t => {
    // lib/settings pulls in lib/db, whose handles would keep the process alive
    registerRedisTeardown(redis);

    const originalSet = settings.set;
    const originalGet = settings.get;
    const written = [];
    // What Redis is pretending to hold, for the handler's read-before-write comparison
    const stored = {};

    t.beforeEach(() => {
        written.length = 0;
        for (let key of Object.keys(stored)) {
            delete stored[key];
        }
        settings.set = async (key, value) => {
            if (key === 'pageBrandName') {
                throw new Error('Redis is unavailable');
            }
            written.push(key);
            return 1;
        };
        settings.get = async key => (key in stored ? stored[key] : originalGet.call(settings, key));
    });

    t.afterEach(() => {
        settings.set = originalSet;
        settings.get = originalGet;
    });

    await t.test('broadcasts every written key once and reports them', async () => {
        const broadcasts = [];
        const route = await captureSettingsPost(async (cmd, data) => broadcasts.push({ cmd, data }));

        const response = await route.handler({ payload: { serviceUrl: 'https://ee.example.com', notifyText: true }, logger });

        assert.deepEqual(response, { updated: ['serviceUrl', 'notifyText'] });
        assert.deepEqual(broadcasts, [{ cmd: 'settings', data: { serviceUrl: 'https://ee.example.com', notifyText: true } }]);
    });

    await t.test('a changed certificate source reloads every TLS listener', async () => {
        // Which certificate a listener serves is resolved from the source mode and the hostname
        // list, and the `settings` broadcast carries neither to anything that acts on it. Nothing
        // else made up for it: the reconciler returns immediately for every mode but `acme`, and
        // even there it only reloads when an order produced new material. So an instance switched
        // to "self-signed only" through the API went on offering its Let's Encrypt certificate
        // until a worker restarted, and the certificate page described material nothing served.
        const { route, commands } = await captureWithCommands();

        const response = await route.handler({ payload: { tlsProvisioning: 'self-signed' }, logger });

        assert.deepEqual(response, { updated: ['tlsProvisioning'] });
        // All three: the SMTP server and the IMAP proxy resolve their material from the same
        // settings and are separate workers from the one that served this request
        assert.deepEqual(commands.sort(), ['apiReloadCertificates', 'imapProxyReloadCertificates', 'smtpReloadCertificates']);
    });

    await t.test('a changed hostname list or service URL reloads every TLS listener', async () => {
        // The service URL names the first hostname served, and the self-signed fallback is
        // regenerated when it no longer covers the configured names.
        for (const payload of [{ tlsHostnames: ['smtp.example.com'] }, { serviceUrl: 'https://mail.example.com' }]) {
            const { route, commands } = await captureWithCommands();
            await route.handler({ payload, logger });
            assert.equal(commands.length, 3, `${Object.keys(payload)[0]} reloads the listeners`);
        }
    });

    await t.test('posting back the value already stored reloads nothing', async () => {
        // A write is not a change: settings.set() is an unconditional hset, and a read-modify-write
        // client posts the whole settings object on every call. Reloading on the write alone handed
        // three listeners a new certificate every time somebody changed the timezone.
        stored.serviceUrl = 'https://ee.example.com';
        stored.tlsProvisioning = 'acme';
        const { route, commands } = await captureWithCommands();

        const response = await route.handler({ payload: { serviceUrl: 'https://ee.example.com', tlsProvisioning: 'acme' }, logger });

        assert.deepEqual(commands, [], 'nothing about what the listeners serve changed');
        assert.deepEqual(response, { updated: ['serviceUrl', 'tlsProvisioning'] }, 'the keys are still written and reported');
    });

    await t.test('the stored service URL posted back in another spelling reloads nothing', async () => {
        // settings.set() stores the origin, so the trailing slash a URL parser adds on the client
        // side is not a change to anything a listener serves - but comparing the payload against
        // the stored value made it look like one.
        stored.serviceUrl = 'https://ee.example.com';
        const { route, commands } = await captureWithCommands();

        await route.handler({ payload: { serviceUrl: 'https://ee.example.com/' }, logger });

        assert.deepEqual(commands, [], 'the same origin is stored either way');
    });

    await t.test('a reordered hostname list is the same list', async () => {
        stored.tlsHostnames = ['smtp.example.com', 'imap.example.com'];
        const { route, commands } = await captureWithCommands();

        await route.handler({ payload: { tlsHostnames: ['imap.example.com', 'smtp.example.com'] }, logger });

        assert.deepEqual(commands, [], 'the same names are served, in whatever order they arrived');
    });

    await t.test('a changed value still reloads, even next to unchanged ones', async () => {
        stored.serviceUrl = 'https://ee.example.com';
        stored.tlsHostnames = ['smtp.example.com'];
        const { route, commands } = await captureWithCommands();

        await route.handler({ payload: { serviceUrl: 'https://ee.example.com', tlsHostnames: ['smtp.example.com', 'imap.example.com'] }, logger });

        assert.equal(commands.length, 3, 'a name was added to the list');
    });

    await t.test('an unrelated setting reloads nothing', async () => {
        const { route, commands } = await captureWithCommands();

        await route.handler({ payload: { notifyText: true }, logger });

        assert.deepEqual(commands, [], 'a listener is not disturbed for a setting it does not read');
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
