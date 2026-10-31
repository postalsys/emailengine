'use strict';

// lib/admin-auth-watch.js: an API worker starts asking for an admin login once a password exists,
// even when the settings broadcast that normally tells it never arrived (another instance, the CLI).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createAdminAuthWatch } = require('../lib/admin-auth-watch');

const logger = { info() {}, warn() {} };

function fakeServer() {
    const server = {
        defaults: [],
        auth: {
            settings: { default: null },
            default(strategy) {
                if (server.auth.settings.default) {
                    throw new Error('Cannot set default strategy more than once');
                }
                server.auth.settings.default = { strategies: [strategy] };
                server.defaults.push(strategy);
            }
        }
    };
    return server;
}

test('admin auth watch', async t => {
    await t.test('does nothing while no password is set', async () => {
        const server = fakeServer();
        const watch = createAdminAuthWatch({ getServer: () => server, isInstanceSecured: async () => false, logger, interval: 60000 });
        assert.equal(await watch.check(), false);
        assert.deepEqual(server.defaults, []);
        watch.stop();
    });

    await t.test('switches the session default on once a password exists, exactly once', async () => {
        const server = fakeServer();
        const watch = createAdminAuthWatch({ getServer: () => server, isInstanceSecured: async () => true, logger, interval: 60000 });
        assert.equal(await watch.check(), true);
        assert.equal(await watch.check(), false);
        assert.deepEqual(server.defaults, ['session']);
        watch.stop();
    });

    await t.test('leaves a server that already has a default alone, without asking Redis', async () => {
        const server = fakeServer();
        server.auth.default('session');
        let asked = 0;
        const watch = createAdminAuthWatch({
            getServer: () => server,
            isInstanceSecured: async () => {
                asked++;
                return true;
            },
            logger,
            interval: 60000
        });
        assert.equal(await watch.check(), false);
        assert.equal(asked, 0);
        watch.stop();
    });

    await t.test('waits for the server to exist', async () => {
        const watch = createAdminAuthWatch({ getServer: () => null, isInstanceSecured: async () => true, logger, interval: 60000 });
        assert.equal(await watch.check(), false);
        watch.stop();
    });

    await t.test('runs on its own timer', async () => {
        const server = fakeServer();
        const watch = createAdminAuthWatch({ getServer: () => server, isInstanceSecured: async () => true, logger, interval: 20 });
        await new Promise(resolve => setTimeout(resolve, 80));
        assert.deepEqual(server.defaults, ['session']);
        watch.stop();
    });
});
