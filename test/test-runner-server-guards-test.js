'use strict';

// test/run-tests.js boots a live server for the integration and dovecot tiers and polls /health
// until it answers. Two ways that went wrong without anyone noticing: a stale listener already on
// the API port answered /health, so the tier ran against old code on a freshly flushed database,
// and a server that crashed during boot was only reported after the full two minute readiness
// timeout. These pin the guards for both.

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const { assertPortFree, TIERS } = require('./run-tests');
const { waitForServer } = require('./helpers/wait-for-server');

test('assertPortFree() refuses a port something is listening on', async () => {
    const listener = net.createServer(socket => socket.destroy());
    await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
    const { port } = listener.address();
    try {
        await assert.rejects(() => assertPortFree(port), /already in use/);
    } finally {
        await new Promise(resolve => listener.close(resolve));
    }

    // and accepts it once the listener is gone
    await assertPortFree(port);
});

test('waitForServer() rejects as soon as the server process has exited', async () => {
    const child = spawn(process.execPath, ['-e', 'process.exit(3)'], { stdio: 'ignore' });
    await once(child, 'exit');

    const started = Date.now();
    await assert.rejects(() => waitForServer({ child }), /Server process exited \(exit code 3\)/);
    // Well short of the two minute readiness timeout; one poll at most
    assert.ok(Date.now() - started < 10000, `took ${Date.now() - started}ms`);
});

test('every tier that boots a server has a stall budget and the dovecot tier enables the listeners', () => {
    for (const [name, tier] of Object.entries(TIERS)) {
        if (tier.serverEnv) {
            assert.ok(tier.stallTimeout > (tier.testTimeout || 180000), `${name}: stallTimeout must exceed the per-test timeout`);
        }
    }

    const env = TIERS.dovecot.serverEnv();
    const prepared = JSON.parse(env.EENGINE_SETTINGS);
    assert.strictEqual(prepared.smtpServerEnabled, true);
    assert.strictEqual(prepared.imapProxyServerEnabled, true);
    // The settings from config/test.toml are kept, not replaced
    assert.strictEqual(prepared.serviceSecret, 'a cat');
});
