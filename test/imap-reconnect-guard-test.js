'use strict';

// Unit tests for IMAPClient.reconnect() guard logic (lib/email-client/imap-client.js).
// reconnect() must NOT start a new connection when one is already in progress,
// or when the client is paused/closing/closed - otherwise accounts get duplicate
// connections or reconnect storms. The actual connect (start()) is stubbed so we
// assert only the guard decisions.

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

const noopLogger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
        return noopLogger;
    }
};

function makeClient() {
    return new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: { del: async () => 1, hget: async () => null, hdel: async () => 1 }
    });
}

// Build a client whose start() is stubbed to record invocation.
function stubbedClient() {
    const client = makeClient();
    let startCalled = false;
    client.start = async () => {
        startCalled = true;
    };
    return { client, startCalled: () => startCalled };
}

registerRedisTeardown(redis);

test('IMAPClient.reconnect() guards', async t => {
    await t.test('skips when a connect is already in progress', async () => {
        const { client, startCalled } = stubbedClient();
        client._connecting = true;
        const result = await client.reconnect();
        assert.strictEqual(result, false);
        assert.strictEqual(startCalled(), false, 'start() must not be called while already connecting');
    });

    await t.test('skips when paused', async () => {
        const { client, startCalled } = stubbedClient();
        client.paused = true;
        const result = await client.reconnect();
        assert.strictEqual(result, false);
        assert.strictEqual(startCalled(), false);
    });

    await t.test('skips when closing', async () => {
        const { client, startCalled } = stubbedClient();
        client.isClosing = true;
        const result = await client.reconnect();
        assert.strictEqual(result, false);
        assert.strictEqual(startCalled(), false);
    });

    await t.test('skips when closed and not forced', async () => {
        const { client, startCalled } = stubbedClient();
        client.isClosed = true;
        const result = await client.reconnect(false);
        assert.strictEqual(result, false);
        assert.strictEqual(startCalled(), false);
    });

    await t.test('proceeds (calls start) when closed but forced', async () => {
        const { client, startCalled } = stubbedClient();
        client.isClosed = true;
        client.paused = false;
        client.isClosing = false;
        client._connecting = false;
        // Avoid the post-connect sync path and any live subconnections.
        client.state = 'unset';
        client.commandClient = null;
        client.closeSubconnections = () => {};
        client.accountObject = { loadAccountData: async () => ({ imapIndexer: 'full' }) };

        await client.reconnect(true);
        assert.strictEqual(startCalled(), true, 'forced reconnect must call start() even when closed');
    });
});
