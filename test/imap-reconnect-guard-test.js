'use strict';

// Unit tests for IMAPClient.reconnect() guard logic (lib/email-client/imap-client.js).
// reconnect() must NOT start a new connection when one is already in progress,
// or when the client is paused/closing/closed - otherwise accounts get duplicate
// connections or reconnect storms. The actual connect (start()) is stubbed so we
// assert only the guard decisions.
//
// Also covers the flip side of the _connecting guard: a failed connection
// cycle must clear the flag again, otherwise every later reconnection attempt
// short-circuits on the guard and the account stays dead until the worker is
// restarted.
//
// Account data is loaded inside start(), within reconnect()'s backOff loop, so
// a transient load failure (e.g. a Redis hiccup) is retried like any other
// connection failure. It used to be loaded by reconnect() itself, where a
// throw escaped past the retry scheduling and stalled the account until the
// next external trigger (resume, account update, worker restart).

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

    await t.test('clears the connecting flag when the connection cycle fails', async () => {
        const { client } = stubbedClient();
        client.state = 'unset';
        const startError = new Error('Redis connection lost');
        client.start = async () => {
            // Flag the client as closed so backOff's retry predicate declines
            // and the failure propagates out of the retry loop
            client.isClosed = true;
            throw startError;
        };

        await assert.rejects(() => client.reconnect(), startError);

        assert.strictEqual(client._connecting, false, 'a failed connection cycle must not leave the connecting flag set');
    });

    // The 'error' event handler only schedules its debounced reconnection while
    // this.reconnectTimer is unset, and only the timer callback ever nulls the
    // field. close()/delete() used to clearTimeout() the handle but leave it
    // assigned, so after pause()+resume() (which reuse the same instance) every
    // later error event saw the stale truthy handle and skipped scheduling.
    await t.test('close() drops the cleared reconnect timer handle', () => {
        const { client } = stubbedClient();
        client.reconnectTimer = setTimeout(() => {}, 60 * 1000).unref();

        client.close();

        assert.strictEqual(client.reconnectTimer, null, 'close() must drop the reconnect timer handle, not just clear it');
    });

    await t.test('delete() drops the cleared reconnect timer handle', async () => {
        const { client } = stubbedClient();
        client.reconnectTimer = setTimeout(() => {}, 60 * 1000).unref();

        await client.delete();

        assert.strictEqual(client.reconnectTimer, null, 'delete() must drop the reconnect timer handle, not just clear it');
    });

    await t.test('a later reconnect attempt is not blocked by the failed one', async () => {
        const { client } = stubbedClient();
        client.state = 'unset';
        let startCalls = 0;
        client.start = async () => {
            startCalls++;
            if (startCalls === 1) {
                client.isClosed = true;
                throw new Error('Redis connection lost');
            }
        };

        await assert.rejects(() => client.reconnect());

        // The failed cycle set isClosed to break out of the retry loop; a
        // forced reconnect (the resume path) must not be blocked by a stale
        // connecting flag left over from the failure
        const result = await client.reconnect(true);

        assert.notStrictEqual(result, false, 'reconnect must not short-circuit on a stale connecting flag');
        assert.strictEqual(startCalls, 2, 'the retry must reach start()');
        assert.strictEqual(client._connecting, false);
    });

    // Account data used to be loaded by reconnect() itself, outside the backOff
    // retry loop: the throw escaped past the retry scheduling (all reconnect()
    // callers only log rejections), so one Redis blip at the wrong instant left
    // the account disconnected until an external trigger. The load now happens
    // inside start(), where the existing backOff loop retries it.
    await t.test('a transient account data load failure is retried within the same cycle', async () => {
        const { client } = stubbedClient();
        delete client.start; // use the real start(), the load happens there
        client.state = 'unset';
        client.notify = async () => {};

        let loadCalls = 0;
        client.accountObject = {
            loadAccountData: async () => {
                loadCalls++;
                if (loadCalls === 1) {
                    throw new Error('Redis connection lost');
                }
                // No imap/oauth2 config: start() bails out cleanly with
                // state 'unset' right after the successful load
                return {};
            }
        };

        await client.reconnect();

        assert.strictEqual(loadCalls, 2, 'the account data load must be retried after the transient failure');
        assert.strictEqual(client._connecting, false);
    });
});
