'use strict';

// Regression tests for the previous-client cleanup in IMAPClient.start().
//
// start() strips all listeners from the replaced client before closing it, which
// also removes the 'close' handler that deletes the client from this.connections
// and updates the Redis connection counter. Before the fix every reconnect cycle
// that replaced a still-open client leaked one ImapFlow instance in the Set (and
// inflated the API-visible 'connections' gauge) - with a failing account this
// grew by one instance per reconnect until the process ran out of memory.

const test = require('node:test');
const assert = require('node:assert').strict;
const EventEmitter = require('events').EventEmitter;

const { IMAPClient } = require('../lib/email-client/imap-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// The module pulls in lib/db (Redis + BullMQ queues), which keeps the event loop alive
registerRedisTeardown(redis);

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

function makeFakePrevClient({ closeThrows } = {}) {
    const prev = new EventEmitter();
    prev.disabled = false;
    prev.closed = false;
    prev.close = () => {
        prev.closed = true;
        if (closeThrows) {
            throw new Error('close failed');
        }
    };
    return prev;
}

function makeClient() {
    const hSetExistsCalls = [];
    const client = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: {
            del: async () => 1,
            hget: async () => null,
            hdel: async () => 1,
            hSetExists: async (...args) => {
                hSetExistsCalls.push(args);
                return 1;
            }
        }
    });

    // Empty account data makes start() return right after the previous-client
    // cleanup block ("can not make a connection" path), keeping the test focused
    client.accountObject = { loadAccountData: async () => ({}) };
    // Matching initial state keeps the state-sync logic in start()'s finally inert
    client.state = 'unset';

    return { client, hSetExistsCalls };
}

test('IMAPClient.start() previous client cleanup', async t => {
    await t.test('removes the replaced client from connection tracking', async () => {
        const { client, hSetExistsCalls } = makeClient();
        const prev = makeFakePrevClient();
        client.imapClient = prev;
        client.connections.add(prev);

        await client.start();

        assert.equal(prev.closed, true);
        assert.equal(prev.disabled, true);
        assert.equal(client.imapClient, null);
        assert.equal(client.connections.has(prev), false, 'replaced client must be dropped from the connections set');
        assert.equal(client.connections.size, 0);

        const counterWrites = hSetExistsCalls.filter(args => args[1] === 'connections');
        assert.equal(counterWrites.length, 1, 'connection counter must be updated once');
        assert.equal(counterWrites[0][2], '0');
    });

    await t.test('cleanup still runs when close() throws', async () => {
        const { client, hSetExistsCalls } = makeClient();
        const prev = makeFakePrevClient({ closeThrows: true });
        client.imapClient = prev;
        client.connections.add(prev);

        await client.start();

        assert.equal(client.connections.has(prev), false);
        assert.equal(hSetExistsCalls.filter(args => args[1] === 'connections').length, 1);
    });

    await t.test('no double decrement if the replaced client emits close later', async () => {
        const { client, hSetExistsCalls } = makeClient();
        const prev = makeFakePrevClient();
        client.imapClient = prev;
        client.connections.add(prev);

        await client.start();
        // listeners were stripped, so this must be a no-op
        prev.emit('close');

        assert.equal(client.connections.size, 0);
        assert.equal(hSetExistsCalls.filter(args => args[1] === 'connections').length, 1, 'counter must not be written again');
    });
});
