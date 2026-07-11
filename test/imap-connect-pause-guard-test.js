'use strict';

// Unit tests for the pause/close re-checks in IMAPClient.connect() and the
// connect() bail handling in start() (lib/email-client/imap-client.js).
//
// pause() synchronously closes the current client and writes state='paused',
// but ImapFlow's connect() has no closed-state check: a pause() landing inside
// connect()'s awaits used to let the socket open anyway, overwrite the paused
// state with 'syncing', and leave a live authenticated connection that nothing
// ever closes (a later close() no-ops on the isClosed guard). start() also
// ignored connect()'s return value, so a bailed connect still fired the
// authenticationSuccess webhook and set up subconnections.

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
    const client = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: {
            del: async () => 1,
            // Report the current state back so start()'s finally sees no drift
            hget: async (key, field) => (field === 'state' ? client.state : null),
            hdel: async () => 1,
            hSetExists: async () => 1
        }
    });
    client.setStateVal = async () => {};
    return client;
}

// pause() sets paused=true, synchronously runs close() (which flags isClosed),
// and writes state='paused'; mirror those effects inline
function simulatePause(client) {
    client.paused = true;
    client.isClosed = true;
    client.state = 'paused';
}

registerRedisTeardown(redis);

test('IMAPClient.connect() pause/close guards', async t => {
    await t.test('bails at entry when the account is already paused', async () => {
        const client = makeClient();
        let loadCalls = 0;
        client.accountObject = {
            loadAccountData: async () => {
                loadCalls++;
                return {};
            }
        };
        client.paused = true;
        client.state = 'paused';

        assert.equal(await client.connect(), false);
        assert.equal(loadCalls, 0, 'account data must not be loaded for a paused account');
        assert.equal(client.state, 'paused', 'the paused state must not be overwritten');
    });

    await t.test('bails after the account data load when pause landed mid-flight', async () => {
        const client = makeClient();
        let connectCalled = false;
        client.imapClient = {
            connect: async () => {
                connectCalled = true;
            }
        };
        client.accountObject = {
            loadAccountData: async () => {
                simulatePause(client);
                return {};
            }
        };

        assert.equal(await client.connect(), false);
        assert.equal(connectCalled, false, 'no socket may be opened for a paused account');
        assert.equal(client.state, 'paused', 'the paused state must not be overwritten');
    });

    await t.test('bails after the handshake when pause raced the connection', async () => {
        const client = makeClient();
        client.accountObject = { loadAccountData: async () => ({}) };
        client.imapClient = {
            connect: async () => {
                simulatePause(client);
            }
        };

        assert.equal(await client.connect(), false);
        assert.equal(client.state, 'paused', 'the paused state must not be overwritten with syncing');
    });
});

test('IMAPClient.start() honors a connect() bail', async () => {
    const client = makeClient();
    client.accountObject = {
        loadAccountData: async () => ({ imap: { host: '127.0.0.1', port: 9993, auth: { user: 'u', pass: 'p' } } })
    };
    // Real ImapFlow instance is constructed but never dials out - the stubbed
    // connect() below is what would open the socket
    client.getImapConfig = async () => ({
        id: 'test',
        host: '127.0.0.1',
        port: 9993,
        secure: false,
        auth: { user: 'u', pass: 'p' },
        logger: noopLogger
    });
    client.connect = async () => false;

    let notifyCalls = 0;
    let setupCalls = 0;
    let stateCountReads = 0;
    client.notify = async () => {
        notifyCalls++;
    };
    client.setupSubConnections = async () => {
        setupCalls++;
    };
    const redisHget = client.redis.hget;
    client.redis.hget = async (key, field) => {
        if (field === 'state:count:connected') {
            stateCountReads++;
        }
        return redisHget(key, field);
    };
    const hSetExistsCalls = [];
    client.redis.hSetExists = async (...args) => {
        hSetExistsCalls.push(args);
        return 1;
    };

    await client.start();

    assert.equal(notifyCalls, 0, 'no notification may be sent for a connection that was never established');
    assert.equal(setupCalls, 0, 'subconnections must not be set up for a bailed connect');
    assert.equal(stateCountReads, 0, 'the first-connection bookkeeping must be skipped');

    // The bailed client never opens a socket, so the close-listener cleanup
    // never fires - start() itself must untrack it, otherwise the paused
    // account keeps reporting connections=1 until the next resume
    assert.equal(client.connections.size, 0, 'the bailed client must be dropped from connection tracking');
    const counterWrites = hSetExistsCalls.filter(args => args[1] === 'connections');
    assert.equal(counterWrites[counterWrites.length - 1][2], '0', 'the connection counter must be written back to zero');
});
