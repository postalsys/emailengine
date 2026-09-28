'use strict';

// Timers and shared connections of the IMAP client that nothing else tracked:
//
// - IMAP-4: a failed connection setup in reconnect() armed a bare setTimeout. It was not debounced
//   against the close handler's own retry (two start() calls, the second tearing down the healthy
//   connection the first had just made) and close()/pause() could not clear it, so it survived a
//   pause and tore the resumed connection down.
// - IMAP-5: a failed resync was retried through the function that arms the regular interval, so the
//   "retry in 4 seconds" became 15 minutes plus 4 seconds, from an untracked timer.
// - IMAP-8: the subconnection reconciler closed whichever command client it found after its listing
//   call, including one API requests were streaming through, and a late event from a replaced
//   command client dropped the reference to its successor.

const test = require('node:test');
const assert = require('node:assert').strict;
const { EventEmitter } = require('node:events');

require('./helpers/mock-db').installDbMock();

const { ImapFlow } = require('imapflow');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

function makeClient() {
    const client = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: { del: async () => 1, hget: async () => null, hdel: async () => 1, hSetExists: async () => 1 }
    });
    client.closeSubconnections = () => {};
    return client;
}

test('IMAPClient.reconnect() setup failure retry', async t => {
    t.beforeEach(() => t.mock.timers.enable({ apis: ['setTimeout'] }));
    t.afterEach(() => t.mock.timers.reset());

    function failingSetup() {
        const client = makeClient();
        let starts = 0;
        client.start = async () => {
            starts++;
        };
        client.state = 'connecting';
        client.checkIMAPConnection = () => {};
        client.syncMailboxes = async () => {
            throw new Error('LIST failed');
        };
        return { client, starts: () => starts };
    }

    await t.test('is armed in the tracked reconnect slot', async () => {
        const { client } = failingSetup();

        await client.reconnect();

        assert.ok(client.reconnectTimer, 'the retry lives in this.reconnectTimer');
        client.close();
    });

    await t.test('close() clears it, so a pause does not leave it to tear down the resumed connection', async () => {
        const { client, starts } = failingSetup();

        await client.reconnect();
        client.close();
        t.mock.timers.tick(60 * 1000);
        await new Promise(resolve => setImmediate(resolve));

        assert.equal(client.reconnectTimer, null);
        assert.equal(starts(), 1, 'no second start() after close()');
    });

    await t.test('does not stack a second timer on a retry the close handler already scheduled', async () => {
        const { client } = failingSetup();
        const scheduled = setTimeout(() => {}, 1000);
        client.reconnectTimer = scheduled;

        await client.reconnect();

        assert.strictEqual(client.reconnectTimer, scheduled, 'one retry slot, whichever handler armed it first');
        client.close();
    });
});

test('IMAPClient resync retry', async t => {
    t.beforeEach(() => t.mock.timers.enable({ apis: ['setTimeout'] }));
    t.afterEach(() => t.mock.timers.reset());

    const flush = async () => {
        for (let i = 0; i < 5; i++) {
            await new Promise(resolve => setImmediate(resolve));
        }
    };

    function failingResync() {
        const client = makeClient();
        client.resyncDelay = 15 * 60 * 1000;
        let passes = 0;
        client.syncMailboxes = async () => {
            passes++;
            throw new Error('STATUS failed');
        };
        return { client, passes: () => passes };
    }

    await t.test('a failed pass is retried after the short backoff, not the full interval', async () => {
        const { client, passes } = failingResync();

        client.scheduleResync(client.resyncDelay);
        t.mock.timers.tick(client.resyncDelay);
        await flush();
        assert.equal(passes(), 1);

        // 2000 * 2^1: the retry comes after 4 seconds, where it used to wait 15 minutes more
        t.mock.timers.tick(4000);
        await flush();
        assert.equal(passes(), 2);
        client.close();
    });

    await t.test('the retry is tracked, so close() clears it', async () => {
        const { client, passes } = failingResync();

        client.scheduleResync(client.resyncDelay);
        t.mock.timers.tick(client.resyncDelay);
        await flush();
        client.close();

        t.mock.timers.tick(client.resyncDelay * 2);
        await flush();
        assert.equal(passes(), 1, 'no pass runs on a closed client');
    });

    await t.test('a pass that keeps failing falls back to the regular interval', async () => {
        const { client, passes } = failingResync();

        client.scheduleResync(0);
        t.mock.timers.tick(0);
        await flush();
        // five fast retries: 4, 8, 16, 30, 30 seconds
        for (const delay of [4000, 8000, 16000, 30000, 30000]) {
            t.mock.timers.tick(delay);
            await flush();
        }
        assert.equal(passes(), 6);

        t.mock.timers.tick(30000);
        await flush();
        assert.equal(passes(), 6, 'the sixth failure waits for the regular interval');

        t.mock.timers.tick(client.resyncDelay);
        await flush();
        assert.equal(passes(), 7);
        client.close();
    });
});

test('IMAPClient command client ownership', async t => {
    await t.test('processSubConnections() leaves a pre-existing command client open', async () => {
        const client = makeClient();
        let closed = 0;
        const shared = { usable: true, close: () => closed++ };
        client.commandClient = shared;
        client.accountObject = { loadAccountData: async () => ({ subconnections: ['Missing'] }) };
        client.getCurrentListing = async () => [];
        client.processNewListingEntries = () => {};

        await client.processSubConnections();

        assert.equal(closed, 0, 'an API request may be streaming through it');
        assert.strictEqual(client.commandClient, shared);
    });

    await t.test('processSubConnections() closes a command client its own listing call created', async () => {
        const client = makeClient();
        let closed = 0;
        const created = { usable: true, close: () => closed++ };
        client.commandClient = null;
        client.accountObject = { loadAccountData: async () => ({ subconnections: ['Missing'] }) };
        client.getCurrentListing = async () => {
            client.commandClient = created;
            return [];
        };
        client.processNewListingEntries = () => {};

        await client.processSubConnections();

        assert.equal(closed, 1);
        assert.equal(client.commandClient, null);
    });

    await t.test('a late event from a replaced command client keeps its successor', async () => {
        t.mock.method(ImapFlow.prototype, 'connect', async () => {});
        t.mock.method(ImapFlow.prototype, 'close', () => {});

        const client = makeClient();
        client.accountObject = {
            getLock: () => ({ waitAcquireLock: async () => ({ success: true }), releaseLock: async () => {} }),
            loadAccountData: async () => ({ imap: { host: 'localhost', port: 993 } })
        };
        client.getImapConfig = async () => ({ host: 'localhost', port: 993, auth: { user: 'u', pass: 'p' }, logger: false });
        client.untrackConnection = async () => {};

        const first = await client.getCommandConnection('test');
        assert.ok(first instanceof EventEmitter);

        const successor = { usable: true, close() {} };
        client.commandClient = successor;

        first.emit('error', Object.assign(new Error('Socket timeout'), { code: 'ETIMEOUT' }));
        assert.strictEqual(client.commandClient, successor, 'the error handler of the old client must not drop the new one');

        first.emit('close');
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(client.commandClient, successor, 'nor its close handler');
    });
});
