'use strict';

// Regression tests for Subconnection lifecycle cleanup.
//
// start(): same defect class as in IMAPClient.start() - removeAllListeners()
// on the replaced client strips the 'close' handler that removes the client
// from parent.connections and updates the Redis connection counter, so every
// subconnection reconnect leaked the previous ImapFlow instance.
//
// close(): must drop the pending 'changes' debounce timer. The mailboxMissing
// disable path closes the subconnection while the parent's listeners are still
// attached, so a surviving timer would emit on the closed instance and trigger
// a pointless sync for the removed folder.

const test = require('node:test');
const assert = require('node:assert').strict;
const EventEmitter = require('events').EventEmitter;

const { Subconnection } = require('../lib/email-client/imap/subconnection');

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

function makeSubconnection() {
    const hSetExistsCalls = [];
    const stopError = new Error('stop after cleanup');

    const parent = {
        connections: new Set(),
        redis: {
            hSetExists: async (...args) => {
                hSetExistsCalls.push(args);
                return 1;
            }
        },
        getAccountKey: () => 'iad:test-account'
    };

    const subconnection = new Subconnection({
        parent,
        account: 'test-account',
        mailbox: { path: 'INBOX' },
        logger: noopLogger,
        // Throwing here aborts start() right after the previous-client cleanup
        getImapConfig: async () => {
            throw stopError;
        }
    });

    return { subconnection, parent, hSetExistsCalls, stopError };
}

test('Subconnection.start() previous client cleanup', async t => {
    await t.test('removes the replaced client from parent connection tracking', async () => {
        const { subconnection, parent, hSetExistsCalls, stopError } = makeSubconnection();
        const prev = makeFakePrevClient();
        subconnection.imapClient = prev;
        parent.connections.add(prev);

        await assert.rejects(() => subconnection.start(), stopError);

        assert.equal(prev.closed, true);
        assert.equal(prev.disabled, true);
        assert.equal(subconnection.imapClient, null);
        assert.equal(parent.connections.has(prev), false, 'replaced client must be dropped from the parent connections set');

        const counterWrites = hSetExistsCalls.filter(args => args[1] === 'connections');
        assert.equal(counterWrites.length, 1, 'connection counter must be updated once');
        assert.equal(counterWrites[0][2], '0');
    });

    await t.test('cleanup still runs when close() throws', async () => {
        const { subconnection, parent, hSetExistsCalls, stopError } = makeSubconnection();
        const prev = makeFakePrevClient({ closeThrows: true });
        subconnection.imapClient = prev;
        parent.connections.add(prev);

        await assert.rejects(() => subconnection.start(), stopError);

        assert.equal(parent.connections.has(prev), false);
        assert.equal(hSetExistsCalls.filter(args => args[1] === 'connections').length, 1);
    });
});

test('Subconnection.close() timer cleanup', async t => {
    await t.test('drops the pending changes debounce', t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });

        const { subconnection } = makeSubconnection();
        let changesEmitted = 0;
        subconnection.on('changes', () => changesEmitted++);

        // Arm the debounce as a flags/exists notification would, then close
        // before it fires
        subconnection.requestSync();
        subconnection.close();

        t.mock.timers.tick(1000);

        assert.equal(changesEmitted, 0, 'a closed subconnection must not emit changes');
        assert.equal(subconnection.emitTimer, false, 'close() must drop the debounce timer handle');
    });
});
