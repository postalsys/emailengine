'use strict';

// Regression tests for the reconnection backoff counter in Subconnection.reconnect().
//
// The counter must be reset only after the monitored mailbox has been opened,
// not right after connect/login succeeds. Before the fix a subconnection whose
// folder could be logged into but not opened (the phantom-folder scenario) reset
// the counter on every cycle, so a server that drops the connection after the
// failed SELECT kept the close-triggered retry loop at the base delay forever -
// the same reset-on-every-cycle storm that was fixed on the primary connection.

const test = require('node:test');
const assert = require('node:assert').strict;

const { Subconnection } = require('../lib/email-client/imap/subconnection');

// reconnect() sleeps delay + Math.random() * 1000 of jitter before connecting;
// zero the jitter so the subtests do not add real wall-clock waits (each test
// file runs in its own process, so the stub can not leak elsewhere)
test.mock.method(Math, 'random', () => 0);

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

function makeSubconnection({ mailboxOpenError } = {}) {
    const subconnection = new Subconnection({
        parent: {
            connections: new Set(),
            redis: { hSetExists: async () => 1 },
            getAccountKey: () => 'iad:test-account'
        },
        account: 'test-account',
        mailbox: { path: 'Shared Folders/team' },
        logger: noopLogger
    });

    // Shrink the scheduling delay so the pre-connect wait stays in milliseconds
    subconnection.reconnectBaseDelay = 1;

    // Replace the connection setup: successful "login", configurable mailboxOpen
    subconnection.start = async () => {
        subconnection.imapClient = {
            usable: true,
            mailboxOpen: async () => {
                if (mailboxOpenError) {
                    throw mailboxOpenError;
                }
                return {};
            }
        };
    };

    return subconnection;
}

test('Subconnection.reconnect() backoff counter', async t => {
    await t.test('keeps the counter when the monitored mailbox can not be opened', async () => {
        const mailboxOpenError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT'
        });
        const subconnection = makeSubconnection({ mailboxOpenError });
        subconnection.reconnectAttempts = 5;

        await subconnection.reconnect();

        // reconnect() increments the counter when scheduling; a failed mailbox
        // open must not reset it, otherwise every retry runs at the base delay
        assert.equal(subconnection.reconnectAttempts, 6, 'counter must keep growing while the setup keeps failing');
        assert.notEqual(subconnection.state, 'connected');
    });

    await t.test('resets the counter after the monitored mailbox is open', async () => {
        const subconnection = makeSubconnection();
        subconnection.reconnectAttempts = 5;

        await subconnection.reconnect();

        assert.equal(subconnection.reconnectAttempts, 0, 'counter must reset after a fully successful setup');
        assert.equal(subconnection.state, 'connected');
    });
});
