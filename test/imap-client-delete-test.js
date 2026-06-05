'use strict';

// Regression test for IMAPClient.delete().
//
// delete() must tear down subconnections exactly like close() does. Before the fix
// delete() skipped this.closeSubconnections(), so deleting an account left every
// Subconnection alive with its 'close'/'error' handlers, which kept reconnecting to
// the just-deleted account (a connection + timer + reconnect-storm leak).

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');

// Minimal logger that satisfies BaseClient.getLogger() and imapConfig.child().
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

function makeFakeSubconnection(path) {
    return {
        path,
        disabled: false,
        listenersRemoved: false,
        closed: false,
        removeAllListeners() {
            this.listenersRemoved = true;
        },
        close() {
            this.closed = true;
        }
    };
}

function makeConnection() {
    const connection = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: { del: async () => 1 }
    });

    // Keep delete() on its happy path without any live resources.
    connection.imapClient = null;
    connection.commandClient = null;
    connection.mailboxes = new Map();
    connection.getMailboxListKey = () => 'mailbox-list-key';

    return connection;
}

test('IMAPClient.delete() tests', async t => {
    t.after(() => {
        // The module pulls in lib/db (Redis + BullMQ queues), which keeps the event
        // loop alive. Node runs each test file in its own process, so exiting here is
        // safe and mirrors the existing redis-operations-test.js cleanup.
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('delete() closes all subconnections', async () => {
        const connection = makeConnection();
        const subA = makeFakeSubconnection('INBOX');
        const subB = makeFakeSubconnection('Archive');
        connection.subconnections = [subA, subB];

        await connection.delete();

        assert.strictEqual(subA.closed, true, 'first subconnection should be closed');
        assert.strictEqual(subB.closed, true, 'second subconnection should be closed');
        assert.strictEqual(subA.listenersRemoved, true, 'first subconnection listeners should be removed');
        assert.strictEqual(subB.listenersRemoved, true, 'second subconnection listeners should be removed');
        assert.strictEqual(connection.subconnections.length, 0, 'subconnections array should be emptied');
    });
});
