'use strict';

// Regression test for IMAP notification handlers (Commit 4).
//
// The 'exists'/'mailboxOpen'/'mailboxClose'/'flags' listeners and expungeHandler
// evaluated normalizePath(event.path) and the mailbox lookup OUTSIDE their
// try/catch. A throw there (e.g. a path whose stringification throws) became an
// unhandled rejection in an async listener, killing the IMAP worker and every
// account assigned to it. The handlers now wrap the full body, so a malformed
// event is swallowed and logged instead.

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');

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

function makeConnection() {
    const connection = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: { del: async () => 1 }
    });
    connection.mailboxes = new Map();
    return connection;
}

// A path whose stringification throws - this reaches normalizePath()'s internal
// regexp test and throws, exercising the code that used to run outside try/catch.
function throwingPathEvent() {
    return {
        path: {
            toString() {
                throw new Error('malformed path');
            }
        }
    };
}

test('IMAP event handlers do not crash on malformed events', async t => {
    t.after(() => {
        // imap-client pulls in lib/db (Redis + queues); exit the per-file process.
        setTimeout(() => process.exit(), 1000).unref();
    });

    const cases = [
        { method: 'handleExistsEvent', usesClientLog: true },
        { method: 'handleMailboxOpenEvent', usesClientLog: true },
        { method: 'handleMailboxCloseEvent', usesClientLog: true },
        { method: 'handleFlagsEvent', usesClientLog: true }
    ];

    for (let { method } of cases) {
        await t.test(`${method}() swallows and logs a malformed-event throw`, async () => {
            const connection = makeConnection();
            let logged = false;
            const client = {
                log: {
                    error() {
                        logged = true;
                    },
                    debug() {
                        logged = true;
                    }
                }
            };

            await connection[method](client, throwingPathEvent());
            assert.strictEqual(logged, true, `${method} should log the caught error`);
        });
    }

    await t.test('expungeHandler() swallows and logs a malformed-event throw', async () => {
        const connection = makeConnection();
        let logged = false;
        connection.logger = Object.assign({}, noopLogger, {
            error() {
                logged = true;
            }
        });

        await connection.expungeHandler(throwingPathEvent());
        assert.strictEqual(logged, true, 'expungeHandler should log the caught error');
    });
});
