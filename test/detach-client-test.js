'use strict';

// Regression tests for detachImapClient().
//
// ImapFlow raises connection failures with a bare emit('error'), so an instance
// left without an 'error' listener turns the next socket failure into an
// uncaughtException that kills the whole worker thread. Replaced clients used to
// be stripped with removeAllListeners() and given at most a once() handler that
// was removed again right after close(), which left a live client with no error
// listener at all - a reset arriving during the socket teardown then took the
// IMAP worker down (Sentry EMAILENGINE-COMMUNITY-2: "read ECONNRESET" at
// TCP.onStreamRead, reported from four workers of the same instance at once).

const test = require('node:test');
const assert = require('node:assert').strict;
const EventEmitter = require('events').EventEmitter;

const { detachImapClient } = require('../lib/email-client/imap/detach-client');

function makeLogger() {
    const warnCalls = [];
    return {
        warnCalls,
        logger: {
            trace() {},
            debug() {},
            info() {},
            warn(entry) {
                warnCalls.push(entry);
            },
            error() {},
            fatal() {}
        }
    };
}

test('detachImapClient()', async t => {
    await t.test('removes the previous listeners', () => {
        const { logger } = makeLogger();
        const client = new EventEmitter();

        let closeCalls = 0;
        client.on('close', () => closeCalls++);

        detachImapClient(client, logger);
        client.emit('close');

        assert.equal(closeCalls, 0, 'handlers of the abandoned client must not fire any more');
    });

    await t.test('keeps a permanent error sink attached', () => {
        const { logger, warnCalls } = makeLogger();
        const client = new EventEmitter();

        detachImapClient(client, logger, { type: 'imapClient', account: 'test-account' });

        const reset = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
        // An EventEmitter with no 'error' listener rethrows the argument, which
        // would reach the global handler and kill the worker
        assert.doesNotThrow(() => client.emit('error', reset));

        assert.equal(warnCalls.length, 1);
        assert.equal(warnCalls[0].err, reset);
        assert.equal(warnCalls[0].account, 'test-account');
        assert.equal(warnCalls[0].type, 'imapClient', 'caller meta must reach the log entry');
    });

    await t.test('survives repeated errors', () => {
        // A once() sink covered the first error only, and a socket teardown can
        // raise more than one
        const { logger, warnCalls } = makeLogger();
        const client = new EventEmitter();

        detachImapClient(client, logger);

        assert.doesNotThrow(() => client.emit('error', new Error('first')));
        assert.doesNotThrow(() => client.emit('error', new Error('second')));
        assert.doesNotThrow(() => client.emit('error', new Error('third')));

        assert.equal(warnCalls.length, 3);
    });
});
