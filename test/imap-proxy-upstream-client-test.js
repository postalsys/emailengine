'use strict';

// Regression tests for the IMAP proxy upstream client sink.
//
// ImapFlow raises connection failures with a bare emit('error'), so an instance left
// without an 'error' listener turns the next socket failure into an uncaughtException
// that kills the IMAP proxy worker. createProxy() used to construct the upstream client
// with no listener at all and rely on connect() rejecting instead of emitting - which
// leaves the window between connect() resolving and unbind() detaching ImapFlow's socket
// handlers, plus everything after the handoff, uncovered. Same failure mode as Sentry
// EMAILENGINE-COMMUNITY-2 in the IMAP worker ("read ECONNRESET" at TCP.onStreamRead).

const test = require('node:test');
const assert = require('node:assert').strict;

const { createUpstreamClient } = require('../lib/imapproxy/upstream-client');

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

function makeClient(logger) {
    // The constructor sets up state only, nothing connects until connect() is called
    return createUpstreamClient({ id: 'test-session', host: '127.0.0.1', port: 993, secure: true, logger });
}

test('createUpstreamClient()', async t => {
    await t.test('attaches an error sink', () => {
        const { logger } = makeLogger();
        const client = makeClient(logger);

        assert.equal(client.listenerCount('error'), 1);
    });

    await t.test('a socket error does not throw out of the emitter', () => {
        const { logger, warnCalls } = makeLogger();
        const client = makeClient(logger);

        const err = new Error('read ECONNRESET');
        err.code = 'ECONNRESET';

        assert.doesNotThrow(() => client.emit('error', err));

        assert.equal(warnCalls.length, 1);
        assert.equal(warnCalls[0].err, err);
        assert.equal(warnCalls[0].cid, 'test-session');
    });

    await t.test('the sink outlives the first error', () => {
        const { logger, warnCalls } = makeLogger();
        const client = makeClient(logger);

        // a once() handler would leave the client bare for every error after the first
        client.emit('error', new Error('first'));
        assert.doesNotThrow(() => client.emit('error', new Error('second')));

        assert.equal(warnCalls.length, 2);
    });
});
