'use strict';

// lib/email-client/connection-readiness.js: a command for an account whose connection was just set
// up (it moved to this instance, or the instance restarted) waits until the connection can answer.

const test = require('node:test');
const assert = require('node:assert').strict;

const { isStartingUp, waitUntilStarted } = require('../lib/email-client/connection-readiness');

test('isStartingUp()', () => {
    assert.equal(isStartingUp(null), false);
    assert.equal(isStartingUp({ state: 'init' }), true);
    assert.equal(isStartingUp({ state: 'connecting' }), true);
    assert.equal(isStartingUp({ state: 'syncing', mailboxes: new Map() }), true, 'no folder listing yet');
    assert.equal(isStartingUp({ state: 'syncing', mailboxes: new Map([['INBOX', {}]]) }), false, 'the listing is enough');
    assert.equal(isStartingUp({ state: 'syncing' }), false, 'an API client has no listing to wait for');
    assert.equal(isStartingUp({ state: 'connected', mailboxes: new Map() }), false);
    assert.equal(isStartingUp({ state: 'authenticationError' }), false, 'a failed connection is not waited for');
});

test('waitUntilStarted()', async t => {
    await t.test('does not wait for a connection that is up', async () => {
        assert.equal(await waitUntilStarted(() => ({ state: 'connected' }), 1000), false);
    });

    await t.test('waits until the connection is up, reading it anew each time', async () => {
        let connection = { state: 'connecting' };
        setTimeout(() => {
            connection = { state: 'syncing', mailboxes: new Map([['INBOX', {}]]) };
        }, 60);
        const started = Date.now();
        assert.equal(await waitUntilStarted(() => connection, 2000, 10), true);
        assert.ok(Date.now() - started >= 50);
    });

    await t.test('gives up after the timeout', async () => {
        const started = Date.now();
        assert.equal(await waitUntilStarted(() => ({ state: 'connecting' }), 80, 10), true);
        assert.ok(Date.now() - started < 500);
    });
});
