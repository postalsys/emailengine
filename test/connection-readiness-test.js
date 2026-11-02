'use strict';

// lib/email-client/connection-readiness.js: a command for an account whose connection was just set
// up (it moved to this instance, or the instance restarted) waits until the connection can answer.

const test = require('node:test');
const assert = require('node:assert').strict;

const { isStartingUp, createStartSignal } = require('../lib/email-client/connection-readiness');

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

test('createStartSignal()', async t => {
    await t.test('does not wait for a connection that started', async () => {
        const signal = createStartSignal();
        signal.note({ state: 'connected' });
        assert.equal(signal.started, true);
        assert.equal(await signal.wait(1000), false);
    });

    await t.test('a wait ends as soon as the connection starts', async () => {
        const signal = createStartSignal();
        signal.note({ state: 'connecting' });
        assert.equal(signal.started, false);
        setTimeout(() => signal.note({ state: 'syncing', mailboxes: new Map([['INBOX', {}]]) }), 60);
        const started = Date.now();
        assert.equal(await signal.wait(2000), true);
        const took = Date.now() - started;
        assert.ok(took >= 50 && took < 1000, `waited ${took} ms`);
    });

    await t.test('gives up after the timeout', async () => {
        const signal = createStartSignal();
        const started = Date.now();
        assert.equal(await signal.wait(80), true);
        assert.ok(Date.now() - started < 500);
        assert.equal(signal.started, false);
    });

    await t.test('a release ends every wait without marking the connection started', async () => {
        const signal = createStartSignal();
        const waits = [signal.wait(5000), signal.wait(5000)];
        signal.release();
        assert.deepEqual(await Promise.all(waits), [true, true]);
        assert.equal(signal.started, false);
    });

    await t.test('a connection that came up as far as it will for now ends the waits for good', async () => {
        // A failed init() that is retried later: waiting on it again for every command held each
        // of them for half its budget for as long as the provider was unreachable
        const signal = createStartSignal();
        signal.note({ state: 'connecting' });
        const waiting = signal.wait(5000);
        signal.give();
        assert.equal(await waiting, true);
        assert.equal(signal.started, true);
        assert.equal(await signal.wait(5000), false);
    });

    await t.test('started stays started when the connection drops and reconnects', async () => {
        // A connection that keeps reconnecting is not waited for: a command for it fails at once
        const signal = createStartSignal();
        signal.note({ state: 'connected' });
        signal.note({ state: 'connecting' });
        assert.equal(signal.started, true);
    });
});

test('an email client notes every state it is set to', async () => {
    require('./helpers/mock-db').installDbMock();
    const { BaseClient } = require('../lib/email-client/base-client');
    const client = new BaseClient('acc', {});
    client.state = 'connecting';
    assert.equal(client.startSignal.started, false);
    client.state = 'authenticationError';
    assert.equal(client.state, 'authenticationError');
    assert.equal(client.startSignal.started, true, 'a failed connection is not waited for');
});
