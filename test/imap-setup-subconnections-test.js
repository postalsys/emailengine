'use strict';

// Unit tests for the subconnection reconciler in IMAPClient.setupSubConnections()
// (lib/email-client/imap-client.js). A configured folder that disappears from the
// server listing is represented by a disabled placeholder object that shares the
// live subconnection's path. The removal loop must therefore compare the
// active/disabled status, not just the path - otherwise a live subconnection
// whose folder was deleted is never closed or demoted (it keeps reconnecting
// against a dead path and the API keeps reporting its stale state), and a
// placeholder whose folder was re-created is never replaced by a live
// subconnection.

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');
const { Subconnection } = require('../lib/email-client/imap/subconnection');
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

// Prevent real connection attempts from subconnections the reconciler creates
test.mock.method(Subconnection.prototype, 'init', async () => {});

const MISSING_PLACEHOLDER = {
    path: 'Reports',
    disabled: true,
    state: 'disabled',
    disabledReason: 'Mailbox folder not found'
};

function makeClient({ listing, subconnections }) {
    const client = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: { del: async () => 1, hget: async () => null, hdel: async () => 1 }
    });

    client.accountObject = {
        loadAccountData: async () => ({ subconnections: ['Reports'], path: '*' })
    };
    client.getCurrentListing = async () => listing;
    client.commandClient = null;
    client.subconnections = subconnections;

    return client;
}

function makeFakeLive({ disabled } = {}) {
    const calls = { close: 0, removeAllListeners: 0 };
    const fakeLive = {
        path: 'Reports',
        state: disabled ? 'disabled' : 'connected',
        ...(disabled ? { disabled: true, disabledReason: 'Mailbox folder not found' } : {}),
        close: () => calls.close++,
        removeAllListeners: () => calls.removeAllListeners++
    };
    return { fakeLive, calls };
}

registerRedisTeardown(redis);

test('IMAPClient.setupSubConnections() reconciliation', async t => {
    await t.test('replaces a live subconnection with the placeholder when its folder is missing', async () => {
        const { fakeLive, calls } = makeFakeLive();
        const client = makeClient({
            listing: [{ path: 'INBOX', specialUse: '\\Inbox' }],
            subconnections: [fakeLive]
        });

        await client.setupSubConnections();

        assert.equal(calls.removeAllListeners, 1, 'the stale live subconnection must drop its listeners');
        assert.equal(calls.close, 1, 'the stale live subconnection must be closed');
        assert.equal(client.subconnections.length, 1);
        assert.deepEqual(client.subconnections[0], MISSING_PLACEHOLDER);
    });

    await t.test('replaces the placeholder with a live subconnection when the folder is re-created', async () => {
        const client = makeClient({
            listing: [{ path: 'INBOX', specialUse: '\\Inbox' }, { path: 'Reports' }],
            subconnections: [{ ...MISSING_PLACEHOLDER }]
        });

        await client.setupSubConnections();

        assert.equal(client.subconnections.length, 1);
        assert.ok(client.subconnections[0] instanceof Subconnection, 'a live subconnection must be created');
        assert.equal(client.subconnections[0].path, 'Reports');
        assert.ok(!client.subconnections[0].disabled, 'the live subconnection must not be disabled');
    });

    await t.test('keeps the placeholder while the folder stays missing', async () => {
        const placeholder = { ...MISSING_PLACEHOLDER };
        const client = makeClient({
            listing: [{ path: 'INBOX', specialUse: '\\Inbox' }],
            subconnections: [placeholder]
        });

        await client.setupSubConnections();

        assert.equal(client.subconnections.length, 1);
        assert.equal(client.subconnections[0], placeholder, 'the same placeholder object must be kept, no churn');
    });

    await t.test('keeps a live subconnection while its folder stays listed', async () => {
        const { fakeLive, calls } = makeFakeLive();
        const client = makeClient({
            listing: [{ path: 'INBOX', specialUse: '\\Inbox' }, { path: 'Reports' }],
            subconnections: [fakeLive]
        });

        await client.setupSubConnections();

        assert.equal(client.subconnections.length, 1);
        assert.equal(client.subconnections[0], fakeLive, 'the live subconnection must be kept');
        assert.equal(calls.close, 0, 'a healthy subconnection must not be closed');
    });

    await t.test('replaces a disabled live instance with a fresh subconnection when the folder is re-created', async () => {
        // A live Subconnection that disabled itself (monitored folder deleted
        // server-side) must be cleaned up and replaced once the folder exists again
        const { fakeLive, calls } = makeFakeLive({ disabled: true });
        const client = makeClient({
            listing: [{ path: 'INBOX', specialUse: '\\Inbox' }, { path: 'Reports' }],
            subconnections: [fakeLive]
        });

        await client.setupSubConnections();

        assert.equal(calls.removeAllListeners, 1, 'the disabled instance must drop its listeners');
        assert.equal(calls.close, 1, 'the disabled instance must be closed');
        assert.equal(client.subconnections.length, 1);
        assert.ok(client.subconnections[0] instanceof Subconnection, 'a fresh live subconnection must be created');
        assert.ok(!client.subconnections[0].disabled);
    });
});
