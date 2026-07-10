'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Mock the db module before any other imports to prevent real Redis/BullMQ
// connections from being created. The exercised sync() path only uses the
// mailbox context's own redis stub, so the module-level mocks stay empty.
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {}
};

const mockRedis = {};

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: mockRedis,
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        documentsQueue: mockQueue,
        exportQueue: mockQueue,
        getFlowProducer: () => ({}),
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const getSecretPath = require.resolve('../lib/get-secret');
require.cache[getSecretPath] = {
    id: getSecretPath,
    filename: getSecretPath,
    loaded: true,
    parent: null,
    children: [],
    exports: async () => null
};

// Now safe to import
const { Mailbox } = require('../lib/email-client/imap/mailbox');

// Regression tests for Mailbox.sync() when SELECT fails for a listed folder.
//
// Some servers (e.g. Dovecot with mailbox list indexes) list a phantom folder
// without \Noselect, answer STATUS for it, but reject SELECT with a tagged NO
// like "NO [NONEXISTENT] Mailbox doesn't exist". Before the fix the rejection
// propagated out of sync() and aborted the entire account connection setup,
// causing an endless reconnect loop. sync() must skip such folders while still
// propagating transient connection errors so reconnect logic keeps working.

function createMockContext({ selectError, statusResult } = {}) {
    const warnCalls = [];
    let lockCalls = 0;

    const ctx = {
        path: 'Shared Folders',
        selected: false,
        syncDisabled: false,
        synced: undefined,
        logger: {
            trace() {},
            debug() {},
            info() {},
            warn(entry) {
                warnCalls.push(entry);
            },
            error() {}
        },
        getNotificationsKey: () => 'test-notifications-key',
        connection: {
            account: 'test-account',
            redis: {
                exists: async () => 0
            },
            imapClient: {
                currentLock: null,
                status: async () =>
                    statusResult !== undefined
                        ? statusResult
                        : {
                              path: 'Shared Folders',
                              messages: 0,
                              uidNext: 1,
                              uidValidity: 1n,
                              highestModseq: false
                          },
                getMailboxLock: async () => {
                    lockCalls++;
                    throw selectError;
                }
            }
        },
        // Use the real select/getMailboxLock implementations so the rejection
        // travels the same path as in production
        select: Mailbox.prototype.select,
        getMailboxLock: Mailbox.prototype.getMailboxLock
    };

    return { ctx, warnCalls, lockCalls: () => lockCalls };
}

test('Mailbox.sync() select failure handling', async t => {
    await t.test('skips folder when SELECT is rejected with a tagged NO', async () => {
        const selectError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT',
            responseText: "Mailbox doesn't exist: Shared Folders"
        });
        const { ctx, warnCalls } = createMockContext({ selectError });

        // must resolve instead of rejecting; forceEmpty=true mirrors the
        // refreshFolderList() call path used during connection setup
        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(ctx.synced, false, 'stale synced resolver must be cleared');
        assert.equal(warnCalls.filter(entry => entry.msg === 'Skipped mailbox that can not be selected').length, 1, 'skip must be logged');
    });

    await t.test('still throws for connection-level errors', async () => {
        const selectError = Object.assign(new Error('Connection not available'), {
            code: 'NoConnection'
        });
        const { ctx } = createMockContext({ selectError });

        await assert.rejects(() => Mailbox.prototype.sync.call(ctx, true), selectError);
    });

    await t.test('failed STATUS on a listed folder is still a silent skip', async () => {
        const selectError = new Error('should not be reached');
        const { ctx, lockCalls } = createMockContext({ selectError, statusResult: false });

        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(lockCalls(), 0, 'SELECT must not be attempted when STATUS already failed');
    });
});
