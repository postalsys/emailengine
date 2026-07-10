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
const { MAILBOX_NEW_NOTIFY } = require('../lib/consts');

// Regression tests for promise settlement in the Mailbox sync flow:
// sync() SELECT-failure handling, sync()/select() behavior when a concurrent
// operation already selected the mailbox, and onOpen() failures before the
// sync work starts.
//
// SELECT-failure background: some servers (e.g. Dovecot with mailbox list
// indexes) list a phantom folder without \Noselect, answer STATUS for it, but
// reject SELECT with a tagged NO like "NO [NONEXISTENT] Mailbox doesn't
// exist". Before the fix the rejection propagated out of sync() and aborted
// the entire account connection setup, causing an endless reconnect loop.
// sync() must skip such folders while still propagating transient connection
// errors so reconnect logic keeps working.
//
// Settlement background: sync() arms this.synced as the resolver of the
// promise it awaits, and the only production call site is onOpen()'s finally.
// Every path that skips the SELECT (already-selected early returns) or fails
// before onOpen()'s try block must still settle the promise, otherwise the
// account wedges in the syncing state forever.

function createMockContext({ selectError, statusResult, statusError, listingError, lockResult } = {}) {
    const warnCalls = [];
    let lockCalls = 0;
    let listingCalls = 0;
    const mockListing = [{ path: 'Other Folder' }];
    const processedListings = [];

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
            getCurrentListing: async () => {
                listingCalls++;
                if (listingError) {
                    throw listingError;
                }
                return mockListing;
            },
            processListing: async listing => {
                processedListings.push(listing);
            },
            redis: {
                exists: async () => 0
            },
            imapClient: {
                currentLock: null,
                mailbox: null,
                status: async () => {
                    if (statusError) {
                        throw statusError;
                    }
                    return statusResult !== undefined
                        ? statusResult
                        : {
                              path: 'Shared Folders',
                              messages: 0,
                              uidNext: 1,
                              uidValidity: 1n,
                              highestModseq: false
                          };
                },
                getMailboxLock: async () => {
                    lockCalls++;
                    if (selectError) {
                        throw selectError;
                    }
                    return lockResult || { release: () => {} };
                }
            }
        },
        // Use the real select/getMailboxLock implementations so the rejection
        // travels the same path as in production
        select: Mailbox.prototype.select,
        getMailboxLock: Mailbox.prototype.getMailboxLock
    };

    return { ctx, warnCalls, lockCalls: () => lockCalls, listingCalls: () => listingCalls, processedListings, mockListing };
}

test('Mailbox.sync() select failure handling', async t => {
    await t.test('skips folder when SELECT is rejected with a tagged NO', async () => {
        const selectError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT',
            responseText: "Mailbox doesn't exist: Shared Folders"
        });
        const { ctx, warnCalls, listingCalls } = createMockContext({ selectError });

        // must resolve instead of rejecting; forceEmpty=true mirrors the
        // refreshFolderList() call path used during connection setup
        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(ctx.synced, false, 'stale synced resolver must be cleared');
        assert.equal(warnCalls.filter(entry => entry.msg === 'Skipped mailbox that can not be selected').length, 1, 'skip must be logged');
        assert.equal(listingCalls(), 0, 'listing must not be refreshed for a phantom folder that is still listed');
    });

    await t.test('refreshes the folder listing when the mailbox is missing', async () => {
        // ImapFlow sets mailboxMissing after a SELECT NO when a verification LIST
        // shows the folder is gone (deleted by another client mid-sync)
        const selectError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT',
            responseText: "Mailbox doesn't exist: Shared Folders",
            mailboxMissing: true
        });
        const { ctx, listingCalls, processedListings, mockListing } = createMockContext({ selectError });

        // must resolve instead of rejecting so the rest of the account sync continues
        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(ctx.synced, false, 'stale synced resolver must be cleared');
        assert.equal(listingCalls(), 1, 'listing must be refreshed right away so the deletion is processed');
        assert.equal(processedListings.length, 1, 'refreshed listing must be processed so new folders are registered and synced');
        assert.equal(processedListings[0], mockListing, 'the freshly fetched listing must be passed through unmodified');
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

    await t.test('propagates a listing refresh failure from the missing-mailbox branch', async () => {
        const selectError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT',
            responseText: "Mailbox doesn't exist: Shared Folders",
            mailboxMissing: true
        });
        const listingError = Object.assign(new Error('Connection not available'), {
            code: 'NoConnection'
        });
        const { ctx, listingCalls, processedListings } = createMockContext({ selectError, listingError });

        // A failing refresh is a connection-level problem: it must reject so
        // the reconnect logic upstream schedules a retry, not be swallowed
        await assert.rejects(() => Mailbox.prototype.sync.call(ctx, true), listingError);

        assert.equal(ctx.synced, false, 'stale synced resolver must be cleared');
        assert.equal(listingCalls(), 1, 'refresh must have been attempted');
        assert.equal(processedListings.length, 0, 'a failed refresh has no listing to process');
    });

    await t.test('processes the refreshed listing when STATUS reports NotFound', async () => {
        const statusError = Object.assign(new Error('Unknown Mailbox'), {
            code: 'NotFound'
        });
        const { ctx, listingCalls, processedListings, lockCalls } = createMockContext({ statusError });

        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(lockCalls(), 0, 'SELECT must not be attempted for a folder missing at STATUS');
        assert.equal(listingCalls(), 1, 'listing must be refreshed');
        assert.equal(processedListings.length, 1, 'refreshed listing must be processed so new folders are registered and synced');
    });
});

test('Mailbox.sync() concurrent select handling', async t => {
    await t.test('returns without arming when the mailbox is selected during the status checks', { timeout: 5000 }, async () => {
        const { ctx, lockCalls } = createMockContext();

        // Simulate a concurrent operation selecting this mailbox while sync()
        // is between its entry guard and the promise arming: onOpen() sets
        // this.selected synchronously with the mailboxOpen event
        ctx.connection.redis.exists = async () => {
            ctx.selected = true;
            return 0;
        };

        const result = await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(result, false, 'sync must defer to the operation that owns the open');
        assert.equal(ctx.synced, undefined, 'the sync promise must not be armed');
        assert.equal(lockCalls(), 0, 'no SELECT must be attempted');
    });

    await t.test('resolves instead of hanging when the path is already locked-active', { timeout: 5000 }, async () => {
        const { ctx, lockCalls } = createMockContext();

        // A concurrent command holds the lock on this same path; select()
        // must settle the armed resolver because no mailboxOpen event will
        // fire for an already-open mailbox. Before the fix this test hung.
        ctx.connection.imapClient.currentLock = { path: 'Shared Folders', lockId: 1, options: {} };

        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(lockCalls(), 0, 'the active lock must not be re-acquired');
    });

    await t.test('resolves when the mailbox is found selected after the lock is acquired', { timeout: 5000 }, async () => {
        let released = 0;
        const { ctx, lockCalls } = createMockContext({ lockResult: { release: () => released++ } });

        // Another operation selected the mailbox while select() was waiting
        // for the lock: the granted lock skips the SELECT, so the armed
        // resolver must be settled before the lock is released
        ctx.connection.imapClient.mailbox = { path: 'Shared Folders' };

        await Mailbox.prototype.sync.call(ctx, true);

        assert.equal(lockCalls(), 1, 'the lock must be acquired once');
        assert.equal(released, 1, 'the granted lock must be released');
    });
});

// --- onOpen(): failures before the sync work starts must still settle the promise ---

function createOnOpenCtx({ stored, mailbox, hgetError, statusThrows } = {}) {
    const notifyCalls = [];
    let syncedCalls = 0;

    const ctx = {
        selected: false,
        runPartialSyncTimer: null,
        listingEntry: { path: 'Shared Folders', name: 'Shared Folders', specialUse: false, isNew: true },
        logger: {
            trace() {},
            debug() {},
            info() {},
            warn() {},
            error() {}
        },
        synced: () => syncedCalls++,
        connection: {
            getAccountKey: () => 'iad:test-account',
            imapClient: { enabled: new Set() },
            redis: {
                hget: async () => {
                    if (hgetError) {
                        throw hgetError;
                    }
                    return '1';
                },
                hSetNew: async () => {},
                exists: async () => 0
            },
            notify: async (mailboxObject, event, data) => {
                notifyCalls.push({ event, data });
            }
        },
        getMailboxStatus: () => {
            if (statusThrows) {
                throw statusThrows;
            }
            return mailbox;
        },
        getStoredStatus: async () => stored,
        getNotificationsKey: () => 'iam:test-account:n:KEY',
        getMailboxKey: () => 'iam:test-account:h:KEY',
        getMessagesKey: () => 'iam:test-account:l:KEY',
        seedMailboxIndex: async () => 0,
        fullSync: async () => 'fullSync',
        partialSync: async () => 'partialSync',
        select: async () => {}
    };

    return { ctx, notifyCalls, syncedCalls: () => syncedCalls };
}

test('Mailbox.onOpen() pre-sync failures', async t => {
    await t.test('settles the armed sync resolver and keeps isNew when reading mailbox status throws', async () => {
        const statusThrows = new Error('IMAP mailbox state is not available');
        const { ctx, notifyCalls, syncedCalls } = createOnOpenCtx({ statusThrows });

        await assert.rejects(() => Mailbox.prototype.onOpen.call(ctx), statusThrows);

        assert.equal(syncedCalls(), 1, 'the sync promise must be settled even when the open failed');
        assert.equal(notifyCalls.length, 0, 'no mailboxNew must be sent for a mailbox that was never synced');
        assert.equal(ctx.listingEntry.isNew, true, 'isNew must be kept so the notification is emitted on the next successful open');
    });

    await t.test('settles the armed sync resolver when the connection-count lookup throws', async () => {
        const hgetError = new Error('Redis connection lost');
        const { ctx, syncedCalls } = createOnOpenCtx({ hgetError });

        await assert.rejects(() => Mailbox.prototype.onOpen.call(ctx), hgetError);

        assert.equal(syncedCalls(), 1, 'the sync promise must be settled even when the open failed');
        assert.equal(ctx.listingEntry.isNew, true, 'isNew must be kept');
    });

    await t.test('emits mailboxNew with the mailbox uidValidity once the open succeeds', async () => {
        const { ctx, notifyCalls, syncedCalls } = createOnOpenCtx({
            stored: { hasStoredState: false, uidNext: false, messages: false, highestModseq: false, lastFullSync: false },
            mailbox: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 }
        });

        await Mailbox.prototype.onOpen.call(ctx);

        assert.equal(notifyCalls.length, 1, 'exactly one mailboxNew must be sent');
        assert.equal(notifyCalls[0].event, MAILBOX_NEW_NOTIFY);
        assert.equal(notifyCalls[0].data.uidValidity, '123');
        assert.equal(ctx.listingEntry.isNew, false, 'isNew must be consumed by a successful open');
        assert.equal(syncedCalls(), 1, 'the sync promise must be settled');
    });
});
