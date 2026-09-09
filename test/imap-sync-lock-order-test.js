'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time
require('./helpers/mock-db').installDbMock();

const { SyncOperations } = require('../lib/email-client/imap/sync-operations');
const { createSyncOperationsContext } = require('./helpers/sync-operations-context');

// Lock discipline of the sync operations.
//
// Mailbox.getMailboxStatus() reports the counters of whatever folder the
// connection has open. Read before the mailbox lock is granted, they can
// belong to a folder an API command opened in the meantime, and the sync then
// persists that folder's UIDVALIDITY, UIDNEXT and message count as this
// folder's state. Every operation therefore reads its snapshots under the
// lock, and gives the lock back exactly once - its release is what reports
// the task to the connection (see Mailbox.getMailboxLock()).

function assertReadUnderLock(calls, counters) {
    const lockAt = calls.order.indexOf('lock');
    assert.ok(lockAt >= 0, 'the lock must be taken');
    assert.ok(calls.order.indexOf('status') > lockAt, 'the mailbox counters must be read after the lock is granted');
    assert.ok(calls.order.indexOf('stored') > lockAt, 'the stored state must be read after the lock is granted');

    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0].uidValidity, counters.uidValidity, 'the persisted counters must be those of the synced folder');
    assert.equal(calls.updateStoredStatus[0].messages, counters.messages);
}

function assertLockReleased(calls) {
    assert.equal(calls.released, 1, 'the lock must be released exactly once');
    assert.equal(calls.order.at(-1), 'release', 'the release comes last');
}

test('runPartialSync reads its snapshots under the lock', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext();

    await SyncOperations.prototype.runPartialSync.call(ctx);

    assertReadUnderLock(calls, counters);
    assertLockReleased(calls);
});

test('runFastSync reads its snapshots under the lock', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext({ imapIndexer: 'fast' });

    await SyncOperations.prototype.runFastSync.call(ctx);

    assertReadUnderLock(calls, counters);
    assertLockReleased(calls);
});

// A caller-supplied snapshot is not a shortcut: onOpen() reads the stored state before the
// lock to pick a strategy from, and a sync ahead of this one in the lock queue (the EXISTS
// debounce, or a previous connection's open still unwinding after a reconnect) has moved
// uidNext on by the time the lock is granted. Trusting that copy re-FETCHes a range that was
// already handled, up to the whole folder when it reports no uidNext at all.
const STALE_STORED_STATUS = { hasStoredState: true, uidValidity: 123n, uidNext: 1, highestModseq: 2n, messages: 0, initialUidNext: 1, lastFullSync: false };

test('runPartialSync ignores a stored snapshot handed to it', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext();

    await SyncOperations.prototype.runPartialSync.call(ctx, STALE_STORED_STATUS);

    assertReadUnderLock(calls, counters);
    assert.equal(calls.fetch.range, '4:*', 'the range must come from the state read under the lock');
});

test('runFastSync ignores a stored snapshot handed to it', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext({ imapIndexer: 'fast' });

    await SyncOperations.prototype.runFastSync.call(ctx, STALE_STORED_STATUS);

    assertReadUnderLock(calls, counters);
    assert.equal(calls.fetch.range, '4:*', 'the range must come from the state read under the lock');
});

test('runFullSync reads its snapshots under the lock', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext();

    await SyncOperations.prototype.runFullSync.call(ctx);

    assertReadUnderLock(calls, counters);
    assertLockReleased(calls);
});

test('seedMailboxIndex gives the lock back', async () => {
    const { ctx, calls, counters } = createSyncOperationsContext();

    await SyncOperations.prototype.seedMailboxIndex.call(ctx, Object.assign({ path: 'INBOX' }, counters));

    assertLockReleased(calls);
});

test('a failing sync still gives the lock back', async () => {
    const { ctx, calls } = createSyncOperationsContext();
    ctx.mailbox.getStoredStatus = async () => {
        throw new Error('Redis connection lost');
    };

    await assert.rejects(() => SyncOperations.prototype.runPartialSync.call(ctx), /Redis connection lost/);

    assertLockReleased(calls);
    assert.equal(ctx.connection.syncing, false);
    assert.equal(ctx.mailbox.syncing, false);
});
