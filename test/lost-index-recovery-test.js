'use strict';

// Regression coverage for non-destructive lost-index recovery.
//
// When EmailEngine's per-mailbox sync state is lost (e.g. Redis evicted it) it must rebuild the
// index SILENTLY instead of replaying every previously-synced message as a new email, which would
// flood the webhook queue. These tests pin both halves of that behavior:
//   1. shouldSeedLostIndex - the decision: recover silently vs. treat as a genuine first sync.
//   2. Mailbox.seedMailboxIndex - the action: index existing messages without queuing messageNew.

const test = require('node:test');
const assert = require('node:assert').strict;

// Prevent real Redis / BullMQ connections the moment Mailbox is required.
// Mirrors the pattern in test/imap-should-run-partial-sync-test.js.
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {}
};

function createMockRedis() {
    return {
        status: 'ready',
        hget: async () => null,
        hset: async () => {},
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async () => ({}),
        multi: () => ({
            exec: async () => [],
            hset: function () {
                return this;
            },
            hdel: function () {
                return this;
            },
            del: function () {
                return this;
            }
        }),
        sMembers: async () => [],
        get: async () => null,
        set: async () => 'OK',
        exists: async () => 0,
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate: function () {
            return createMockRedis();
        }
    };
}

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: createMockRedis(),
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

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { shouldSeedLostIndex, SyncOperations } = require('../lib/email-client/imap/sync-operations');
const { MAILBOX_RESET_NOTIFY } = require('../lib/consts');
const { createSyncOperationsContext } = require('./helpers/sync-operations-context');

// --- shouldSeedLostIndex: the recover-silently decision -------------------------------------
//
// The stored objects below follow the getStoredStatus contract: hasStoredState reports
// whether the mailbox hash held ANY field at all (Redis eviction removes whole keys),
// while individual fields are false when absent.

test('shouldSeedLostIndex is false on a genuine first sync (preserves notifyFrom backfill)', () => {
    // First connected session: state:count:connected === 1 by the time onOpen runs.
    const stored = { hasStoredState: false, uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 1), false);
});

test('shouldSeedLostIndex is true when a prior session synced but folder state is gone', () => {
    const stored = { hasStoredState: false, uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 2), true);
});

test('shouldSeedLostIndex is false when stored state is intact', () => {
    const stored = { hasStoredState: true, uidNext: 42 };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 5), false);
});

test('shouldSeedLostIndex is false when the server mailbox is empty', () => {
    const stored = { hasStoredState: false, uidNext: false };
    const mailbox = { messages: 0 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 5), false);
});

test('shouldSeedLostIndex is false when the account never connected before', () => {
    const stored = { hasStoredState: false, uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 0), false);
});

test('shouldSeedLostIndex is false on a server that omits UIDNEXT once other state is persisted', () => {
    // Regression: servers that omit UIDNEXT from SELECT never get a stored uidNext
    // (updateStoredStatus skips falsy values), but the fields written by every sync
    // keep the hash present. Keying on uidNext alone caused an infinite reseed loop
    // with messageNew permanently suppressed.
    const stored = { hasStoredState: true, uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 3, initialUidNext: false, lastFullSync: false };
    const mailbox = { messages: 3 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 5), false);
});

test('shouldSeedLostIndex is false for a synced-but-empty mailbox (stored messages: 0 is state)', () => {
    const stored = { hasStoredState: true, uidValidity: false, uidNext: false, highestModseq: false, messages: 0, initialUidNext: false, lastFullSync: false };
    const mailbox = { messages: 4 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 3), false);
});

test('shouldSeedLostIndex is false when any single field survived in the hash', () => {
    // initialUidNext alone can remain from an interrupted first sync - the hash was not
    // evicted, so the normal notifyFrom-bounded path is the correct continuation there.
    const mailbox = { messages: 5 };
    const onlyInitialUidNext = {
        hasStoredState: true,
        uidValidity: false,
        uidNext: false,
        highestModseq: false,
        messages: false,
        initialUidNext: 7,
        lastFullSync: false
    };
    assert.equal(shouldSeedLostIndex(onlyInitialUidNext, mailbox, 5), false);
});

// --- SyncOperations.seedMailboxIndex: the silent rebuild action -----------------------------

test('seedMailboxIndex records every message without queuing any notification', async () => {
    const mailboxStatus = { uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3, path: 'INBOX' };
    const messages = [
        { uid: 10, flags: new Set(['\\Seen']) },
        { uid: 20, flags: new Set(['\\Seen', '\\Recent']) },
        { uid: null, flags: new Set() }, // partial/garbage response - must be skipped
        { uid: 30, flags: new Set() }
    ];

    const { ctx, calls } = createSyncOperationsContext({ messages });
    const indexed = await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'syncStateLost' });

    // Every valid message is recorded in the index...
    assert.equal(indexed, 3);
    assert.deepEqual(calls.entryListSet, [10, 20, 30]);

    // ...with NO notification queued (this is the whole point - no messageNew flood)
    assert.equal(calls.zadd.length, 0);

    // Stale queued notifications are dropped and the server state is persisted as the baseline
    assert.deepEqual(calls.deletedKeys, ['iam:acc:n:KEY']);
    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0], mailboxStatus);

    // The \\Recent flag is stripped before indexing
    assert.equal(messages[1].flags.has('\\Recent'), false);

    // The lock is given back (its release is what reports the task to the connection)
    assert.equal(calls.released, 1);

    // A single mailboxReset is emitted with the reason, and no prevUidValidity for a lost index
    assert.equal(calls.resetEvents.length, 1);
    assert.equal(calls.resetEvents[0].event, MAILBOX_RESET_NOTIFY);
    assert.equal(calls.resetEvents[0].payload.reason, 'syncStateLost');
    assert.equal(calls.resetEvents[0].payload.uidValidity, '123');
    assert.equal('prevUidValidity' in calls.resetEvents[0].payload, false);
});

test('seedMailboxIndex includes prevUidValidity when reseeding after a UIDVALIDITY change', async () => {
    const mailboxStatus = { uidValidity: 200n, uidNext: 2, highestModseq: 1n, messages: 1, path: 'INBOX' };
    const { ctx, calls } = createSyncOperationsContext({ messages: [{ uid: 1, flags: new Set() }] });

    await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'uidValidityChange', prevUidValidity: '123' });

    assert.equal(calls.resetEvents.length, 1);
    assert.equal(calls.resetEvents[0].payload.reason, 'uidValidityChange');
    assert.equal(calls.resetEvents[0].payload.prevUidValidity, '123');
    assert.equal(calls.zadd.length, 0);
});

// --- seedMailboxIndex in fast indexer mode ---------------------------------------------------

test('seedMailboxIndex in fast mode skips message enumeration when the server reports UIDNEXT', async () => {
    // Fast mode never maintains the message index; runFastSync only needs the stored
    // uidNext baseline, which updateStoredStatus persists from the reported value.
    const mailboxStatus = { uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 50000, path: 'INBOX' };
    const { ctx, calls } = createSyncOperationsContext({ messages: [{ uid: 1, flags: new Set() }], imapIndexer: 'fast' });

    const indexed = await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'syncStateLost' });

    assert.equal(indexed, 0);
    assert.equal(calls.fetch, undefined, 'no 1:* fetch in fast mode');
    assert.equal(calls.fetchOne.length, 0, 'no fetchOne when the server reported UIDNEXT');
    assert.equal(calls.entryListSet.length, 0, 'fast mode must not build the message index');
    assert.equal(calls.zadd.length, 0);
    assert.deepEqual(calls.deletedKeys, ['iam:acc:n:KEY']);
    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0], mailboxStatus);
    assert.equal(calls.resetEvents.length, 1);
    assert.equal(calls.resetEvents[0].event, MAILBOX_RESET_NOTIFY);
});

test('seedMailboxIndex in fast mode derives the uidNext baseline when the server omits UIDNEXT', async () => {
    // Without a stored uidNext, runFastSync would replay every message as messageNew.
    const mailboxStatus = { uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 3, path: 'INBOX' };
    const { ctx, calls } = createSyncOperationsContext({ imapIndexer: 'fast', fetchOneResult: { uid: 30 } });

    await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'syncStateLost' });

    assert.equal(calls.fetchOne.length, 1);
    assert.equal(calls.fetchOne[0].range, '*');
    // The derived baseline is persisted through the regular updateStoredStatus mechanism
    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0].uidNext, 31);
    assert.equal(mailboxStatus.uidNext, false, 'the caller-owned status object must not be mutated');
    assert.equal(calls.fetch, undefined, 'no 1:* fetch in fast mode');
    assert.equal(calls.entryListSet.length, 0);
    assert.equal(calls.zadd.length, 0);
    assert.equal(calls.resetEvents.length, 1);
});

test('seedMailboxIndex in fast mode completes without a baseline if fetchOne yields nothing', async () => {
    // A raced expunge can leave fetchOne empty-handed; the seed must still finish cleanly.
    const mailboxStatus = { uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 3, path: 'INBOX' };
    const { ctx, calls } = createSyncOperationsContext({ imapIndexer: 'fast', fetchOneResult: false });

    await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'syncStateLost' });

    assert.equal(calls.fetchOne.length, 1);
    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0].uidNext, false, 'no synthesized baseline without a UID');
    assert.equal(calls.resetEvents.length, 1);
});

// --- onOpen wiring: which branch runs when state is missing ---------------------------------

function createOnOpenCtx({ stored, mailbox, previouslyConnected, syncDisabled = false, queuedNotifications = 0 }) {
    const calls = { seed: [], fullSync: 0, partialSync: 0, select: 0, updateStoredStatus: [], notify: [] };

    const ctx = {
        selected: false,
        syncDisabled,
        runPartialSyncTimer: null,
        listingEntry: { path: 'INBOX', name: 'INBOX', specialUse: '\\Inbox', isNew: false },
        logger: { info: () => {}, debug: () => {}, warn: () => {}, error: () => {} },
        synced: null,
        connection: {
            getAccountKey: () => 'iad:acc',
            imapClient: { enabled: new Set() },
            redis: {
                hget: async () => (previouslyConnected === null ? null : String(previouslyConnected)),
                hSetNew: async () => {},
                exists: async () => queuedNotifications,
                multi() {
                    const chain = {
                        zcard: () => chain,
                        del: () => chain,
                        exec: async () => [[null, 0]]
                    };
                    return chain;
                }
            },
            notify: async (mailboxObject, event, data) => {
                calls.notify.push({ event, data });
            }
        },
        settleSyncPass: Mailbox.prototype.settleSyncPass,
        getMailboxStatus: () => mailbox,
        getStoredStatus: async () => stored,
        updateStoredStatus: async status => {
            calls.updateStoredStatus.push(status);
        },
        getNotificationsKey: () => 'iam:acc:n:KEY',
        getMailboxKey: () => 'iam:acc:h:KEY',
        getMessagesKey: () => 'iam:acc:l:KEY',
        seedMailboxIndex: async (...args) => {
            calls.seed.push(args);
            return 0;
        },
        fullSync: async () => {
            calls.fullSync++;
            return 'fullSync';
        },
        partialSync: async () => {
            calls.partialSync++;
            return 'partialSync';
        },
        select: async () => {
            calls.select++;
        }
    };

    return { ctx, calls };
}

// Shaped like the real getStoredStatus() answer for a folder that was never synced: every
// field present and false. A stored status built without the uidValidity key hid that the
// UIDVALIDITY check used to fire on it and reseed silently instead of running a full sync
function neverSyncedStatus() {
    return { hasStoredState: false, uidValidity: false, uidNext: false, messages: false, highestModseq: false, initialUidNext: false, lastFullSync: false };
}

test('onOpen recovers silently when folder state is lost after a prior session', async () => {
    const { ctx, calls } = createOnOpenCtx({
        stored: { hasStoredState: false, uidNext: false }, // mailbox hash evicted: no stored state
        mailbox: { uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3 },
        previouslyConnected: 2
    });

    const result = await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(result, false);
    assert.equal(calls.seed.length, 1);
    assert.equal(calls.seed[0][1].reason, 'syncStateLost');
    // The normal sync paths that would replay messageNew must NOT run
    assert.equal(calls.fullSync, 0);
    assert.equal(calls.partialSync, 0);
});

test('onOpen does NOT seed on a genuine first sync (normal sync path runs)', async () => {
    const { ctx, calls } = createOnOpenCtx({
        stored: neverSyncedStatus(),
        mailbox: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 },
        previouslyConnected: 1
    });

    await Mailbox.prototype.onOpen.call(ctx);

    // First sync must fall through to the normal (notifyFrom-bounded) sync, not the silent reseed
    assert.equal(calls.seed.length, 0);
    assert.equal(calls.fullSync, 1, 'the existing messages are advertised through a full sync');
    assert.equal(calls.partialSync, 0);
});

test('onOpen does NOT reseed on a server that omits UIDNEXT once state is persisted (no loop)', async () => {
    // Regression: after one seed the stored hash holds uidValidity/highestModseq/messages
    // but never uidNext on such servers. The next open must take the normal sync path,
    // not loop back into seedMailboxIndex (which suppressed messageNew forever).
    const { ctx, calls } = createOnOpenCtx({
        stored: { hasStoredState: true, uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 3, initialUidNext: false, lastFullSync: false },
        mailbox: { uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 3 },
        previouslyConnected: 3
    });

    const result = await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(calls.seed.length, 0, 'must not reseed when stored state exists');
    // Unchanged MODSEQ means no sync is needed at all on this open
    assert.equal(result, false);
    assert.equal(calls.fullSync, 0);
    assert.equal(calls.partialSync, 0);
});

test('onOpen syncs new mail in a previously-empty mailbox instead of silently reseeding', async () => {
    // A synced-but-empty folder stores messages: "0". When the first messages arrive,
    // they must be advertised via the normal sync path, not swallowed by a reseed.
    const { ctx, calls } = createOnOpenCtx({
        stored: { hasStoredState: true, uidValidity: 123n, uidNext: false, highestModseq: 9n, messages: 0, initialUidNext: false, lastFullSync: false },
        mailbox: { uidValidity: 123n, uidNext: false, highestModseq: 10n, messages: 5 },
        previouslyConnected: 3
    });

    await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(calls.seed.length, 0, 'stored messages: 0 is state, not a lost index');
    assert.ok(calls.fullSync + calls.partialSync >= 1, 'new mail must run a normal sync');
});

test('onOpen reseeds on a UIDVALIDITY change ahead of any queued notifications', async () => {
    // The queued entries reference UIDs of the previous incarnation of the folder. Replaying
    // them through a full sync against the old index used to fire messageDeleted for every
    // indexed message and messageNew for every message on the server
    const { ctx, calls } = createOnOpenCtx({
        stored: { hasStoredState: true, uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3, initialUidNext: 1, lastFullSync: false },
        mailbox: { uidValidity: 124n, uidNext: 4, highestModseq: 2n, messages: 3 },
        previouslyConnected: 3,
        queuedNotifications: 1
    });

    const result = await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(result, false);
    assert.equal(calls.seed.length, 1);
    assert.equal(calls.seed[0][1].reason, 'uidValidityChange');
    assert.equal(calls.seed[0][1].prevUidValidity, '123');
    assert.equal(calls.fullSync, 0, 'the stale queue must not be replayed');
    // The folder was recreated, not created: mailboxReset (sent by the seed) is the event
    // for that, and no mailboxNew may accompany it
    assert.equal(ctx.listingEntry.isNew, false);
    assert.equal(calls.notify.length, 0);
});

test('onOpen replays queued notifications through a full sync when UIDVALIDITY is unchanged', async () => {
    const { ctx, calls } = createOnOpenCtx({
        stored: { hasStoredState: true, uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3, initialUidNext: 1, lastFullSync: false },
        mailbox: { uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3 },
        previouslyConnected: 3,
        queuedNotifications: 1
    });

    await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(calls.seed.length, 0);
    assert.equal(calls.fullSync, 1, 'an interrupted publish is finished by a full sync');
});

test('onOpen only refreshes the counters of a folder excluded from syncing', async () => {
    // A Gmail label or a folder outside the account path list is opened by an API command
    // on the primary connection. sync() never selects such a folder; the open handler must
    // not index it or advertise its messages either
    const mailbox = { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 };
    const { ctx, calls } = createOnOpenCtx({
        stored: neverSyncedStatus(),
        mailbox,
        previouslyConnected: 3,
        syncDisabled: true
    });

    const result = await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(result, false);
    assert.deepEqual(calls.updateStoredStatus, [mailbox], 'the listing counters are kept current');
    assert.equal(calls.seed.length, 0);
    assert.equal(calls.fullSync, 0);
    assert.equal(calls.partialSync, 0);
    assert.equal(ctx.processingOpen, false, 'the latch must be released');
});

test('onOpen does not select the mailbox again once the sync is done', async () => {
    // The primary connection runs with auto-IDLE, so there is nothing to restart. The
    // extra select took a lock on the open mailbox, and that lock cancelled the
    // return-to-main-mailbox timer armed by the API command whose SELECT triggered
    // this open - the connection then stayed parked on the folder
    const { ctx, calls } = createOnOpenCtx({
        stored: neverSyncedStatus(),
        mailbox: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 },
        previouslyConnected: 1
    });

    await Mailbox.prototype.onOpen.call(ctx);

    assert.equal(calls.fullSync, 1);
    assert.equal(calls.select, 0, 'no lock may be taken after the sync');
});
