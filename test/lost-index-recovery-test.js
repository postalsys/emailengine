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

// Shaped like a SyncOperations instance (this.mailbox / this.connection / this.logger).
function createSeedCtx(messages, opts = {}) {
    const calls = {
        entryListSet: [],
        updateStoredStatus: [],
        deletedKeys: [],
        zadd: [],
        resetEvents: [],
        fetchOne: []
    };

    const redis = {
        del: async key => {
            calls.deletedKeys.push(key);
        },
        zadd: async (...args) => {
            // Recording any zadd lets a test fail loudly if a notification is ever queued
            calls.zadd.push(args);
        }
    };

    const ctx = {
        logger: { warn: () => {}, debug: () => {}, error: () => {} },
        connection: {
            syncing: false,
            redis,
            imapClient: {
                fetch: (range, fields, opts) => {
                    calls.fetch = { range, fields, opts };
                    return (async function* () {
                        for (const m of messages) {
                            yield m;
                        }
                    })();
                },
                fetchOne: async (range, fields) => {
                    calls.fetchOne.push({ range, fields });
                    return 'fetchOneResult' in opts ? opts.fetchOneResult : false;
                }
            },
            notify: async (mailbox, event, payload) => {
                calls.resetEvents.push({ event, payload });
            }
        },
        mailbox: {
            path: 'INBOX',
            syncing: false,
            imapIndexer: opts.imapIndexer || 'full',
            listingEntry: { path: 'INBOX', name: 'INBOX', specialUse: '\\Inbox' },
            getNotificationsKey: () => 'iam:acc:n:KEY',
            getMailboxLock: async () => ({ release: () => {} }),
            entryListSet: async data => {
                calls.entryListSet.push(data.uid);
            },
            updateStoredStatus: async data => {
                calls.updateStoredStatus.push(data);
            }
        }
    };

    return { ctx, calls };
}

test('seedMailboxIndex records every message without queuing any notification', async () => {
    const mailboxStatus = { uidValidity: 123n, uidNext: 51, highestModseq: 10n, messages: 3, path: 'INBOX' };
    const messages = [
        { uid: 10, flags: new Set(['\\Seen']) },
        { uid: 20, flags: new Set(['\\Seen', '\\Recent']) },
        { uid: null, flags: new Set() }, // partial/garbage response - must be skipped
        { uid: 30, flags: new Set() }
    ];

    const { ctx, calls } = createSeedCtx(messages);
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

    // A single mailboxReset is emitted with the reason, and no prevUidValidity for a lost index
    assert.equal(calls.resetEvents.length, 1);
    assert.equal(calls.resetEvents[0].event, MAILBOX_RESET_NOTIFY);
    assert.equal(calls.resetEvents[0].payload.reason, 'syncStateLost');
    assert.equal(calls.resetEvents[0].payload.uidValidity, '123');
    assert.equal('prevUidValidity' in calls.resetEvents[0].payload, false);
});

test('seedMailboxIndex includes prevUidValidity when reseeding after a UIDVALIDITY change', async () => {
    const mailboxStatus = { uidValidity: 200n, uidNext: 2, highestModseq: 1n, messages: 1, path: 'INBOX' };
    const { ctx, calls } = createSeedCtx([{ uid: 1, flags: new Set() }]);

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
    const { ctx, calls } = createSeedCtx([{ uid: 1, flags: new Set() }], { imapIndexer: 'fast' });

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
    const { ctx, calls } = createSeedCtx([], { imapIndexer: 'fast', fetchOneResult: { uid: 30 } });

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
    const { ctx, calls } = createSeedCtx([], { imapIndexer: 'fast', fetchOneResult: false });

    await SyncOperations.prototype.seedMailboxIndex.call(ctx, mailboxStatus, { reason: 'syncStateLost' });

    assert.equal(calls.fetchOne.length, 1);
    assert.equal(calls.updateStoredStatus.length, 1);
    assert.equal(calls.updateStoredStatus[0].uidNext, false, 'no synthesized baseline without a UID');
    assert.equal(calls.resetEvents.length, 1);
});

// --- onOpen wiring: which branch runs when state is missing ---------------------------------

function createOnOpenCtx({ stored, mailbox, previouslyConnected }) {
    const calls = { seed: [], fullSync: 0, partialSync: 0, select: 0 };

    const ctx = {
        selected: false,
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
                exists: async () => 0
            }
        },
        getMailboxStatus: () => mailbox,
        getStoredStatus: async () => stored,
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
        stored: { hasStoredState: false, uidNext: false, messages: false, highestModseq: false },
        mailbox: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 },
        previouslyConnected: 1
    });

    await Mailbox.prototype.onOpen.call(ctx);

    // First sync must fall through to the normal (notifyFrom-bounded) sync, not the silent reseed
    assert.equal(calls.seed.length, 0);
    assert.ok(calls.fullSync + calls.partialSync >= 1);
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
