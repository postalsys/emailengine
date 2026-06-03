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

test('shouldSeedLostIndex is false on a genuine first sync (preserves notifyFrom backfill)', () => {
    // First connected session: state:count:connected === 1 by the time onOpen runs.
    const stored = { uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 1), false);
});

test('shouldSeedLostIndex is true when a prior session synced but folder state is gone', () => {
    const stored = { uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 2), true);
});

test('shouldSeedLostIndex is false when stored state is intact (uidNext is a number)', () => {
    const stored = { uidNext: 42 };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 5), false);
});

test('shouldSeedLostIndex is false when the server mailbox is empty', () => {
    const stored = { uidNext: false };
    const mailbox = { messages: 0 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 5), false);
});

test('shouldSeedLostIndex is false when the account never connected before', () => {
    const stored = { uidNext: false };
    const mailbox = { messages: 5 };
    assert.equal(shouldSeedLostIndex(stored, mailbox, 0), false);
});

// --- SyncOperations.seedMailboxIndex: the silent rebuild action -----------------------------

// Shaped like a SyncOperations instance (this.mailbox / this.connection / this.logger).
function createSeedCtx(messages) {
    const calls = {
        entryListSet: [],
        updateStoredStatus: [],
        deletedKeys: [],
        zadd: [],
        resetEvents: []
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
                }
            },
            notify: async (mailbox, event, payload) => {
                calls.resetEvents.push({ event, payload });
            }
        },
        mailbox: {
            path: 'INBOX',
            syncing: false,
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
        stored: { uidNext: false }, // mailbox hash evicted: no stored state
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
        stored: { uidNext: false, messages: false, highestModseq: false },
        mailbox: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 },
        previouslyConnected: 1
    });

    await Mailbox.prototype.onOpen.call(ctx);

    // First sync must fall through to the normal (notifyFrom-bounded) sync, not the silent reseed
    assert.equal(calls.seed.length, 0);
    assert.ok(calls.fullSync + calls.partialSync >= 1);
});
