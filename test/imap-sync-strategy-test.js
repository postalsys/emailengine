'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Prevent real Redis / BullMQ connections when sync-operations.js transitively
// requires lib/db via lib/tools and lib/settings. Mirrors the pattern in
// test/process-changes-test.js — otherwise the event loop never resolves.
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

const {
    hasUidValidityChanged,
    hasNoModseqChanges,
    canUseCondstorePartialSync,
    canUseSimplePartialSync,
    canSkipSync,
    isRecentFullSync,
    getFetchRange,
    FULL_SYNC_DELAY,
    FETCH_BATCH_SIZE
} = require('../lib/email-client/imap/sync-operations');

// The shape here mirrors getStoredStatus()/getMailboxStatus() output so the
// helpers see the same types they would at runtime. messages and uidNext are
// Numbers (or false), highestModseq and uidValidity are BigInts (or false).
function storedStatus(overrides = {}) {
    return Object.assign(
        {
            path: 'INBOX',
            uidValidity: false,
            highestModseq: false,
            messages: false,
            uidNext: false,
            initialUidNext: false,
            noInferiors: false,
            lastFullSync: false
        },
        overrides
    );
}

function mailboxStatus(overrides = {}) {
    return Object.assign(
        {
            path: 'INBOX',
            highestModseq: false,
            uidValidity: false,
            uidNext: false,
            messages: 0
        },
        overrides
    );
}

test('hasUidValidityChanged returns false when stored has no uidValidity (first sync)', () => {
    const stored = storedStatus();
    delete stored.uidValidity;
    assert.equal(hasUidValidityChanged(stored, mailboxStatus({ uidValidity: 123n })), false);
});

test('hasUidValidityChanged returns false when values match', () => {
    assert.equal(hasUidValidityChanged(storedStatus({ uidValidity: 123n }), mailboxStatus({ uidValidity: 123n })), false);
});

test('hasUidValidityChanged returns true when values differ', () => {
    assert.equal(hasUidValidityChanged(storedStatus({ uidValidity: 123n }), mailboxStatus({ uidValidity: 124n })), true);
});

test('hasNoModseqChanges returns false when stored modseq is missing', () => {
    assert.equal(hasNoModseqChanges(storedStatus(), mailboxStatus({ highestModseq: 10n })), false);
});

test('hasNoModseqChanges returns true when stored and mailbox modseq are equal', () => {
    assert.equal(hasNoModseqChanges(storedStatus({ highestModseq: 10n }), mailboxStatus({ highestModseq: 10n })), true);
});

test('hasNoModseqChanges returns false when modseqs differ', () => {
    assert.equal(hasNoModseqChanges(storedStatus({ highestModseq: 10n }), mailboxStatus({ highestModseq: 11n })), false);
});

test('canUseCondstorePartialSync returns false when CONDSTORE is not enabled', () => {
    const imapClient = { enabled: new Set() };
    const stored = storedStatus({ highestModseq: 10n, messages: 5, uidNext: 6 });
    const mailbox = mailboxStatus({ highestModseq: 11n, messages: 6, uidNext: 7 });
    assert.equal(canUseCondstorePartialSync(imapClient, stored, mailbox), false);
});

test('canUseCondstorePartialSync returns true for CONDSTORE additions-only deltas', () => {
    const imapClient = { enabled: new Set(['CONDSTORE']) };
    const stored = storedStatus({ highestModseq: 10n, messages: 5, uidNext: 6 });
    const mailbox = mailboxStatus({ highestModseq: 11n, messages: 6, uidNext: 7 });
    assert.equal(canUseCondstorePartialSync(imapClient, stored, mailbox), true);
});

test('canUseCondstorePartialSync returns false when uidNext and messages deltas disagree (implied deletion)', () => {
    const imapClient = { enabled: new Set(['CONDSTORE']) };
    // uidNext jumped by 2 but messages only grew by 1 => something was deleted
    const stored = storedStatus({ highestModseq: 10n, messages: 5, uidNext: 6 });
    const mailbox = mailboxStatus({ highestModseq: 11n, messages: 6, uidNext: 8 });
    assert.equal(canUseCondstorePartialSync(imapClient, stored, mailbox), false);
});

test('canUseSimplePartialSync returns true for pure additions', () => {
    const stored = storedStatus({ messages: 10, uidNext: 101 });
    const mailbox = mailboxStatus({ messages: 12, uidNext: 103 });
    assert.equal(canUseSimplePartialSync(stored, mailbox), true);
});

test('canUseSimplePartialSync returns false when message count is unchanged', () => {
    const stored = storedStatus({ messages: 10, uidNext: 101 });
    const mailbox = mailboxStatus({ messages: 10, uidNext: 101 });
    assert.equal(canUseSimplePartialSync(stored, mailbox), false);
});

test('canUseSimplePartialSync returns false when deltas imply a deletion', () => {
    const stored = storedStatus({ messages: 10, uidNext: 101 });
    // one added, one deleted: uidNext +1, messages +0
    const mailbox = mailboxStatus({ messages: 10, uidNext: 102 });
    assert.equal(canUseSimplePartialSync(stored, mailbox), false);
});

test('canSkipSync returns true when counts match and a recent full sync is recorded', () => {
    const stored = storedStatus({ messages: 10, uidNext: 101, lastFullSync: new Date() });
    const mailbox = mailboxStatus({ messages: 10, uidNext: 101 });
    assert.equal(canSkipSync(stored, mailbox), true);
});

test('canSkipSync returns false when the last full sync has expired', () => {
    const stored = storedStatus({
        messages: 10,
        uidNext: 101,
        lastFullSync: new Date(Date.now() - (FULL_SYNC_DELAY + 60 * 1000))
    });
    const mailbox = mailboxStatus({ messages: 10, uidNext: 101 });
    assert.equal(canSkipSync(stored, mailbox), false);
});

test('canSkipSync returns false when server counts differ from stored', () => {
    const stored = storedStatus({ messages: 10, uidNext: 101, lastFullSync: new Date() });
    const mailbox = mailboxStatus({ messages: 11, uidNext: 102 });
    assert.equal(canSkipSync(stored, mailbox), false);
});

test('isRecentFullSync handles missing and expired timestamps', () => {
    assert.equal(isRecentFullSync(storedStatus()), false);
    assert.equal(isRecentFullSync(storedStatus({ lastFullSync: new Date(Date.now() - (FULL_SYNC_DELAY + 60 * 1000)) })), false);
    assert.equal(isRecentFullSync(storedStatus({ lastFullSync: new Date() })), true);
});

test('getFetchRange yields initial batch, advances, and terminates', () => {
    const total = FETCH_BATCH_SIZE * 2 + 5;
    const first = getFetchRange(total, false);
    assert.equal(first, `1:${FETCH_BATCH_SIZE}`);

    const second = getFetchRange(total, first);
    assert.equal(second, `${FETCH_BATCH_SIZE + 1}:${FETCH_BATCH_SIZE * 2}`);

    // Third batch has fewer than FETCH_BATCH_SIZE messages remaining, so the
    // tail marker becomes '*' to fetch to the end.
    const third = getFetchRange(total, second);
    assert.equal(third, `${FETCH_BATCH_SIZE * 2 + 1}:*`);

    // After a '*' tail we must stop.
    assert.equal(getFetchRange(total, third), false);
});

test('getFetchRange returns false when the mailbox has fewer messages than already fetched', () => {
    assert.equal(getFetchRange(0, false), false);
});
