'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Prevent real Redis / BullMQ connections the moment Mailbox is required.
// Mirrors the pattern in test/process-changes-test.js.
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

function createCtx({ stored, mailbox }) {
    return {
        getStoredStatus: async () => stored,
        getMailboxStatus: () => mailbox
    };
}

test('shouldRunPartialSyncAfterExists triggers when uidNext differs while counts are equal', async () => {
    const ctx = createCtx({
        stored: { messages: 10, uidNext: 101, highestModseq: 50n },
        // A message arrived then another was expunged: net count unchanged,
        // but uidNext advanced on the server.
        mailbox: { messages: 10, uidNext: 102, highestModseq: 50n }
    });
    assert.equal(await Mailbox.prototype.shouldRunPartialSyncAfterExists.call(ctx), true);
});

test('shouldRunPartialSyncAfterExists triggers when highestModseq differs while counts are equal', async () => {
    const ctx = createCtx({
        stored: { messages: 10, uidNext: 101, highestModseq: 50n },
        // Flag update on an existing message: count and uidNext unchanged, modseq advances.
        mailbox: { messages: 10, uidNext: 101, highestModseq: 51n }
    });
    assert.equal(await Mailbox.prototype.shouldRunPartialSyncAfterExists.call(ctx), true);
});

test('shouldRunPartialSyncAfterExists does not trigger when all three fields agree', async () => {
    const ctx = createCtx({
        stored: { messages: 10, uidNext: 101, highestModseq: 50n },
        mailbox: { messages: 10, uidNext: 101, highestModseq: 50n }
    });
    assert.equal(await Mailbox.prototype.shouldRunPartialSyncAfterExists.call(ctx), false);
});

test('shouldRunPartialSyncAfterExists triggers when message count differs (original behavior preserved)', async () => {
    const ctx = createCtx({
        stored: { messages: 10, uidNext: 101, highestModseq: 50n },
        mailbox: { messages: 11, uidNext: 102, highestModseq: 51n }
    });
    assert.equal(await Mailbox.prototype.shouldRunPartialSyncAfterExists.call(ctx), true);
});

test('shouldRunPartialSyncAfterExists triggers on first sync (stored state is empty / false)', async () => {
    const ctx = createCtx({
        // First-time sync: getStoredStatus returns false for all numeric fields.
        stored: { messages: false, uidNext: false, highestModseq: false },
        mailbox: { messages: 5, uidNext: 6, highestModseq: 10n }
    });
    assert.equal(await Mailbox.prototype.shouldRunPartialSyncAfterExists.call(ctx), true);
});
