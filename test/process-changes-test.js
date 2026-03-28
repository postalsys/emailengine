'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Mock the db module before any other imports to prevent real Redis/BullMQ
// connections from being created.
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

const mockRedis = createMockRedis();

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
const { MESSAGE_UPDATED_NOTIFY } = require('../lib/consts');

function createMockContext(overrides) {
    let markUpdatedCalled = false;
    let notifyCalls = [];
    let warnCalls = [];

    let ctx = {
        path: 'INBOX',
        logger: {
            trace: () => {},
            debug: () => {},
            info: () => {},
            warn: (...args) => {
                warnCalls.push(args);
            },
            error: () => {},
            fatal: () => {}
        },
        connection: {
            account: 'test-account',
            packUid: async (mailbox, uid) => `packed-${uid}`,
            notify: async (mailbox, event, data) => {
                notifyCalls.push({ event, data });
            },
            redis: mockRedis,
            getAccountKey: () => 'iam:test-account'
        },
        packUidWithLogging: Mailbox.prototype.packUidWithLogging,
        markUpdated: async function () {
            markUpdatedCalled = true;
        },
        get _markUpdatedCalled() {
            return markUpdatedCalled;
        },
        get _notifyCalls() {
            return notifyCalls;
        },
        get _warnCalls() {
            return warnCalls;
        }
    };

    if (overrides) {
        if (overrides.connection) {
            ctx.connection = Object.assign({}, ctx.connection, overrides.connection);
        }
        if (overrides.logger) {
            ctx.logger = overrides.logger;
        }
        if (overrides.markUpdated) {
            ctx.markUpdated = overrides.markUpdated;
        }
        if (overrides.packUidWithLogging) {
            ctx.packUidWithLogging = overrides.packUidWithLogging;
        }
    }

    return ctx;
}

test('Mailbox processChanges', async t => {
    await t.test('calls notify with correct event and payload, then calls markUpdated', async () => {
        let ctx = createMockContext();
        let changes = { flags: { added: ['\\Seen'] } };

        await Mailbox.prototype.processChanges.call(ctx, { uid: 42 }, changes);

        assert.strictEqual(ctx._notifyCalls.length, 1, 'notify should be called once');
        assert.strictEqual(ctx._notifyCalls[0].event, MESSAGE_UPDATED_NOTIFY);
        assert.strictEqual(ctx._notifyCalls[0].data.id, 'packed-42');
        assert.strictEqual(ctx._notifyCalls[0].data.uid, 42);
        assert.deepStrictEqual(ctx._notifyCalls[0].data.changes, changes);
        assert.ok(ctx._markUpdatedCalled, 'markUpdated should be called after notify');
    });

    await t.test('returns early when packUidWithLogging returns null', async () => {
        let ctx = createMockContext({
            connection: {
                packUid: async () => null,
                notify: async () => {
                    throw new Error('notify should not be called');
                }
            }
        });

        await Mailbox.prototype.processChanges.call(ctx, { uid: 99 }, { flags: {} });

        assert.ok(!ctx._markUpdatedCalled, 'markUpdated should not be called');
    });

    await t.test('propagates error when notify throws, skipping markUpdated', async () => {
        let markUpdatedCalled = false;
        let ctx = createMockContext({
            connection: {
                packUid: async (mailbox, uid) => `packed-${uid}`,
                notify: async () => {
                    throw new Error('Redis connection lost');
                }
            },
            markUpdated: async () => {
                markUpdatedCalled = true;
            }
        });

        await assert.rejects(
            async () => {
                await Mailbox.prototype.processChanges.call(ctx, { uid: 10 }, { flags: {} });
            },
            err => {
                assert.strictEqual(err.message, 'Redis connection lost');
                return true;
            }
        );

        assert.ok(!markUpdatedCalled, 'markUpdated must not be called when notify throws');
    });

    await t.test('logs warning when packUid returns null', async () => {
        let ctx = createMockContext({
            connection: {
                packUid: async () => null,
                notify: async () => {}
            }
        });

        await Mailbox.prototype.processChanges.call(ctx, { uid: 77 }, {});

        assert.ok(ctx._warnCalls.length > 0, 'should have logged a warning');
        let warnMsg = ctx._warnCalls[0][0];
        assert.ok(warnMsg.msg && warnMsg.msg.includes('packUid returned invalid'), 'warning should mention packUid failure');
        assert.strictEqual(warnMsg.uid, 77, 'warning should include the UID');
        assert.strictEqual(warnMsg.path, 'INBOX', 'warning should include the mailbox path');
    });
});
