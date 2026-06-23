'use strict';

// Unit coverage for the "Run sync" (PUT /v1/account/{account}/sync) catch-up implemented
// for API accounts. Gmail and Outlook previously inherited the base no-op syncMailboxes();
// these tests verify the new per-provider overrides trigger a real catch-up and that the
// Outlook missed-message recovery can bypass its cooldown for a manual sync.

const test = require('node:test');
const assert = require('node:assert').strict;

// Mock the db module before importing the clients so no real Redis/BullMQ connections open.
const mockQueue = { add: async () => ({}), close: async () => {}, on: () => {}, off: () => {} };
function createMockRedis() {
    return {
        status: 'ready',
        hget: async () => null,
        hset: async () => {},
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async () => ({}),
        multi: () => ({ exec: async () => [] }),
        get: async () => null,
        set: async () => 'OK',
        del: async () => 1,
        exists: async () => 0,
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate() {
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

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');

const GMAIL_READ_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
const GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';

function createMockLogger() {
    let logger = {};
    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = () => {};
    }
    return logger;
}

test('Run sync for Gmail accounts', async t => {
    await t.test('triggers a history catch-up when new history exists', async () => {
        let triggered = [];
        let requested = false;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            getAccountKey: () => 'iad:gmail1',
            accountObject: { loadAccountData: async () => ({ oauth2: { scope: [GMAIL_READ_SCOPE] }, googleHistoryId: '3000' }) },
            request: async () => {
                requested = true;
                return { historyId: '5000' };
            },
            redis: createMockRedis(),
            triggerSync: (from, to) => triggered.push([from, to])
        };

        let result = await GmailClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.ok(requested, 'profile should be fetched');
        assert.deepStrictEqual(triggered, [[3000, 5000]], 'triggerSync should run from stored to current historyId');
    });

    await t.test('does not trigger when there is nothing new', async () => {
        let triggered = [];
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            getAccountKey: () => 'iad:gmail2',
            accountObject: { loadAccountData: async () => ({ oauth2: { scope: [GMAIL_READ_SCOPE] }, googleHistoryId: '5000' }) },
            request: async () => ({ historyId: '5000' }),
            redis: createMockRedis(),
            triggerSync: (from, to) => triggered.push([from, to])
        };

        let result = await GmailClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.deepStrictEqual(triggered, [], 'no sync when current equals stored historyId');
    });

    await t.test('is a no-op for send-only accounts', async () => {
        let triggered = [];
        let requested = false;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            getAccountKey: () => 'iad:gmail3',
            accountObject: { loadAccountData: async () => ({ oauth2: { scope: [GMAIL_SEND_SCOPE] } }) },
            request: async () => {
                requested = true;
                return { historyId: '5000' };
            },
            redis: mockRedis,
            triggerSync: (from, to) => triggered.push([from, to])
        };

        let result = await GmailClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, null, 'send-only account returns without syncing');
        assert.strictEqual(requested, false, 'profile must not be fetched for send-only');
        assert.deepStrictEqual(triggered, []);
    });

    await t.test('returns null when the client is closed', async () => {
        let triggered = [];
        let ctx = { closed: true, triggerSync: (from, to) => triggered.push([from, to]) };
        let result = await GmailClient.prototype.syncMailboxes.call(ctx);
        assert.strictEqual(result, null);
        assert.deepStrictEqual(triggered, []);
    });
});

test('Run sync for Outlook accounts', async t => {
    await t.test('refreshes folder cache and forces missed-message recovery', async () => {
        let folderRefreshed = false;
        let missedOpts;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            renewMailboxFolderCache: async () => {
                folderRefreshed = true;
            },
            syncMissedMessages: async opts => {
                missedOpts = opts;
                return true;
            }
        };

        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.ok(folderRefreshed, 'folder cache should be refreshed');
        assert.deepStrictEqual(missedOpts, { force: true }, 'missed recovery should be forced for a manual sync');
    });

    await t.test('continues to recovery even if folder cache refresh throws', async () => {
        let missedCalled = false;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            renewMailboxFolderCache: async () => {
                throw new Error('graph down');
            },
            syncMissedMessages: async () => {
                missedCalled = true;
                return true;
            }
        };

        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.ok(missedCalled, 'recovery should still run after a folder refresh failure');
    });

    await t.test('returns null when the client is closed', async () => {
        let ctx = { closed: true };
        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);
        assert.strictEqual(result, null);
    });
});

test('Outlook syncMissedMessages cooldown handling', async t => {
    await t.test('respects the cooldown when not forced', async () => {
        let setCalled = false;
        let ctx = {
            account: 'o1',
            logger: createMockLogger(),
            getAccountKey: () => 'iad:o1',
            redis: Object.assign(createMockRedis(), {
                set: async () => {
                    setCalled = true;
                    return null; // NX fails -> cooldown active
                }
            })
        };

        let result = await OutlookClient.prototype.syncMissedMessages.call(ctx);

        assert.strictEqual(result, false, 'should skip when cooldown is active');
        assert.ok(setCalled, 'cooldown key should be checked when not forced');
    });

    await t.test('bypasses the cooldown when forced', async () => {
        let setCalled = false;
        let requestCalled = false;
        let ctx = {
            account: 'o2',
            logger: createMockLogger(),
            getAccountKey: () => 'iad:o2',
            oauth2UserPath: 'me',
            redis: Object.assign(createMockRedis(), {
                set: async () => {
                    setCalled = true;
                    return 'OK';
                },
                hget: async () => null,
                del: async () => 1
            }),
            request: async () => {
                // Proves we proceeded past the cooldown gate; throwing exercises the
                // graceful error path (caught, returns false).
                requestCalled = true;
                throw new Error('graph query failed');
            }
        };

        let result = await OutlookClient.prototype.syncMissedMessages.call(ctx, { force: true });

        assert.strictEqual(result, false);
        assert.strictEqual(setCalled, false, 'cooldown key must not be acquired when forced');
        assert.ok(requestCalled, 'forced run should proceed to query messages');
    });
});
