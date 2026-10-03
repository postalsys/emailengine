'use strict';

// Unit coverage for the "Run sync" (PUT /v1/account/{account}/sync) catch-up implemented
// for API accounts. Gmail and Outlook previously inherited the base no-op syncMailboxes();
// these tests verify the new per-provider overrides trigger a real catch-up, which for Outlook
// is a stored missed-message recovery request.

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
        subscribe: async () => {},
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
        exportQueue: mockQueue,
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { createMockLogger } = require('./helpers/mock-logger');

const GMAIL_READ_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
const GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';

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
    await t.test('refreshes folder cache and queues a missed-message recovery', async () => {
        let folderRefreshed = false;
        let queued = 0;
        let recovered = 0;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            accountObject: { queueMissedRecovery: async () => queued++ },
            renewMailboxFolderCache: async () => {
                folderRefreshed = true;
            },
            recoverMissedNotifications: () => recovered++
        };

        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.ok(folderRefreshed, 'folder cache should be refreshed');
        assert.strictEqual(queued, 1, 'the recovery request is stored, so it is retried when it fails');
        assert.strictEqual(recovered, 1, 'and picked up right away');
    });

    await t.test('queues a manual recovery, carrying how far back to look when asked', async () => {
        const queued = [];
        const ctx = {
            closed: false,
            logger: createMockLogger(),
            accountObject: { queueMissedRecovery: async opts => queued.push(opts) },
            renewMailboxFolderCache: async () => {},
            recoverMissedNotifications: () => true
        };
        const since = Date.now() - 24 * 60 * 60 * 1000;

        await OutlookClient.prototype.syncMailboxes.call(ctx);
        await OutlookClient.prototype.syncMailboxes.call(ctx, { since });

        assert.deepStrictEqual(queued, [
            { reason: 'manual', since: undefined },
            { reason: 'manual', since }
        ]);
    });

    await t.test('continues to recovery even if folder cache refresh throws', async () => {
        let queued = 0;
        let ctx = {
            closed: false,
            logger: createMockLogger(),
            accountObject: { queueMissedRecovery: async () => queued++ },
            renewMailboxFolderCache: async () => {
                throw new Error('graph down');
            },
            recoverMissedNotifications: () => true
        };

        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);

        assert.strictEqual(result, true);
        assert.strictEqual(queued, 1, 'recovery should still be queued after a folder refresh failure');
    });

    await t.test('returns null when the client is closed', async () => {
        let ctx = { closed: true };
        let result = await OutlookClient.prototype.syncMailboxes.call(ctx);
        assert.strictEqual(result, null);
    });
});
