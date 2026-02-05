'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Mock the db module before any other imports to prevent real Redis/BullMQ
// connections from being created. The imap-client module and its dependencies
// import db at the module level, which would open persistent connections that
// keep the test process alive.
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
        // ioredfour Lock calls defineCommand() to register Lua scripts
        defineCommand: () => {},
        // ioredfour Lock calls redis.duplicate() to create a subscriber connection.
        // Return a mock to prevent real Redis connections.
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

// Now safe to import IMAPClient without opening real connections
const { IMAPClient } = require('../lib/email-client/imap-client');

function createMockLogger() {
    let calls = [];
    let logger = {};
    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = (...args) => {
            calls.push({ level, args });
        };
    }
    return { logger, calls };
}

function createMockImapClient(overrides) {
    return {
        usable: true,
        mailbox: { path: 'INBOX' },
        idling: false,
        close: () => {},
        idle: async () => {},
        list: async () => [{ path: 'INBOX', delimiter: '/' }],
        append: async () => ({ uid: 1, path: 'INBOX' }),
        ...overrides
    };
}

function createMockMailbox(name, syncFn) {
    return {
        path: name,
        sync: syncFn || (async () => {})
    };
}

function createBaseUploadCtx(overrides) {
    return {
        isClosing: false,
        isClosed: false,
        state: 'connected',
        syncing: false,
        checkIMAPConnection: IMAPClient.prototype.checkIMAPConnection,
        prepareRawMessage: async () => ({
            raw: Buffer.from('test message'),
            messageId: '<test@example.com>',
            documentStoreUsed: false,
            referencedMessage: null
        }),
        packUid: async () => 'encodedId',
        onTaskCompleted: () => {},
        ...overrides
    };
}

test('IMAP null guard tests', async t => {
    await t.test('syncMailboxes() returns early when imapClient becomes null during loop', async () => {
        let { logger } = createMockLogger();
        let syncedMailboxes = [];

        let mailbox1 = createMockMailbox('INBOX', async () => {
            syncedMailboxes.push('INBOX');
        });
        let mailbox2 = createMockMailbox('Sent', async () => {
            syncedMailboxes.push('Sent');
        });
        let mailbox3 = createMockMailbox('Drafts', async () => {
            syncedMailboxes.push('Drafts');
        });

        let mailboxes = new Map();
        mailboxes.set('inbox', mailbox1);
        mailboxes.set('sent', mailbox2);
        mailboxes.set('drafts', mailbox3);

        // Context simulating an IMAPClient with a connection that drops
        // after the first mailbox sync
        let ctx = {
            logger,
            imapClient: createMockImapClient(),
            mailboxes,
            untaggedExpungeTimer: null,
            resyncTimer: null,
            completedTimer: null,
            state: 'connected',
            syncing: false,
            refreshFolderList: async () => {
                // Return null so all mailboxes enter the sync branch
                return null;
            },
            setStateVal: async () => {},
            getAccountKey: () => 'test:account',
            redis: mockRedis,
            isConnected: () => !!ctx.imapClient && ctx.imapClient.usable
        };

        // After INBOX syncs, null out the imapClient to simulate disconnection
        mailbox1.sync = async () => {
            syncedMailboxes.push('INBOX');
            ctx.imapClient = null;
        };

        await IMAPClient.prototype.syncMailboxes.call(ctx);

        // Only INBOX should have been synced before the guard triggered
        assert.ok(syncedMailboxes.includes('INBOX'), 'INBOX should have been synced');
        assert.ok(!syncedMailboxes.includes('Sent'), 'Sent should not have been synced after disconnect');
        assert.ok(!syncedMailboxes.includes('Drafts'), 'Drafts should not have been synced after disconnect');
    });

    await t.test('syncMailboxes() returns early when imapClient.usable becomes false during loop', async () => {
        let { logger } = createMockLogger();
        let syncedMailboxes = [];

        let mailbox1 = createMockMailbox('INBOX');
        let mailbox2 = createMockMailbox('Sent');

        let mailboxes = new Map();
        mailboxes.set('inbox', mailbox1);
        mailboxes.set('sent', mailbox2);

        let mockImapClient = createMockImapClient();

        let ctx = {
            logger,
            imapClient: mockImapClient,
            mailboxes,
            untaggedExpungeTimer: null,
            resyncTimer: null,
            completedTimer: null,
            state: 'connected',
            syncing: false,
            refreshFolderList: async () => null,
            setStateVal: async () => {},
            getAccountKey: () => 'test:account',
            redis: mockRedis,
            isConnected: () => !!ctx.imapClient && ctx.imapClient.usable
        };

        mailbox1.sync = async () => {
            syncedMailboxes.push('INBOX');
            // Mark unusable instead of nulling
            mockImapClient.usable = false;
        };
        mailbox2.sync = async () => {
            syncedMailboxes.push('Sent');
        };

        await IMAPClient.prototype.syncMailboxes.call(ctx);

        assert.ok(syncedMailboxes.includes('INBOX'), 'INBOX should have been synced');
        assert.ok(!syncedMailboxes.includes('Sent'), 'Sent should not have been synced after usable=false');
    });

    await t.test('syncMailboxes() completes normally when imapClient stays connected', async () => {
        let { logger } = createMockLogger();
        let syncedMailboxes = [];

        let mailbox1 = createMockMailbox('INBOX', async () => syncedMailboxes.push('INBOX'));
        let mailbox2 = createMockMailbox('Sent', async () => syncedMailboxes.push('Sent'));

        let mailboxes = new Map();
        mailboxes.set('inbox', mailbox1);
        mailboxes.set('sent', mailbox2);

        let ctx = {
            logger,
            imapClient: createMockImapClient({
                rawCapabilities: [],
                authCapabilities: new Map(),
                serverInfo: {}
            }),
            mailboxes,
            mailbox: { path: 'INBOX' },
            main: { path: 'INBOX' },
            untaggedExpungeTimer: null,
            resyncTimer: null,
            completedTimer: null,
            state: 'syncing',
            syncing: false,
            account: 'test-account',
            refreshFolderList: async () => null,
            setStateVal: async () => {},
            getAccountKey: () => 'test:account',
            redis: mockRedis,
            isConnected: () => !!ctx.imapClient && ctx.imapClient.usable
        };

        await IMAPClient.prototype.syncMailboxes.call(ctx);

        assert.deepStrictEqual(syncedMailboxes, ['INBOX', 'Sent'], 'All mailboxes should have been synced');
        assert.strictEqual(ctx.state, 'connected', 'State should be connected after successful sync');
    });

    await t.test('getCurrentListing() does not crash when imapClient is null and getImapConnection returns null', async () => {
        let { logger } = createMockLogger();

        let ctx = {
            logger,
            imapClient: null,
            isClosing: false,
            isClosed: false,
            isConnected: () => false,
            checkIMAPConnection: IMAPClient.prototype.checkIMAPConnection,
            getImapConnection: async () => null
        };

        await assert.rejects(
            async () => {
                await IMAPClient.prototype.getCurrentListing.call(ctx, {}, { allowSecondary: true });
            },
            err => {
                assert.strictEqual(err.code, 'ConnectionError');
                assert.strictEqual(err.message, 'Failed to get connection');
                return true;
            }
        );
    });

    await t.test('getCurrentListing() calls close() when imapClient exists and getImapConnection returns null', async () => {
        let { logger } = createMockLogger();
        let closeCalled = false;

        let ctx = {
            logger,
            imapClient: createMockImapClient({
                close: () => {
                    closeCalled = true;
                }
            }),
            isClosing: false,
            isClosed: false,
            isConnected: () => true,
            checkIMAPConnection: IMAPClient.prototype.checkIMAPConnection,
            getImapConnection: async () => null
        };

        await assert.rejects(
            async () => {
                await IMAPClient.prototype.getCurrentListing.call(ctx, {}, { allowSecondary: true });
            },
            err => {
                assert.strictEqual(err.code, 'ConnectionError');
                return true;
            }
        );

        assert.ok(closeCalled, 'close() should have been called on the existing imapClient');
    });

    await t.test('getCurrentListing() does not crash when imapClient becomes null and listing is empty', async () => {
        let { logger } = createMockLogger();

        let mockConnectionClient = createMockImapClient({
            list: async () => [] // empty listing triggers close path
        });

        let ctx = {
            logger,
            imapClient: null, // already null when empty listing triggers close
            isClosing: false,
            isClosed: false,
            isConnected: () => false,
            checkIMAPConnection: IMAPClient.prototype.checkIMAPConnection,
            getImapConnection: async () => mockConnectionClient,
            accountObject: {
                loadAccountData: async () => ({ imap: {} })
            }
        };

        await assert.rejects(
            async () => {
                await IMAPClient.prototype.getCurrentListing.call(ctx, {}, { allowSecondary: true });
            },
            err => {
                assert.strictEqual(err.code, 'ServerBug');
                assert.strictEqual(err.message, 'Server bug: empty mailbox listing');
                return true;
            }
        );
    });

    await t.test('getCurrentListing() closes imapClient on empty listing when imapClient exists', async () => {
        let { logger } = createMockLogger();
        let closeCalled = false;

        let mockConnectionClient = createMockImapClient({
            list: async () => []
        });

        let ctx = {
            logger,
            imapClient: createMockImapClient({
                close: () => {
                    closeCalled = true;
                }
            }),
            isClosing: false,
            isClosed: false,
            isConnected: () => true,
            checkIMAPConnection: IMAPClient.prototype.checkIMAPConnection,
            getImapConnection: async () => mockConnectionClient,
            accountObject: {
                loadAccountData: async () => ({ imap: {} })
            }
        };

        await assert.rejects(
            async () => {
                await IMAPClient.prototype.getCurrentListing.call(ctx, {}, { allowSecondary: true });
            },
            err => {
                assert.strictEqual(err.code, 'ServerBug');
                return true;
            }
        );

        assert.ok(closeCalled, 'close() should have been called on existing imapClient');
    });

    await t.test('uploadMessage() does not crash when imapClient becomes null after append', async () => {
        let { logger } = createMockLogger();
        let idleCalled = false;

        let mockConnectionClient = createMockImapClient({
            append: async () => ({ uid: 42, path: 'INBOX' })
        });

        let ctx = createBaseUploadCtx({
            logger,
            imapClient: null,
            isConnected: () => false,
            getImapConnection: async () => mockConnectionClient
        });

        let result = await IMAPClient.prototype.uploadMessage.call(ctx, { path: 'INBOX', flags: [], raw: Buffer.from('test') }, { allowSecondary: true });

        assert.ok(result, 'Should return a result');
        assert.strictEqual(result.uid, 42, 'Should include UID from append response');
        assert.ok(!idleCalled, 'IDLE should not have been called when imapClient is null');
    });

    await t.test('uploadMessage() enters IDLE when imapClient is the same as connectionClient', async () => {
        let { logger } = createMockLogger();
        let idleCalled = false;

        let mockImapClient = createMockImapClient({
            append: async () => ({ uid: 42, path: 'INBOX' }),
            idle: async () => {
                idleCalled = true;
            },
            idling: false,
            mailbox: { path: 'INBOX' }
        });

        let ctx = createBaseUploadCtx({
            logger,
            imapClient: mockImapClient,
            isConnected: () => true,
            getImapConnection: async () => mockImapClient
        });

        let result = await IMAPClient.prototype.uploadMessage.call(ctx, { path: 'INBOX', flags: [], raw: Buffer.from('test') }, { allowSecondary: true });

        assert.ok(result, 'Should return a result');
        assert.strictEqual(result.uid, 42);
        assert.ok(idleCalled, 'IDLE should have been called when connectionClient === imapClient');
    });

    await t.test('uploadMessage() skips IDLE when connectionClient differs from imapClient', async () => {
        let { logger } = createMockLogger();
        let idleCalled = false;

        let mockImapClient = createMockImapClient({
            idle: async () => {
                idleCalled = true;
            }
        });

        let differentConnectionClient = createMockImapClient({
            append: async () => ({ uid: 99, path: 'Sent' })
        });

        let ctx = createBaseUploadCtx({
            logger,
            imapClient: mockImapClient,
            isConnected: () => true,
            getImapConnection: async () => differentConnectionClient
        });

        let result = await IMAPClient.prototype.uploadMessage.call(ctx, { path: 'Sent', flags: [], raw: Buffer.from('test') }, { allowSecondary: true });

        assert.ok(result, 'Should return a result');
        assert.strictEqual(result.uid, 99);
        assert.ok(!idleCalled, 'IDLE should not be called when connectionClient !== imapClient');
    });
});
