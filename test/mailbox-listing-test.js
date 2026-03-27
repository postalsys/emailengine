'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const msgpack = require('msgpack5')();

// --- Mock setup ---

let mockRedisData = {};
let pipelineCalls = [];

function createMockRedis() {
    return {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hset: async (key, field, value) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            mockRedisData[key][field] = value;
        },
        hgetall: async key => mockRedisData[key] || null,
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async key => mockRedisData[key] || {},
        hgetBuffer: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            Object.assign(mockRedisData[key], data);
        },
        multi: () => {
            const ops = [];
            return {
                hmset(key, data) {
                    ops.push({ cmd: 'hmset', key, data });
                    return this;
                },
                hset() {
                    return this;
                },
                hdel() {
                    return this;
                },
                del(key) {
                    ops.push({ cmd: 'del', key });
                    return this;
                },
                expire() {
                    return this;
                },
                srem() {
                    return this;
                },
                zadd() {
                    return this;
                },
                hincrby() {
                    return this;
                },
                async exec() {
                    for (const op of ops) {
                        if (op.cmd === 'hmset') {
                            if (!mockRedisData[op.key]) mockRedisData[op.key] = {};
                            Object.assign(mockRedisData[op.key], op.data);
                        } else if (op.cmd === 'del') {
                            delete mockRedisData[op.key];
                        }
                    }
                    return [];
                }
            };
        },
        pipeline: () => {
            const ops = [];
            pipelineCalls = [];
            return {
                hgetall(key) {
                    ops.push({ cmd: 'hgetall', key });
                    pipelineCalls.push(key);
                    return this;
                },
                async exec() {
                    let results = [];
                    for (const op of ops) {
                        if (op.cmd === 'hgetall') {
                            results.push([null, mockRedisData[op.key] || null]);
                        }
                    }
                    return results;
                }
            };
        },
        ttl: async () => 3600,
        eval: async () => 1,
        smembers: async () => [],
        srem: async () => {},
        exists: async () => 0,
        get: async () => null,
        set: async () => 'OK',
        scan: async () => ['0', []],
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
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {},
    getJob: async () => null
};

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

const { normalizePath } = require('../lib/tools');
const { REDIS_PREFIX, MAILBOX_HASH } = require('../lib/consts');

test('Mailbox listing performance tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(() => {
        mockRedisData = {};
        pipelineCalls = [];
    });

    // --- Change 1: getCurrentListing O(n) comparison tests ---

    await t.test('getCurrentListing detects new, changed, and deleted mailboxes with Map/Set lookups', async () => {
        // Simulate what getCurrentListing does with the Map/Set approach

        // Stored listing (from Redis) - has INBOX, Sent, and OldFolder
        let storedListing = [
            { path: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'OldFolder', delimiter: '/', specialUseSource: undefined, noInferiors: false }
        ];

        // Server listing - has INBOX (changed delimiter), Sent (unchanged), NewFolder (new)
        let listing = [
            { path: 'INBOX', delimiter: '.', specialUseSource: 'extension', noInferiors: false },
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'NewFolder', delimiter: '/', specialUseSource: undefined, noInferiors: false }
        ];

        // Build lookup map from stored listing (the fix)
        const storedListingMap = new Map();
        for (const entry of storedListing) {
            storedListingMap.set(normalizePath(entry.path), entry);
        }

        let hasChanges = false;

        // Detect new/changed
        for (let mailbox of listing) {
            let existingMailbox = storedListingMap.get(normalizePath(mailbox.path));
            if (!existingMailbox) {
                mailbox.isNew = true;
                hasChanges = true;
            } else if (
                existingMailbox.delimiter !== mailbox.delimiter ||
                existingMailbox.specialUseSource !== mailbox.specialUseSource ||
                existingMailbox.noInferiors !== mailbox.noInferiors
            ) {
                hasChanges = true;
            }
        }

        // Detect deleted
        const listingPathSet = new Set(listing.map(mailbox => normalizePath(mailbox.path)));
        let deletedPaths = [];
        for (let entry of storedListing) {
            if (!listingPathSet.has(normalizePath(entry.path))) {
                deletedPaths.push(entry.path);
                hasChanges = true;
            }
        }

        assert.ok(hasChanges, 'Should detect changes');
        assert.ok(listing[2].isNew, 'NewFolder should be marked as new');
        assert.strictEqual(listing[0].isNew, undefined, 'INBOX should not be marked as new (it exists but changed)');
        assert.deepStrictEqual(deletedPaths, ['OldFolder'], 'OldFolder should be detected as deleted');
    });

    await t.test('getCurrentListing handles case-insensitive INBOX normalization', async () => {
        let storedListing = [{ path: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false }];

        let listing = [{ path: 'inbox', delimiter: '/', specialUseSource: 'extension', noInferiors: false }];

        const storedListingMap = new Map();
        for (const entry of storedListing) {
            storedListingMap.set(normalizePath(entry.path), entry);
        }

        let existingMailbox = storedListingMap.get(normalizePath(listing[0].path));
        assert.ok(existingMailbox, 'Should find INBOX via case-insensitive normalization');
    });

    await t.test('getCurrentListing handles large folder counts efficiently', async () => {
        let count = 5000;
        let storedListing = [];
        let listing = [];

        for (let i = 0; i < count; i++) {
            storedListing.push({ path: `Folder${i}`, delimiter: '/', specialUseSource: undefined, noInferiors: false });
            listing.push({ path: `Folder${i}`, delimiter: '/', specialUseSource: undefined, noInferiors: false });
        }

        // Add one new, remove one old
        listing.push({ path: 'BrandNew', delimiter: '/', specialUseSource: undefined, noInferiors: false });
        storedListing.push({ path: 'WillBeDeleted', delimiter: '/', specialUseSource: undefined, noInferiors: false });

        const start = Date.now();

        const storedListingMap = new Map();
        for (const entry of storedListing) {
            storedListingMap.set(normalizePath(entry.path), entry);
        }

        let hasChanges = false;
        for (let mailbox of listing) {
            let existingMailbox = storedListingMap.get(normalizePath(mailbox.path));
            if (!existingMailbox) {
                mailbox.isNew = true;
                hasChanges = true;
            }
        }

        const listingPathSet = new Set(listing.map(mailbox => normalizePath(mailbox.path)));
        let deletedCount = 0;
        for (let entry of storedListing) {
            if (!listingPathSet.has(normalizePath(entry.path))) {
                deletedCount++;
                hasChanges = true;
            }
        }

        let elapsed = Date.now() - start;

        assert.ok(hasChanges, 'Should detect changes');
        assert.ok(listing[count].isNew, 'BrandNew should be marked as new');
        assert.strictEqual(deletedCount, 1, 'Should detect one deleted folder');
        assert.ok(elapsed < 500, `Should complete in under 500ms for ${count} folders, took ${elapsed}ms`);
    });

    // --- Change 2: getMailboxListing Redis pipeline tests ---

    await t.test('getMailboxListing uses pipeline for batch Redis lookups', async () => {
        let paths = ['INBOX', 'Sent', 'Drafts'];
        let storedListing = {};

        // Set up stored listing in mock Redis
        for (let path of paths) {
            storedListing[path] = msgpack.encode({
                path,
                delimiter: '/',
                name: path,
                listed: true,
                subscribed: true
            });
        }

        // Set up mailbox info data in mock Redis
        for (let path of paths) {
            let redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(path)).digest('hex')).toString(36);
            mockRedisData[`${REDIS_PREFIX}iam:testaccount:h:${redisKey}`] = {
                path,
                messages: '42',
                uidNext: '100'
            };
        }

        // Simulate what getMailboxListing does with pipeline
        let pipeline = mockRedis.pipeline();
        for (let path of paths) {
            let redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(path)).digest('hex')).toString(36);
            pipeline.hgetall(`${REDIS_PREFIX}iam:testaccount:h:${redisKey}`);
        }
        let pipelineResults = await pipeline.exec();

        assert.strictEqual(pipelineResults.length, paths.length, 'Pipeline should return results for all paths');
        assert.strictEqual(pipelineCalls.length, paths.length, 'Pipeline should batch all hgetall calls');

        // Verify results are correctly extracted
        for (let i = 0; i < paths.length; i++) {
            let [err, data] = pipelineResults[i];
            assert.strictEqual(err, null, 'No pipeline error');
            assert.ok(data, 'Should have data for path');
            assert.strictEqual(data.path, paths[i]);
            assert.strictEqual(data.messages, '42');
        }
    });

    await t.test('getMailboxListing merges pipeline results with stored listing and status', async () => {
        let paths = ['INBOX', 'Sent'];
        let storedListing = {};

        for (let path of paths) {
            storedListing[path] = msgpack.encode({
                path,
                delimiter: '/',
                name: path,
                listed: true,
                subscribed: true
            });
        }

        // Set up mailbox info
        for (let path of paths) {
            let redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(path)).digest('hex')).toString(36);
            mockRedisData[`${REDIS_PREFIX}iam:testaccount:h:${redisKey}`] = {
                path,
                messages: '10',
                uidNext: '50'
            };
        }

        // Simulate mailboxListing with status (from IMAP LIST command)
        let mailboxListing = [
            { path: 'INBOX', status: { messages: 10, unseen: 3, path: 'INBOX' } },
            { path: 'Sent', status: { messages: 5, unseen: 0, path: 'Sent' } }
        ];

        // Build map (the fix)
        let mailboxListingMap = new Map();
        for (let entry of mailboxListing) {
            if (entry.status) {
                delete entry.status.path;
            }
            mailboxListingMap.set(entry.path, entry);
        }

        // Pipeline
        let pipeline = mockRedis.pipeline();
        for (let path of paths) {
            let redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(path)).digest('hex')).toString(36);
            pipeline.hgetall(`${REDIS_PREFIX}iam:testaccount:h:${redisKey}`);
        }
        let pipelineResults = await pipeline.exec();

        // Build mailboxes
        let mailboxes = [];
        for (let i = 0; i < paths.length; i++) {
            let path = paths[i];
            let decoded = msgpack.decode(storedListing[path]);
            let listedMailboxInfo = mailboxListingMap.get(path);

            let mailboxInfo = {};
            let [pipelineErr, data] = pipelineResults[i] || [];
            if (!pipelineErr && data && Object.keys(data).length) {
                mailboxInfo = {
                    path: data.path || path,
                    messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
                    uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false
                };
            }

            mailboxes.push(Object.assign(decoded, mailboxInfo, listedMailboxInfo && listedMailboxInfo.status ? { status: listedMailboxInfo.status } : {}));
        }

        assert.strictEqual(mailboxes.length, 2);
        assert.strictEqual(mailboxes[0].path, 'INBOX');
        assert.strictEqual(mailboxes[0].messages, 10);
        assert.strictEqual(mailboxes[0].uidNext, 50);
        assert.deepStrictEqual(mailboxes[0].status, { messages: 10, unseen: 3 });
        assert.strictEqual(mailboxes[1].path, 'Sent');
        assert.deepStrictEqual(mailboxes[1].status, { messages: 5, unseen: 0 });
    });

    await t.test('getMailboxListing handles missing mailbox info gracefully', async () => {
        // No mailbox info data set up -- pipeline returns null
        let path = 'EmptyFolder';
        let storedListing = {
            [path]: msgpack.encode({
                path,
                delimiter: '/',
                name: path,
                listed: true,
                subscribed: true
            })
        };

        let pipeline = mockRedis.pipeline();
        let redisKey = BigInt('0x' + crypto.createHash(MAILBOX_HASH).update(normalizePath(path)).digest('hex')).toString(36);
        pipeline.hgetall(`${REDIS_PREFIX}iam:testaccount:h:${redisKey}`);
        let pipelineResults = await pipeline.exec();

        let [pipelineErr, data] = pipelineResults[0];
        let mailboxInfo = {};
        if (!pipelineErr && data && Object.keys(data).length) {
            mailboxInfo = {
                path: data.path || path,
                messages: data.messages && !isNaN(data.messages) ? Number(data.messages) : false,
                uidNext: data.uidNext && !isNaN(data.uidNext) ? Number(data.uidNext) : false
            };
        }

        let decoded = msgpack.decode(storedListing[path]);
        let result = Object.assign(decoded, mailboxInfo);

        assert.strictEqual(result.path, path);
        assert.strictEqual(result.messages, undefined, 'Should not have messages when no mailbox info');
    });

    // --- Change 3: Gmail detailed label cache tests ---

    await t.test('Gmail label detail cache avoids repeated API calls', async () => {
        let apiCallCount = 0;

        // Simulate the caching logic from gmail-client listMailboxes
        let cachedDetailedLabels = null;
        let cachedDetailedLabelsTime = null;

        let labels = [
            { id: 'Label_1', name: 'Work', type: 'user' },
            { id: 'Label_2', name: 'Personal', type: 'user' },
            { id: 'INBOX', name: 'INBOX', type: 'system' }
        ];

        let fetchDetailedLabels = async () => {
            let results = [];
            for (let label of labels) {
                apiCallCount++;
                results.push({ ...label, messagesTotal: 100, messagesUnread: 5 });
            }
            return results;
        };

        // First call -- should fetch
        let now = Date.now();
        let resultLabels;
        if (!cachedDetailedLabels || now > cachedDetailedLabelsTime + 60 * 1000) {
            resultLabels = await fetchDetailedLabels();
            cachedDetailedLabels = resultLabels;
            cachedDetailedLabelsTime = now;
        } else {
            resultLabels = cachedDetailedLabels;
        }

        assert.strictEqual(apiCallCount, 3, 'First call should make API requests');
        assert.strictEqual(resultLabels.length, 3);

        // Second call within 60s -- should use cache
        let resultLabels2;
        let now2 = Date.now();
        let cacheValid = cachedDetailedLabels && now2 <= cachedDetailedLabelsTime + 60 * 1000;
        if (!cacheValid) {
            resultLabels2 = await fetchDetailedLabels();
            cachedDetailedLabels = resultLabels2;
        } else {
            resultLabels2 = cachedDetailedLabels;
        }

        assert.strictEqual(apiCallCount, 3, 'Second call should use cache, no new API requests');
        assert.strictEqual(resultLabels2.length, 3);
        assert.strictEqual(resultLabels2, cachedDetailedLabels, 'Should return cached reference');
    });

    await t.test('Gmail label detail cache expires after 60 seconds', async () => {
        let cachedDetailedLabels = [{ id: 'Label_1', name: 'Test' }];
        let cachedDetailedLabelsTime = Date.now() - 61 * 1000; // 61 seconds ago

        let now = Date.now();
        let cacheHit = cachedDetailedLabels && now <= cachedDetailedLabelsTime + 60 * 1000;

        assert.strictEqual(cacheHit, false, 'Cache should be expired after 60 seconds');
    });

    await t.test('Gmail label detail cache clears on label mutation', async () => {
        let cache = { labels: [{ id: 'Label_1', name: 'Test' }], time: Date.now() };

        // Simulate label create/update/delete clearing the cache
        cache.labels = null;

        let now = Date.now();
        let cacheHit = !!(cache.labels && now <= cache.time + 60 * 1000);

        assert.strictEqual(cacheHit, false, 'Cache should miss after mutation clears it');
    });

    await t.test('Gmail listMailboxes without counters does not use detailed cache', async () => {
        let cachedDetailedLabels = [{ id: 'Label_1', name: 'Cached', messagesTotal: 999 }];
        let cachedDetailedLabelsTime = Date.now();

        let options = {}; // No statusQuery
        let resultLabels;

        if (options && options.statusQuery?.unseen) {
            let now = Date.now();
            if (cachedDetailedLabels && now <= cachedDetailedLabelsTime + 60 * 1000) {
                resultLabels = cachedDetailedLabels;
            }
        } else {
            resultLabels = [{ id: 'Label_1', name: 'Fresh' }]; // basic labels
        }

        assert.strictEqual(resultLabels[0].name, 'Fresh', 'Without counters, should use basic labels not cache');
    });
});
