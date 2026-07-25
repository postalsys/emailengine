'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const msgpack = require('msgpack5')();

// Mock the db module before any other imports to prevent real Redis/BullMQ
// connections from being created.
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {},
    getJob: async () => null
};

let mockRedisData = {};

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
        hgetallBuffer: async () => ({}),
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
        ttl: async () => 3600,
        hincrby: async (key, field, increment) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            mockRedisData[key][field] = String((Number(mockRedisData[key][field]) || 0) + increment);
            return Number(mockRedisData[key][field]);
        },
        zpopmin: async () => [],
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

// Now safe to import production modules
const { Export, generateExportId, calculateScore, getExportKey, getExportQueueKey } = require('../lib/export');
const { REDIS_PREFIX } = require('../lib/consts');

test('Export functionality tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // Reset mock data before each test that needs it
    t.beforeEach(() => {
        mockRedisData = {};
    });

    // generateExportId tests
    await t.test('generateExportId() returns string starting with exp_', async () => {
        const id = generateExportId();
        assert.strictEqual(typeof id, 'string');
        assert.ok(id.startsWith('exp_'), `Expected id to start with 'exp_', got: ${id}`);
    });

    await t.test('generateExportId() returns unique values on each call', async () => {
        const id1 = generateExportId();
        const id2 = generateExportId();
        const id3 = generateExportId();

        assert.notStrictEqual(id1, id2);
        assert.notStrictEqual(id2, id3);
        assert.notStrictEqual(id1, id3);
    });

    await t.test('generateExportId() returns 28 character string', async () => {
        const id = generateExportId();
        // exp_ (4) + 12 bytes hex (24) = 28 characters
        assert.strictEqual(id.length, 28);
    });

    await t.test('generateExportId() only contains valid hex characters after prefix', async () => {
        const id = generateExportId();
        const hexPart = id.substring(4);
        assert.ok(/^[0-9a-f]+$/.test(hexPart), 'Hex part should only contain hex characters');
    });

    // Score calculation tests - using production calculateScore function
    await t.test('Score calculation: different messageIds with same timestamp produce different scores', async () => {
        const baseTimestamp = 1700000000000;

        const score1 = calculateScore(baseTimestamp, 'INBOX', 'msg_001', 1);
        const score2 = calculateScore(baseTimestamp, 'INBOX', 'msg_002', 2);
        const score3 = calculateScore(baseTimestamp, 'INBOX', 'msg_003', 3);

        assert.notStrictEqual(score1, score2);
        assert.notStrictEqual(score2, score3);
        assert.notStrictEqual(score1, score3);
    });

    await t.test('Score calculation: scores maintain chronological ordering', async () => {
        const earlierTimestamp = 1700000000000;
        const laterTimestamp = 1700000001000;

        // Even with different messageIds, earlier timestamp should have lower score
        const scoreEarlier = calculateScore(earlierTimestamp, 'INBOX', 'msg_zzz', 1);
        const scoreLater = calculateScore(laterTimestamp, 'INBOX', 'msg_aaa', 2);

        assert.ok(scoreEarlier < scoreLater, 'Earlier timestamp should produce lower score');
    });

    await t.test('Score calculation: same inputs produce same score', async () => {
        const timestamp = 1700000000000;

        const score1 = calculateScore(timestamp, 'INBOX', 'consistent_id', 100);
        const score2 = calculateScore(timestamp, 'INBOX', 'consistent_id', 100);

        assert.strictEqual(score1, score2, 'Same inputs should produce same score');
    });

    await t.test('Score calculation: handles Date objects', async () => {
        const date = new Date(1700000000000);
        const timestamp = 1700000000000;
        const messageId = 'msg_test';

        const scoreFromDate = calculateScore(date, 'INBOX', messageId, 1);
        const scoreFromTimestamp = calculateScore(timestamp, 'INBOX', messageId, 1);

        assert.strictEqual(scoreFromDate, scoreFromTimestamp, 'Date object and timestamp should produce same score');
    });

    await t.test('Score calculation: handles null/undefined/empty messageId', async () => {
        const timestamp = 1700000000000;

        const scoreNull = calculateScore(timestamp, null, null, null);
        const scoreUndefined = calculateScore(timestamp, undefined, undefined, undefined);
        const scoreEmpty = calculateScore(timestamp, '', '', '');

        assert.strictEqual(scoreNull, scoreEmpty, 'null inputs should be treated as empty');
        assert.strictEqual(scoreUndefined, scoreEmpty, 'undefined inputs should be treated as empty');
    });

    await t.test('Score calculation: long messageIds work correctly', async () => {
        const timestamp = 1700000000000;

        // Test with realistic Graph API / Gmail message IDs
        const outlookId = 'AAMkAGVmMDEzMTM4LTZmYWUtNDdkNC1hMDZiLTU1OGY5OTZhYmY4OABGAAAAAADUuTJK1K9sTpCdqXop_4NaBwCd9nJ-tVysQYj2Cekan9XRAAAAAAEMAAC';
        const gmailId = '18abc123def456789';

        const outlookScore = calculateScore(timestamp, 'INBOX', outlookId, 1);
        const gmailScore = calculateScore(timestamp, 'INBOX', gmailId, 2);

        assert.strictEqual(typeof outlookScore, 'number');
        assert.strictEqual(typeof gmailScore, 'number');
        assert.ok(Number.isSafeInteger(outlookScore), 'Outlook score should be safe integer');
        assert.ok(Number.isSafeInteger(gmailScore), 'Gmail score should be safe integer');
    });

    await t.test('Score calculation: messages with same timestamp have unique scores', async () => {
        const timestamp = 1700000000000;
        const messageIds = ['msg_001', 'msg_002', 'msg_003', 'msg_004', 'msg_005', 'msg_100', 'msg_200', 'msg_300', 'msg_400', 'msg_500'];

        const scores = messageIds.map((id, i) => calculateScore(timestamp, 'INBOX', id, i + 1));
        const uniqueScores = new Set(scores);

        assert.strictEqual(uniqueScores.size, messageIds.length, 'All messages should produce unique scores');
    });

    await t.test('Score calculation uses 4-byte hash for tiebreaker', async () => {
        // Verify the production function uses 4-byte hash by checking two values
        // that differ only in the 4th byte of their SHA-256 hash
        const timestamp = 1700000000000;
        const score = calculateScore(timestamp, 'INBOX', 'test_msg', 1);

        // Manually compute expected score with 4-byte hash
        const uniqueKey = 'INBOX:test_msg:1';
        const hash = crypto.createHash('sha256').update(uniqueKey).digest();
        const tiebreaker = (((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]) >>> 0) % 1000000;
        const baseSeconds = Math.floor(timestamp / 1000);
        const expectedScore = baseSeconds * 1000000 + tiebreaker;

        assert.strictEqual(score, expectedScore, 'Production score should match 4-byte hash calculation');
    });

    // formatStatus tests - using production Export.formatStatus
    await t.test('formatStatus() correctly formats all status fields', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'processing',
            phase: 'indexing',
            folders: '["INBOX","Sent"]',
            startDate: '1700000000000',
            endDate: '1700100000000',
            isEncrypted: '1',
            foldersScanned: '5',
            foldersTotal: '10',
            messagesQueued: '100',
            messagesExported: '50',
            messagesSkipped: '2',
            bytesWritten: '1024000',
            created: '1699900000000',
            expiresAt: '1700200000000',
            error: ''
        };

        const result = Export.formatStatus(data);

        assert.strictEqual(result.exportId, 'exp_test123');
        assert.strictEqual(result.status, 'processing');
        assert.strictEqual(result.phase, 'indexing');
        assert.deepStrictEqual(result.folders, ['INBOX', 'Sent']);
        assert.strictEqual(typeof result.startDate, 'string');
        assert.strictEqual(typeof result.endDate, 'string');
        assert.strictEqual(result.isEncrypted, true);
        assert.strictEqual(result.progress.foldersScanned, 5);
        assert.strictEqual(result.progress.foldersTotal, 10);
        assert.strictEqual(result.progress.messagesQueued, 100);
        assert.strictEqual(result.progress.messagesExported, 50);
        assert.strictEqual(result.progress.messagesSkipped, 2);
        assert.strictEqual(result.progress.bytesWritten, 1024000);
        assert.strictEqual(result.error, null);
    });

    await t.test('formatStatus() includes isEncrypted field', async () => {
        const dataEncrypted = {
            exportId: 'exp_test1',
            status: 'completed',
            phase: 'complete',
            isEncrypted: '1'
        };

        const dataNotEncrypted = {
            exportId: 'exp_test2',
            status: 'completed',
            phase: 'complete',
            isEncrypted: '0'
        };

        const resultEncrypted = Export.formatStatus(dataEncrypted);
        const resultNotEncrypted = Export.formatStatus(dataNotEncrypted);

        assert.strictEqual(resultEncrypted.isEncrypted, true);
        assert.strictEqual(resultNotEncrypted.isEncrypted, false);
        assert.ok('isEncrypted' in resultEncrypted, 'isEncrypted field should be present');
        assert.ok('isEncrypted' in resultNotEncrypted, 'isEncrypted field should be present');
    });

    await t.test('formatStatus() handles missing/null values', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'queued',
            phase: 'pending'
        };

        const result = Export.formatStatus(data);

        assert.strictEqual(result.exportId, 'exp_test123');
        assert.strictEqual(result.status, 'queued');
        assert.strictEqual(result.phase, undefined); // pending phase is hidden
        assert.deepStrictEqual(result.folders, []);
        assert.strictEqual(result.progress.foldersScanned, 0);
        assert.strictEqual(result.progress.messagesQueued, 0);
    });

    await t.test('formatStatus() converts timestamps to ISO dates', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'completed',
            phase: 'complete',
            created: '1700000000000',
            expiresAt: '1700100000000'
        };

        const result = Export.formatStatus(data);

        // Should be valid ISO date strings
        assert.ok(result.created.includes('T'), 'created should be ISO date');
        assert.ok(result.expiresAt.includes('T'), 'expiresAt should be ISO date');

        // Should be parseable
        const createdDate = new Date(result.created);
        assert.strictEqual(createdDate.getTime(), 1700000000000);
    });

    await t.test('formatStatus() preserves error message', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'failed',
            phase: 'exporting',
            error: 'Connection timeout'
        };

        const result = Export.formatStatus(data);

        assert.strictEqual(result.error, 'Connection timeout');
    });

    await t.test('formatStatus() handles empty error as null', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'completed',
            phase: 'complete',
            error: ''
        };

        const result = Export.formatStatus(data);

        assert.strictEqual(result.error, null);
    });

    // Export.isCancelled() tests
    await t.test('Export.isCancelled() returns true for cancelled status', async () => {
        const account = 'test-account';
        const exportId = 'exp_test123';
        mockRedisData[`exp:${account}:${exportId}`] = { status: 'cancelled' };

        const result = await Export.isCancelled(account, exportId);
        assert.strictEqual(result, true);
    });

    await t.test('Export.isCancelled() returns true for missing export', async () => {
        const result = await Export.isCancelled('nonexistent', 'exp_nonexistent');
        assert.strictEqual(result, true);
    });

    await t.test('Export.isCancelled() returns false for processing export', async () => {
        const account = 'test-account';
        const exportId = 'exp_active';
        mockRedisData[`exp:${account}:${exportId}`] = { status: 'processing' };

        const result = await Export.isCancelled(account, exportId);
        assert.strictEqual(result, false);
    });

    // Account validation in Export.create()
    await t.test('Export.create() throws 404 for non-existent account', async () => {
        // No account data in mock redis
        mockRedisData = {};

        await assert.rejects(
            () =>
                Export.create('nonexistent-account', {
                    startDate: '2024-01-01T00:00:00Z',
                    endDate: '2024-12-31T23:59:59Z'
                }),
            err => {
                assert.strictEqual(err.code, 'AccountNotFound');
                assert.strictEqual(err.statusCode, 404);
                return true;
            }
        );
    });

    // DecryptStream._transform is not async
    await t.test('DecryptStream._transform is not async', async () => {
        const { createDecryptStream } = require('../lib/stream-encrypt');
        const stream = await createDecryptStream('test-secret');
        assert.notStrictEqual(stream._transform.constructor.name, 'AsyncFunction', '_transform should not be async');
    });

    // Schema validation tests
    await t.test('exportRequestSchema rejects startDate >= endDate', async () => {
        const schemasPath = require.resolve('../lib/schemas');
        // Clear any cached version
        delete require.cache[schemasPath];
        const { exportRequestSchema } = require('../lib/schemas');

        const result = exportRequestSchema.validate({
            startDate: '2024-12-31T23:59:59Z',
            endDate: '2024-01-01T00:00:00Z'
        });

        assert.ok(result.error, 'Should reject when startDate >= endDate');
        assert.ok(result.error.message.includes('startDate must be before endDate'), `Expected date range error, got: ${result.error.message}`);
    });

    await t.test('exportRequestSchema accepts valid date range', async () => {
        const { exportRequestSchema } = require('../lib/schemas');

        const result = exportRequestSchema.validate({
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-12-31T23:59:59Z'
        });

        assert.ok(!result.error, `Should accept valid date range, got error: ${result.error?.message}`);
    });

    await t.test('settingsSchema accepts exportMaxMessages', async () => {
        const Joi = require('joi');
        const { settingsSchema } = require('../lib/schemas');

        const schema = Joi.object(settingsSchema);
        const result = schema.validate({ exportMaxMessages: 500000 });

        assert.ok(!result.error, `Should accept exportMaxMessages, got error: ${result.error?.message}`);
    });

    await t.test('settingsSchema accepts exportMaxSize', async () => {
        const Joi = require('joi');
        const { settingsSchema } = require('../lib/schemas');

        const schema = Joi.object(settingsSchema);
        const result = schema.validate({ exportMaxSize: 10737418240 });

        assert.ok(!result.error, `Should accept exportMaxSize, got error: ${result.error?.message}`);
    });

    // Msgpack encoding tests
    await t.test('Msgpack encodes message info correctly', async () => {
        const messageInfo = {
            folder: 'INBOX',
            messageId: 'msg_123',
            uid: 456,
            size: 1024
        };

        const encoded = msgpack.encode(messageInfo).toString('base64url');
        const decoded = msgpack.decode(Buffer.from(encoded, 'base64url'));

        assert.deepStrictEqual(decoded, messageInfo);
    });

    await t.test('Msgpack handles special characters in folder names', async () => {
        const messageInfo = {
            folder: 'INBOX/Subfolder/With Spaces',
            messageId: 'msg_123',
            uid: 789,
            size: 2048
        };

        const encoded = msgpack.encode(messageInfo).toString('base64url');
        const decoded = msgpack.decode(Buffer.from(encoded, 'base64url'));

        assert.strictEqual(decoded.folder, 'INBOX/Subfolder/With Spaces');
    });

    await t.test('Msgpack handles unicode folder names', async () => {
        const messageInfo = {
            folder: 'INBOX/Folder-With-Dashes',
            messageId: 'msg_123',
            uid: 789,
            size: 2048
        };

        const encoded = msgpack.encode(messageInfo).toString('base64url');
        const decoded = msgpack.decode(Buffer.from(encoded, 'base64url'));

        assert.strictEqual(decoded.folder, messageInfo.folder);
    });

    await t.test('Msgpack handles large UIDs', async () => {
        const messageInfo = {
            folder: 'INBOX',
            messageId: 'msg_123',
            uid: 4294967295, // max uint32
            size: 0
        };

        const encoded = msgpack.encode(messageInfo).toString('base64url');
        const decoded = msgpack.decode(Buffer.from(encoded, 'base64url'));

        assert.strictEqual(decoded.uid, 4294967295);
    });

    // Export key format tests - the status hash and the indexed-message queue must land on
    // distinct keys, otherwise deleteFully() wipes one while the other leaks. Both keys must
    // carry REDIS_PREFIX so an instance sharing a Redis db stays namespaced.
    await t.test('Export key format includes account and exportId', async () => {
        assert.strictEqual(getExportKey('test-account', 'exp_123'), `${REDIS_PREFIX}exp:test-account:exp_123`);
    });

    await t.test('Export queue key format includes account and exportId', async () => {
        assert.strictEqual(getExportQueueKey('test-account', 'exp_123'), `${REDIS_PREFIX}exq:test-account:exp_123`);

        assert.notStrictEqual(
            getExportQueueKey('test-account', 'exp_123'),
            getExportKey('test-account', 'exp_123'),
            'the queue key must not collide with the status key'
        );
    });

    // Progress and timestamp rendering. Every counter is stored in Redis as a string, so
    // formatStatus() is what turns a raw hash into the numbers the API and the admin UI show.
    await t.test('formatStatus() parses progress counters out of their Redis string form', async () => {
        const status = Export.formatStatus({
            exportId: 'exp_abc123def456abc123def456',
            status: 'processing',
            phase: 'exporting',
            folders: '["INBOX"]',
            foldersScanned: '15',
            foldersTotal: '20',
            messagesQueued: '500',
            messagesExported: '450',
            messagesSkipped: '5',
            bytesWritten: '52428800'
        });

        assert.deepStrictEqual(status.progress, {
            foldersScanned: 15,
            foldersTotal: 20,
            messagesQueued: 500,
            messagesExported: 450,
            messagesSkipped: 5,
            bytesWritten: 52428800
        });
    });

    await t.test('formatStatus() defaults every missing progress counter to 0', async () => {
        // A freshly created export has no counters written yet - the API must still report
        // a complete progress object rather than undefined/NaN fields.
        const status = Export.formatStatus({ exportId: 'exp_abc123def456abc123def456', status: 'queued', phase: 'pending' });

        assert.deepStrictEqual(status.progress, {
            foldersScanned: 0,
            foldersTotal: 0,
            messagesQueued: 0,
            messagesExported: 0,
            messagesSkipped: 0,
            bytesWritten: 0
        });
        assert.strictEqual(status.phase, undefined, 'the pending phase is not surfaced');
        assert.deepStrictEqual(status.folders, []);
    });

    await t.test('formatStatus() renders stored epoch millisecond timestamps as ISO dates', async () => {
        const created = Date.UTC(2024, 0, 15, 10, 30, 0);
        const status = Export.formatStatus({
            exportId: 'exp_abc123def456abc123def456',
            status: 'completed',
            phase: 'complete',
            folders: '[]',
            startDate: String(created),
            created: String(created),
            expiresAt: String(created + 86400000),
            isEncrypted: '1'
        });

        assert.strictEqual(status.created, '2024-01-15T10:30:00.000Z');
        assert.strictEqual(status.startDate, '2024-01-15T10:30:00.000Z');
        assert.strictEqual(status.expiresAt, '2024-01-16T10:30:00.000Z');
        assert.strictEqual(status.endDate, undefined, 'an unset date must be omitted, not rendered as epoch 0');
        assert.strictEqual(status.isEncrypted, true);
    });

    // truncated field in formatStatus
    await t.test('formatStatus() includes truncated field when set', async () => {
        const data = {
            exportId: 'exp_abc123def456abc123def456',
            status: 'completed',
            phase: 'complete',
            folders: '[]',
            truncated: '1',
            created: String(Date.now()),
            expiresAt: String(Date.now() + 86400000),
            error: ''
        };

        const result = Export.formatStatus(data);
        assert.strictEqual(result.truncated, true);
    });

    await t.test('formatStatus() omits truncated field when not set', async () => {
        const data = {
            exportId: 'exp_abc123def456abc123def456',
            status: 'completed',
            phase: 'complete',
            folders: '[]',
            created: String(Date.now()),
            expiresAt: String(Date.now() + 86400000),
            error: ''
        };

        const result = Export.formatStatus(data);
        assert.strictEqual(result.truncated, undefined);
    });

    // Export.startProcessing() tests
    await t.test('Export.startProcessing() sets status, phase, and refreshes expiresAt', async () => {
        const account = 'test-account';
        const exportId = 'exp_test123';
        const exportKey = `exp:${account}:${exportId}`;
        const oldExpiresAt = Date.now() - 1000; // already in the past
        mockRedisData[exportKey] = { exportId, status: 'queued', phase: 'pending', expiresAt: String(oldExpiresAt) };

        await Export.startProcessing(account, exportId);

        assert.strictEqual(mockRedisData[exportKey].status, 'processing');
        assert.strictEqual(mockRedisData[exportKey].phase, 'indexing');
        assert.ok(Number(mockRedisData[exportKey].expiresAt) > Date.now(), 'expiresAt should be refreshed to a future value');
    });

    await t.test('Export.startProcessing() resets progress counters and clears the queue', async () => {
        const account = 'test-account';
        const exportId = 'exp_test123';
        const exportKey = `exp:${account}:${exportId}`;
        const queueKey = `exq:${account}:${exportId}`;
        // Simulate state left over from a previous (interrupted) run that is being reprocessed.
        mockRedisData[exportKey] = {
            exportId,
            status: 'processing',
            phase: 'exporting',
            messagesQueued: '100',
            messagesExported: '42',
            messagesSkipped: '3',
            bytesWritten: '12345',
            foldersScanned: '2',
            foldersTotal: '4',
            truncated: '1'
        };
        mockRedisData[queueKey] = { leftover: '1' };

        await Export.startProcessing(account, exportId);

        assert.strictEqual(Number(mockRedisData[exportKey].messagesQueued), 0);
        assert.strictEqual(Number(mockRedisData[exportKey].messagesExported), 0);
        assert.strictEqual(Number(mockRedisData[exportKey].messagesSkipped), 0);
        assert.strictEqual(Number(mockRedisData[exportKey].bytesWritten), 0);
        assert.strictEqual(Number(mockRedisData[exportKey].foldersScanned), 0);
        assert.strictEqual(Number(mockRedisData[exportKey].foldersTotal), 0);
        assert.strictEqual(mockRedisData[exportKey].truncated, '0');
        assert.strictEqual(mockRedisData[queueKey], undefined, 'Queue key should be cleared');
    });

    // Export.deleteFully() tests
    await t.test('Export.deleteFully() removes export and queue keys', async () => {
        const account = 'test-account';
        const exportId = 'exp_test123';
        const exportKey = `exp:${account}:${exportId}`;
        const queueKey = `exq:${account}:${exportId}`;
        mockRedisData[exportKey] = { exportId, status: 'cancelled' };
        mockRedisData[queueKey] = { someData: '1' };

        await Export.deleteFully(account, exportId);

        assert.strictEqual(mockRedisData[exportKey], undefined, 'Export key should be deleted');
        assert.strictEqual(mockRedisData[queueKey], undefined, 'Queue key should be deleted');
    });

    // Export.getNextBatch() tests
    await t.test('Export.getNextBatch() counts undecodable entries as skipped', async () => {
        const account = 'test-account';
        const exportId = 'exp_test123';
        const exportKey = `exp:${account}:${exportId}`;
        mockRedisData[exportKey] = { exportId, status: 'processing', messagesSkipped: '0' };

        const validEntry = msgpack.encode({ folder: 'INBOX', messageId: '<a@b>', uid: 1, size: 10 }).toString('base64url');
        const garbageEntry = 'not-valid-msgpack-data';

        const originalZpopmin = mockRedis.zpopmin;
        mockRedis.zpopmin = async () => [validEntry, '1', garbageEntry, '2'];
        try {
            const messages = await Export.getNextBatch(account, exportId, 10);

            assert.strictEqual(messages.length, 1, 'Only the decodable entry should be returned');
            assert.strictEqual(messages[0].messageId, '<a@b>');
            assert.strictEqual(Number(mockRedisData[exportKey].messagesSkipped), 1, 'Undecodable entry should be counted as skipped');
        } finally {
            mockRedis.zpopmin = originalZpopmin;
        }
    });

    // Schema validation for truncated field
    await t.test('exportStatusSchema accepts truncated field', async () => {
        const schemasPath = require.resolve('../lib/schemas');
        delete require.cache[schemasPath];
        const { exportStatusSchema } = require('../lib/schemas');

        const result = exportStatusSchema.validate({
            exportId: 'exp_abc123def456abc123def456',
            status: 'completed',
            truncated: true
        });

        assert.ok(!result.error, `Should accept truncated field, got error: ${result.error?.message}`);
    });
});

// Regression tests for the error classifiers the export worker uses to decide between skipping a
// single message, retrying, or failing the whole job. Account.assertMessageFound throws a Boom 404
// whose code/status live only in err.output - isSkippableError used to read only the plain fields,
// so an expunged message failed the entire export instead of being counted as skipped.
test('Export error classifiers', async t => {
    const Boom = require('@hapi/boom');
    const { isTransientError, isSkippableError, isFolderMissingError, isRetryableError } = require('../lib/export');

    await t.test('Boom 404 from Account.assertMessageFound is skippable', () => {
        // exact construction from lib/account.js assertFound()
        let error = Boom.boomify(new Error('Requested message was not found'), { statusCode: 404 });
        error.output.payload.code = 'MessageNotFound';

        assert.strictEqual(isSkippableError(error), true, 'Boom-wrapped MessageNotFound must be skippable');
        assert.strictEqual(isTransientError(error), false, 'a missing message is not transient');
    });

    await t.test('Boom 404 from Account.assertFolderFound is a missing folder', () => {
        let error = Boom.boomify(new Error('Requested folder was not found'), { statusCode: 404 });
        error.output.payload.code = 'FolderNotFound';

        assert.strictEqual(isFolderMissingError(error), true);
    });

    await t.test('plain RPC-reconstructed not-found errors keep working', () => {
        // workers/export.js call() rebuilds RPC errors with plain code/statusCode fields
        let err = new Error('Folder not found');
        err.code = 'NotFound';
        err.statusCode = 404;

        assert.strictEqual(isFolderMissingError(err), true);
        assert.strictEqual(isSkippableError(err), true);
    });

    await t.test('transient and permanent errors are not skippable', () => {
        let timeout = new Error('connection timed out');
        timeout.code = 'ETIMEDOUT';
        assert.strictEqual(isTransientError(timeout), true);
        assert.strictEqual(isSkippableError(timeout), false);

        let upstream = new Error('upstream failed');
        upstream.statusCode = 502;
        assert.strictEqual(isTransientError(upstream), true);
        assert.strictEqual(isSkippableError(upstream), false);

        let other = new Error('something else');
        assert.strictEqual(isTransientError(other), false);
        assert.strictEqual(isSkippableError(other), false);
        assert.strictEqual(isFolderMissingError(other), false);
    });

    await t.test('every network error code in the transient list is retried', () => {
        // Spelled out rather than iterated over the production array: asserting a filter against
        // its own input can not fail, and a code silently dropped from the list would stop being
        // retried - the export would fail outright on a blip that used to recover.
        for (const code of ['ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH']) {
            let err = new Error(`socket failure: ${code}`);
            err.code = code;
            assert.strictEqual(isTransientError(err), true, `${code} must be treated as transient`);
            assert.strictEqual(isRetryableError(err), true, `${code} must also be retryable in the batch path`);
        }
    });

    await t.test('the whole 5xx range is transient and 4xx is not', () => {
        for (const statusCode of [500, 502, 503, 599]) {
            assert.strictEqual(isTransientError({ statusCode }), true, `${statusCode} must be transient`);
        }
        for (const statusCode of [400, 404, 499, 600]) {
            assert.strictEqual(isTransientError({ statusCode }), false, `${statusCode} must not be transient`);
        }
    });

    await t.test('a timeout is recognised by code or by message', () => {
        // The RPC layer reports its own timeouts as code 'Timeout' (lib/export.js, workers), while
        // provider clients only put the word in the message - both have to keep the export alive.
        assert.strictEqual(isTransientError({ code: 'Timeout', message: 'Timeout waiting for command response' }), true);
        assert.strictEqual(isTransientError(new Error('Socket timeout while fetching message')), true);
        assert.strictEqual(isTransientError(new Error('timeout')), true);
    });

    await t.test('a message that can not be identified is skipped, not retried forever', () => {
        // The export worker throws this when a message has no usable id; retrying can not help,
        // so it has to be skippable or the whole export fails on one unusable message.
        let err = new Error('Failed to generate message ID for message');
        assert.strictEqual(isSkippableError(err), true);
        assert.strictEqual(isTransientError(err), false);
    });

    await t.test('a 404 in either error shape is skippable', () => {
        assert.strictEqual(isSkippableError({ statusCode: 404 }), true, 'plain client/RPC error shape');
        assert.strictEqual(isSkippableError({ output: { statusCode: 404 } }), true, 'Boom error shape');
        assert.strictEqual(isSkippableError({ code: 'MessageNotFound' }), true);
        assert.strictEqual(isSkippableError({ output: { payload: { code: 'MessageNotFound' } } }), true);
    });

    // The API-account batch fetch path retries a superset of isTransientError: rate limits and
    // Outlook's dropped-batch-response (EMISSING_RESPONSE) on top of the transient network/5xx set.
    // A single such blip must not fail an entire multi-message export.
    await t.test('rate limits, dropped batch responses, and transient errors are retryable', () => {
        assert.strictEqual(isRetryableError({ statusCode: 429 }), true, '429 is retryable');
        assert.strictEqual(isRetryableError({ code: 'rateLimitExceeded' }), true);
        assert.strictEqual(isRetryableError({ code: 'userRateLimitExceeded' }), true);
        assert.strictEqual(isRetryableError({ code: 'EMISSING_RESPONSE' }), true, 'dropped Outlook batch response is retryable');
        assert.strictEqual(isRetryableError({ statusCode: 503 }), true, 'transient 5xx is retryable');
        assert.strictEqual(isRetryableError({ code: 'ETIMEDOUT' }), true);
    });

    await t.test('skippable and permanent errors are not retryable', () => {
        let notFound = new Error('Requested message was not found');
        notFound.code = 'MessageNotFound';
        notFound.statusCode = 404;
        assert.strictEqual(isRetryableError(notFound), false, 'a missing message is not retryable');

        assert.strictEqual(isRetryableError({ statusCode: 400 }), false, 'a 4xx (other than 429) is not retryable');
        assert.strictEqual(isRetryableError({ code: 'InvalidGrant' }), false);
        assert.strictEqual(isRetryableError(new Error('something else')), false);
    });
});

// Export truncation limits.
//
// This used to be a block of ~10 tests driving simulateIndexMessages()/simulateExportMessages()
// - hand-written copies of the worker loops - so nothing here could fail when the real limit
// handling changed. The rules now live in lib/export.js (resolveExportLimit /
// isExportLimitReached) and workers/export.js applies them at all three sites, so these drive
// the shipped code.
test('Export truncation limits', async t => {
    const { resolveExportLimit, isExportLimitReached } = require('../lib/export');

    await t.test('an unset, zero or unusable stored limit falls back to the default', () => {
        // settings.getValue() answers null for a key that was never written, and hands a stored
        // 0 or '' straight back. None of those is a usable limit: taken literally, 0 would mean
        // "stop before the first message" and export nothing at all.
        for (const stored of [null, undefined, 0, '', 'not a number', NaN]) {
            assert.strictEqual(resolveExportLimit(stored, 1000), 1000, `stored ${JSON.stringify(stored)} must fall back`);
        }
    });

    await t.test('a negative stored limit falls back instead of truncating everything', () => {
        // `Number(value) || DEFAULT` passed a negative straight through, and `total >= -1` is
        // true before a single message is indexed - every export came back empty and truncated.
        assert.strictEqual(resolveExportLimit(-1, 1000), 1000);
        assert.strictEqual(resolveExportLimit(-50000, 1000), 1000);
    });

    await t.test('a real stored limit is used, including as a numeric string', () => {
        assert.strictEqual(resolveExportLimit(25, 1000), 25);
        assert.strictEqual(resolveExportLimit('25', 1000), 25, 'settings values come back as strings');
        assert.strictEqual(resolveExportLimit(1, 1000), 1);
    });

    await t.test('a limit of 0 means unlimited', () => {
        // The API contract documents 0 as "no limit", so the check must never fire on it.
        assert.strictEqual(isExportLimitReached(0, 0), false);
        assert.strictEqual(isExportLimitReached(1000000, 0), false, 'an unlimited export must not truncate');
        assert.strictEqual(isExportLimitReached(1000000, undefined), false);
    });

    await t.test('the limit itself still fits and the next message truncates', () => {
        // Off by one here means either one message short of the documented limit, or one over.
        assert.strictEqual(isExportLimitReached(98, 100), false);
        assert.strictEqual(isExportLimitReached(99, 100), false, 'the 100th message must still be exported');
        assert.strictEqual(isExportLimitReached(100, 100), true, 'at the limit the export stops');
        assert.strictEqual(isExportLimitReached(101, 100), true);
    });

    await t.test('the byte limit behaves the same way as the message limit', () => {
        // Same predicate guards totalBytesWritten on both export paths (batch and single fetch).
        const maxExportSize = resolveExportLimit(null, 5 * 1024 * 1024);

        assert.strictEqual(maxExportSize, 5 * 1024 * 1024);
        assert.strictEqual(isExportLimitReached(maxExportSize - 1, maxExportSize), false);
        assert.strictEqual(isExportLimitReached(maxExportSize, maxExportSize), true);
    });
});
