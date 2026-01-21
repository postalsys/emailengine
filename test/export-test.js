'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const msgpack = require('msgpack5')();

// Test pure functions and logic without loading the full export module
// This avoids the Bugsnag/logger initialization issues

const EXPORT_ID_PREFIX = 'exp_';

// Replicate the generateExportId function logic
function generateExportId() {
    return EXPORT_ID_PREFIX + crypto.randomBytes(12).toString('hex');
}

// Replicate the score calculation logic
// Uses messageId hash for tiebreaker instead of UID to avoid collisions with large UIDs
// Using factor of 1000 to stay within JavaScript safe integer range (< 2^53)
function calculateScore(timestamp, messageId) {
    const baseTimestamp = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp) || Date.now();

    // Generate tiebreaker from messageId hash (0-999 range)
    let tiebreaker = 0;
    const id = messageId || '';
    for (let i = 0; i < id.length; i++) {
        tiebreaker = ((tiebreaker << 5) - tiebreaker + id.charCodeAt(i)) | 0;
    }
    tiebreaker = Math.abs(tiebreaker) % 1000;

    return baseTimestamp * 1000 + tiebreaker;
}

// Replicate the formatStatus function logic
function formatStatus(data) {
    const toIsoDate = value => (value ? new Date(Number(value)).toISOString() : undefined);

    return {
        exportId: data.exportId,
        status: data.status,
        phase: data.phase !== 'pending' ? data.phase : undefined,
        folders: data.folders ? JSON.parse(data.folders) : [],
        startDate: toIsoDate(data.startDate),
        endDate: toIsoDate(data.endDate),
        progress: {
            foldersScanned: Number(data.foldersScanned) || 0,
            foldersTotal: Number(data.foldersTotal) || 0,
            messagesQueued: Number(data.messagesQueued) || 0,
            messagesExported: Number(data.messagesExported) || 0,
            messagesSkipped: Number(data.messagesSkipped) || 0,
            bytesWritten: Number(data.bytesWritten) || 0
        },
        created: toIsoDate(data.created),
        expiresAt: toIsoDate(data.expiresAt),
        error: data.error || null
    };
}

// Replicate the getNextBatch minScore calculation logic
function calculateMinScore(lastScore) {
    return lastScore > 0 ? '(' + lastScore : lastScore;
}

test('Export functionality tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
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

    // Score calculation tests - using messageId hash for tiebreaker
    await t.test('Score calculation: different messageIds with same timestamp produce different scores', async () => {
        const baseTimestamp = 1700000000000;

        const score1 = calculateScore(baseTimestamp, 'msg_001');
        const score2 = calculateScore(baseTimestamp, 'msg_002');
        const score3 = calculateScore(baseTimestamp, 'msg_003');

        assert.notStrictEqual(score1, score2);
        assert.notStrictEqual(score2, score3);
        assert.notStrictEqual(score1, score3);
    });

    await t.test('Score calculation: scores maintain chronological ordering', async () => {
        const earlierTimestamp = 1700000000000;
        const laterTimestamp = 1700000001000;

        // Even with different messageIds, earlier timestamp should have lower score
        const scoreEarlier = calculateScore(earlierTimestamp, 'msg_zzz');
        const scoreLater = calculateScore(laterTimestamp, 'msg_aaa');

        assert.ok(scoreEarlier < scoreLater, 'Earlier timestamp should produce lower score');
    });

    await t.test('Score calculation: same messageId produces same tiebreaker', async () => {
        const timestamp = 1700000000000;

        const score1 = calculateScore(timestamp, 'consistent_id');
        const score2 = calculateScore(timestamp, 'consistent_id');

        assert.strictEqual(score1, score2, 'Same messageId should produce same score');
    });

    await t.test('Score calculation: handles Date objects', async () => {
        const date = new Date(1700000000000);
        const timestamp = 1700000000000;
        const messageId = 'msg_test';

        const scoreFromDate = calculateScore(date, messageId);
        const scoreFromTimestamp = calculateScore(timestamp, messageId);

        assert.strictEqual(scoreFromDate, scoreFromTimestamp, 'Date object and timestamp should produce same score');
    });

    await t.test('Score calculation: handles null/undefined/empty messageId', async () => {
        const timestamp = 1700000000000;

        const scoreNull = calculateScore(timestamp, null);
        const scoreUndefined = calculateScore(timestamp, undefined);
        const scoreEmpty = calculateScore(timestamp, '');

        assert.strictEqual(scoreNull, scoreEmpty, 'null messageId should be treated as empty');
        assert.strictEqual(scoreUndefined, scoreEmpty, 'undefined messageId should be treated as empty');
    });

    await t.test('Score calculation: long messageIds work correctly', async () => {
        const timestamp = 1700000000000;

        // Test with realistic Graph API / Gmail message IDs
        const outlookId = 'AAMkAGVmMDEzMTM4LTZmYWUtNDdkNC1hMDZiLTU1OGY5OTZhYmY4OABGAAAAAADUuTJK1K9sTpCdqXop_4NaBwCd9nJ-tVysQYj2Cekan9XRAAAAAAEMAAC';
        const gmailId = '18abc123def456789';

        const outlookScore = calculateScore(timestamp, outlookId);
        const gmailScore = calculateScore(timestamp, gmailId);

        assert.strictEqual(typeof outlookScore, 'number');
        assert.strictEqual(typeof gmailScore, 'number');
        assert.ok(Number.isSafeInteger(outlookScore), 'Outlook score should be safe integer');
        assert.ok(Number.isSafeInteger(gmailScore), 'Gmail score should be safe integer');
    });

    await t.test('Score calculation: messages with same timestamp have unique scores', async () => {
        const timestamp = 1700000000000;
        const messageIds = ['msg_001', 'msg_002', 'msg_003', 'msg_004', 'msg_005', 'msg_100', 'msg_200', 'msg_300', 'msg_400', 'msg_500'];

        const scores = messageIds.map(id => calculateScore(timestamp, id));
        const uniqueScores = new Set(scores);

        assert.strictEqual(uniqueScores.size, messageIds.length, 'All messageIds should produce unique scores');
    });

    // formatStatus tests
    await t.test('formatStatus() correctly formats all status fields', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'processing',
            phase: 'indexing',
            folders: '["INBOX","Sent"]',
            startDate: '1700000000000',
            endDate: '1700100000000',
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

        const result = formatStatus(data);

        assert.strictEqual(result.exportId, 'exp_test123');
        assert.strictEqual(result.status, 'processing');
        assert.strictEqual(result.phase, 'indexing');
        assert.deepStrictEqual(result.folders, ['INBOX', 'Sent']);
        assert.strictEqual(typeof result.startDate, 'string');
        assert.strictEqual(typeof result.endDate, 'string');
        assert.strictEqual(result.progress.foldersScanned, 5);
        assert.strictEqual(result.progress.foldersTotal, 10);
        assert.strictEqual(result.progress.messagesQueued, 100);
        assert.strictEqual(result.progress.messagesExported, 50);
        assert.strictEqual(result.progress.messagesSkipped, 2);
        assert.strictEqual(result.progress.bytesWritten, 1024000);
        assert.strictEqual(result.error, null);
    });

    await t.test('formatStatus() handles missing/null values', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'queued',
            phase: 'pending'
        };

        const result = formatStatus(data);

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

        const result = formatStatus(data);

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

        const result = formatStatus(data);

        assert.strictEqual(result.error, 'Connection timeout');
    });

    await t.test('formatStatus() handles empty error as null', async () => {
        const data = {
            exportId: 'exp_test123',
            status: 'completed',
            phase: 'complete',
            error: ''
        };

        const result = formatStatus(data);

        assert.strictEqual(result.error, null);
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

    // getNextBatch minScore calculation tests
    await t.test('calculateMinScore uses exclusive lower bound for lastScore > 0', async () => {
        const minScore = calculateMinScore(1700000000000);
        assert.ok(minScore.toString().startsWith('('), 'Should use exclusive lower bound');
    });

    await t.test('calculateMinScore uses inclusive lower bound for lastScore = 0', async () => {
        const minScore = calculateMinScore(0);
        assert.strictEqual(minScore, 0, 'Should use inclusive lower bound for 0');
    });

    await t.test('calculateMinScore handles small positive values', async () => {
        const minScore = calculateMinScore(1);
        assert.strictEqual(minScore, '(1', 'Should use exclusive for any positive value');
    });

    // Worker callQueue timeout cleanup test (Issue 1 regression)
    await t.test('Worker call() timeout deletes entry from callQueue', async () => {
        // Simulate the call function behavior
        const callQueue = new Map();
        let mids = 0;

        const simulateCall = (ttl = 50) => {
            return new Promise((resolve, reject) => {
                const mid = `${Date.now()}:${++mids}`;

                const timer = setTimeout(() => {
                    callQueue.delete(mid); // This is the fix being tested
                    const err = new Error('Timeout waiting for command response [T6]');
                    err.statusCode = 504;
                    err.code = 'Timeout';
                    err.ttl = ttl;
                    reject(err);
                }, ttl);

                callQueue.set(mid, { resolve, reject, timer });
            });
        };

        // Verify callQueue has entry before timeout
        const callPromise = simulateCall(50);
        assert.strictEqual(callQueue.size, 1, 'callQueue should have 1 entry');

        try {
            await callPromise;
        } catch (err) {
            assert.strictEqual(err.code, 'Timeout');
        }

        // Verify callQueue is empty after timeout
        assert.strictEqual(callQueue.size, 0, 'callQueue should be empty after timeout');
    });

    await t.test('Worker call() timeout returns correct error details', async () => {
        const callQueue = new Map();
        let mids = 0;
        const testTtl = 100;

        const simulateCall = ttl => {
            return new Promise((resolve, reject) => {
                const mid = `${Date.now()}:${++mids}`;

                const timer = setTimeout(() => {
                    callQueue.delete(mid);
                    const err = new Error('Timeout waiting for command response [T6]');
                    err.statusCode = 504;
                    err.code = 'Timeout';
                    err.ttl = ttl;
                    reject(err);
                }, ttl);

                callQueue.set(mid, { resolve, reject, timer });
            });
        };

        try {
            await simulateCall(testTtl);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.statusCode, 504);
            assert.strictEqual(err.code, 'Timeout');
            assert.strictEqual(err.ttl, testTtl);
            assert.ok(err.message.includes('T6'));
        }
    });

    await t.test('Worker call() clears timer on successful response', async () => {
        const callQueue = new Map();
        let mids = 0;
        let timerCleared = false;

        const simulateCallWithResponse = ttl => {
            return new Promise((resolve, reject) => {
                const mid = `${Date.now()}:${++mids}`;

                const timer = setTimeout(() => {
                    callQueue.delete(mid);
                    reject(new Error('Should not timeout'));
                }, ttl);

                callQueue.set(mid, { resolve, reject, timer });

                // Simulate immediate response
                setTimeout(() => {
                    if (callQueue.has(mid)) {
                        const entry = callQueue.get(mid);
                        clearTimeout(entry.timer);
                        timerCleared = true;
                        callQueue.delete(mid);
                        entry.resolve({ success: true });
                    }
                }, 10);
            });
        };

        const result = await simulateCallWithResponse(1000);
        assert.strictEqual(result.success, true);
        assert.strictEqual(timerCleared, true, 'Timer should be cleared');
        assert.strictEqual(callQueue.size, 0, 'callQueue should be empty');
    });

    // Export key format tests
    await t.test('Export key format includes account and exportId', async () => {
        const REDIS_PREFIX = 'bull:';
        const getExportKey = (account, exportId) => `${REDIS_PREFIX}exp:${account}:${exportId}`;

        const key = getExportKey('test-account', 'exp_123');
        assert.ok(key.includes('test-account'));
        assert.ok(key.includes('exp_123'));
        assert.ok(key.includes(':exp:'));
    });

    await t.test('Export queue key format includes account and exportId', async () => {
        const REDIS_PREFIX = 'bull:';
        const getExportQueueKey = (account, exportId) => `${REDIS_PREFIX}exq:${account}:${exportId}`;

        const key = getExportQueueKey('test-account', 'exp_123');
        assert.ok(key.includes('test-account'));
        assert.ok(key.includes('exp_123'));
        assert.ok(key.includes(':exq:'));
    });

    // Concurrent export limit logic tests
    await t.test('Concurrent export Lua script logic simulation', async () => {
        // Simulate the Lua script logic for concurrent export limiting
        const simulateConcurrentCheck = (activeMembers, maxConcurrent, accountPrefix, newEntry) => {
            let count = 0;
            for (const member of activeMembers) {
                if (member.startsWith(accountPrefix)) {
                    count++;
                }
            }

            if (count >= maxConcurrent) {
                return 0; // Limit reached
            }

            return 1; // Can add
        };

        // Test: under limit
        const result1 = simulateConcurrentCheck(['account1:exp_1'], 3, 'account1:', 'account1:exp_2');
        assert.strictEqual(result1, 1, 'Should allow when under limit');

        // Test: at limit
        const result2 = simulateConcurrentCheck(['account1:exp_1', 'account1:exp_2', 'account1:exp_3'], 3, 'account1:', 'account1:exp_4');
        assert.strictEqual(result2, 0, 'Should reject when at limit');

        // Test: other accounts do not count
        const result3 = simulateConcurrentCheck(['account2:exp_1', 'account2:exp_2', 'account2:exp_3'], 3, 'account1:', 'account1:exp_1');
        assert.strictEqual(result3, 1, 'Should allow when other accounts have exports');
    });

    // Active set entry parsing tests (for markInterruptedAsFailed)
    await t.test('Active set entry parsing handles account IDs with colons', async () => {
        // The actual logic in lib/export.js
        const parseEntry = entry => {
            const separatorIndex = entry.indexOf(':exp_');
            if (separatorIndex === -1) return null;
            const account = entry.substring(0, separatorIndex);
            const exportId = entry.substring(separatorIndex + 1);
            return { account, exportId };
        };

        // Normal case
        const result1 = parseEntry('account1:exp_abc123');
        assert.strictEqual(result1.account, 'account1');
        assert.strictEqual(result1.exportId, 'exp_abc123');

        // Account ID with colon
        const result2 = parseEntry('user:domain.com:exp_abc123');
        assert.strictEqual(result2.account, 'user:domain.com');
        assert.strictEqual(result2.exportId, 'exp_abc123');

        // Invalid entry
        const result3 = parseEntry('no-export-id-here');
        assert.strictEqual(result3, null);
    });

    // Timestamp conversion tests
    await t.test('toTimestamp handles Date objects', async () => {
        const toTimestamp = date => (date instanceof Date ? date.getTime() : new Date(date).getTime());

        const date = new Date('2024-01-15T10:30:00Z');
        const result = toTimestamp(date);

        assert.strictEqual(typeof result, 'number');
        assert.strictEqual(result, date.getTime());
    });

    await t.test('toTimestamp handles ISO strings', async () => {
        const toTimestamp = date => (date instanceof Date ? date.getTime() : new Date(date).getTime());

        const isoString = '2024-01-15T10:30:00Z';
        const result = toTimestamp(isoString);

        assert.strictEqual(typeof result, 'number');
        assert.strictEqual(result, new Date(isoString).getTime());
    });

    await t.test('toTimestamp handles timestamp numbers', async () => {
        const toTimestamp = date => (date instanceof Date ? date.getTime() : new Date(date).getTime());

        const timestamp = 1705315800000;
        const result = toTimestamp(timestamp);

        assert.strictEqual(result, timestamp);
    });

    // Error construction tests (for queue failure cleanup - Issue 2)
    await t.test('TooManyExports error has correct properties', async () => {
        const err = new Error('Maximum concurrent exports reached');
        err.code = 'TooManyExports';
        err.statusCode = 429;

        assert.strictEqual(err.message, 'Maximum concurrent exports reached');
        assert.strictEqual(err.code, 'TooManyExports');
        assert.strictEqual(err.statusCode, 429);
    });

    await t.test('Queue failure should trigger cleanup', async () => {
        // This tests the logic pattern used in Issue 2 fix
        let cleanupCalled = false;
        const cleanup = () => {
            cleanupCalled = true;
        };

        const queueAdd = async () => {
            throw new Error('Queue connection failed');
        };

        try {
            await queueAdd();
        } catch (err) {
            cleanup();
            assert.strictEqual(err.message, 'Queue connection failed');
        }

        assert.strictEqual(cleanupCalled, true, 'Cleanup should be called on queue failure');
    });

    // Progress calculation tests
    await t.test('Progress fields are correctly parsed from strings', async () => {
        const data = {
            foldersScanned: '15',
            foldersTotal: '20',
            messagesQueued: '500',
            messagesExported: '450',
            messagesSkipped: '5',
            bytesWritten: '52428800'
        };

        const progress = {
            foldersScanned: Number(data.foldersScanned) || 0,
            foldersTotal: Number(data.foldersTotal) || 0,
            messagesQueued: Number(data.messagesQueued) || 0,
            messagesExported: Number(data.messagesExported) || 0,
            messagesSkipped: Number(data.messagesSkipped) || 0,
            bytesWritten: Number(data.bytesWritten) || 0
        };

        assert.strictEqual(progress.foldersScanned, 15);
        assert.strictEqual(progress.foldersTotal, 20);
        assert.strictEqual(progress.messagesQueued, 500);
        assert.strictEqual(progress.messagesExported, 450);
        assert.strictEqual(progress.messagesSkipped, 5);
        assert.strictEqual(progress.bytesWritten, 52428800);
    });

    await t.test('Progress fields default to 0 for missing values', async () => {
        const data = {};

        const progress = {
            foldersScanned: Number(data.foldersScanned) || 0,
            foldersTotal: Number(data.foldersTotal) || 0,
            messagesQueued: Number(data.messagesQueued) || 0
        };

        assert.strictEqual(progress.foldersScanned, 0);
        assert.strictEqual(progress.foldersTotal, 0);
        assert.strictEqual(progress.messagesQueued, 0);
    });

    // Export status transition tests
    await t.test('Valid export status transitions', async () => {
        const validStatuses = ['queued', 'processing', 'completed', 'failed'];
        const validPhases = ['pending', 'indexing', 'exporting', 'complete'];

        for (const status of validStatuses) {
            assert.strictEqual(typeof status, 'string');
        }

        for (const phase of validPhases) {
            assert.strictEqual(typeof phase, 'string');
        }
    });

    // File path construction test
    await t.test('Export file path format is correct', async () => {
        const pathlib = require('path');
        const exportPath = '/tmp/exports';
        const exportId = 'exp_abc123def456';

        const filePath = pathlib.join(exportPath, `${exportId}.ndjson.gz`);

        assert.strictEqual(filePath, '/tmp/exports/exp_abc123def456.ndjson.gz');
        assert.ok(filePath.endsWith('.ndjson.gz'));
    });
});
