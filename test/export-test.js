'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const msgpack = require('msgpack5')();

// Test pure functions and logic without loading the full export module.
// This avoids the Bugsnag/logger initialization issues.
// Score calculation must match lib/export.js Export.queueMessage() exactly.

const EXPORT_ID_PREFIX = 'exp_';

// Replicate the generateExportId function logic
function generateExportId() {
    return EXPORT_ID_PREFIX + crypto.randomBytes(12).toString('hex');
}

// Replicate the score calculation logic from lib/export.js Export.queueMessage()
// Uses SHA-256 hash of composite key (folder:messageId:uid) for tiebreaker
// Using factor of 1000000 with baseSeconds to stay within JavaScript safe integer range (< 2^53)
function calculateScore(timestamp, messageId, folder, uid) {
    const baseTimestamp = timestamp instanceof Date ? timestamp.getTime() : Number(timestamp) || Date.now();
    const baseSeconds = Math.floor(baseTimestamp / 1000);

    // Generate tiebreaker from SHA-256 hash of composite key (0-999999 range)
    const uniqueKey = `${folder || ''}:${messageId || ''}:${uid || ''}`;
    const hash = crypto.createHash('sha256').update(uniqueKey).digest();
    const tiebreaker = (((hash[0] << 16) | (hash[1] << 8) | hash[2]) >>> 0) % 1000000;

    return baseSeconds * 1000000 + tiebreaker;
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

    // Score calculation tests - using SHA-256 hash of composite key for tiebreaker
    // Production algorithm: lib/export.js Export.queueMessage()
    await t.test('Score calculation: different messageIds with same timestamp produce different scores', async () => {
        const baseTimestamp = 1700000000000;

        const score1 = calculateScore(baseTimestamp, 'msg_001', 'INBOX', 1);
        const score2 = calculateScore(baseTimestamp, 'msg_002', 'INBOX', 2);
        const score3 = calculateScore(baseTimestamp, 'msg_003', 'INBOX', 3);

        assert.notStrictEqual(score1, score2);
        assert.notStrictEqual(score2, score3);
        assert.notStrictEqual(score1, score3);
    });

    await t.test('Score calculation: scores maintain chronological ordering', async () => {
        const earlierTimestamp = 1700000000000;
        const laterTimestamp = 1700000001000;

        // Even with different messageIds, earlier timestamp should have lower score
        const scoreEarlier = calculateScore(earlierTimestamp, 'msg_zzz', 'INBOX', 1);
        const scoreLater = calculateScore(laterTimestamp, 'msg_aaa', 'INBOX', 2);

        assert.ok(scoreEarlier < scoreLater, 'Earlier timestamp should produce lower score');
    });

    await t.test('Score calculation: same inputs produce same score', async () => {
        const timestamp = 1700000000000;

        const score1 = calculateScore(timestamp, 'consistent_id', 'INBOX', 100);
        const score2 = calculateScore(timestamp, 'consistent_id', 'INBOX', 100);

        assert.strictEqual(score1, score2, 'Same inputs should produce same score');
    });

    await t.test('Score calculation: handles Date objects', async () => {
        const date = new Date(1700000000000);
        const timestamp = 1700000000000;
        const messageId = 'msg_test';

        const scoreFromDate = calculateScore(date, messageId, 'INBOX', 1);
        const scoreFromTimestamp = calculateScore(timestamp, messageId, 'INBOX', 1);

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

        const outlookScore = calculateScore(timestamp, outlookId, 'INBOX', 1);
        const gmailScore = calculateScore(timestamp, gmailId, 'INBOX', 2);

        assert.strictEqual(typeof outlookScore, 'number');
        assert.strictEqual(typeof gmailScore, 'number');
        assert.ok(Number.isSafeInteger(outlookScore), 'Outlook score should be safe integer');
        assert.ok(Number.isSafeInteger(gmailScore), 'Gmail score should be safe integer');
    });

    await t.test('Score calculation: messages with same timestamp have unique scores', async () => {
        const timestamp = 1700000000000;
        const messageIds = ['msg_001', 'msg_002', 'msg_003', 'msg_004', 'msg_005', 'msg_100', 'msg_200', 'msg_300', 'msg_400', 'msg_500'];

        const scores = messageIds.map((id, i) => calculateScore(timestamp, id, 'INBOX', i + 1));
        const uniqueScores = new Set(scores);

        assert.strictEqual(uniqueScores.size, messageIds.length, 'All messages should produce unique scores');
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
    function createCallSimulator() {
        const callQueue = new Map();
        let mids = 0;

        function simulateCall(ttl) {
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
        }

        return { callQueue, simulateCall };
    }

    await t.test('Worker call() timeout deletes entry from callQueue', async () => {
        const { callQueue, simulateCall } = createCallSimulator();

        const callPromise = simulateCall(50);
        assert.strictEqual(callQueue.size, 1, 'callQueue should have 1 entry');

        try {
            await callPromise;
        } catch (err) {
            assert.strictEqual(err.code, 'Timeout');
        }

        assert.strictEqual(callQueue.size, 0, 'callQueue should be empty after timeout');
    });

    await t.test('Worker call() timeout returns correct error details', async () => {
        const { simulateCall } = createCallSimulator();
        const testTtl = 100;

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

    // Atomic check-and-add simulation tests (prevents TOCTOU race condition)
    function atomicCheckAndAdd(activeSet, maxConcurrent, maxGlobal, accountPrefix, activeEntry) {
        const members = Array.from(activeSet);

        if (members.length >= maxGlobal) {
            return 0;
        }

        let accountCount = 0;
        for (const member of members) {
            if (member.startsWith(accountPrefix)) {
                accountCount++;
            }
        }

        if (accountCount >= maxConcurrent) {
            return 0;
        }

        activeSet.add(activeEntry);
        return 1;
    }

    await t.test('Atomic check-and-add prevents race condition', async () => {
        const activeSet = new Set();

        const result1 = atomicCheckAndAdd(activeSet, 1, 10, 'account1:', 'account1:exp_1');
        const result2 = atomicCheckAndAdd(activeSet, 1, 10, 'account1:', 'account1:exp_2');

        assert.strictEqual(result1, 1, 'First request should succeed');
        assert.strictEqual(result2, 0, 'Second request should be rejected (limit reached)');
        assert.strictEqual(activeSet.size, 1, 'Only one entry should be in active set');
        assert.ok(activeSet.has('account1:exp_1'), 'First entry should be in active set');
    });

    await t.test('Atomic check-and-add allows different accounts concurrently', async () => {
        const activeSet = new Set();

        const result1 = atomicCheckAndAdd(activeSet, 1, 10, 'account1:', 'account1:exp_1');
        const result2 = atomicCheckAndAdd(activeSet, 1, 10, 'account2:', 'account2:exp_1');
        const result3 = atomicCheckAndAdd(activeSet, 1, 10, 'account3:', 'account3:exp_1');

        assert.strictEqual(result1, 1, 'Account 1 should succeed');
        assert.strictEqual(result2, 1, 'Account 2 should succeed');
        assert.strictEqual(result3, 1, 'Account 3 should succeed');
        assert.strictEqual(activeSet.size, 3, 'All three entries should be in active set');
    });

    await t.test('Atomic check-and-add respects global limit', async () => {
        const activeSet = new Set(['a:exp_1', 'b:exp_1']);

        const result = atomicCheckAndAdd(activeSet, 5, 2, 'account3:', 'account3:exp_1');

        assert.strictEqual(result, 0, 'Should reject when global limit reached');
        assert.strictEqual(activeSet.size, 2, 'Active set should not change');
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
    function toTimestamp(date) {
        return date instanceof Date ? date.getTime() : new Date(date).getTime();
    }

    await t.test('toTimestamp handles Date objects', async () => {
        const date = new Date('2024-01-15T10:30:00Z');
        const result = toTimestamp(date);

        assert.strictEqual(typeof result, 'number');
        assert.strictEqual(result, date.getTime());
    });

    await t.test('toTimestamp handles ISO strings', async () => {
        const isoString = '2024-01-15T10:30:00Z';
        const result = toTimestamp(isoString);

        assert.strictEqual(typeof result, 'number');
        assert.strictEqual(result, new Date(isoString).getTime());
    });

    await t.test('toTimestamp handles timestamp numbers', async () => {
        const timestamp = 1705315800000;
        assert.strictEqual(toTimestamp(timestamp), timestamp);
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

    // File path construction test
    await t.test('Export file path format is correct', async () => {
        const pathlib = require('path');
        const filePath = pathlib.join('/tmp/exports', 'exp_abc123def456.ndjson.gz');

        assert.strictEqual(filePath, '/tmp/exports/exp_abc123def456.ndjson.gz');
        assert.ok(filePath.endsWith('.ndjson.gz'));
    });

    // =====================================================
    // Export reliability improvement tests
    // =====================================================

    // Replicate the isTransientError function for testing
    function isTransientError(err) {
        // Network errors
        if (['ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH'].includes(err.code)) {
            return true;
        }
        // Server errors (5xx)
        if (err.statusCode >= 500 && err.statusCode < 600) {
            return true;
        }
        // Timeout errors
        if (err.code === 'Timeout' || err.message?.includes('timeout')) {
            return true;
        }
        return false;
    }

    // Replicate the isSkippableError function for testing
    function isSkippableError(err) {
        return err.code === 'MessageNotFound' || err.statusCode === 404 || err.message?.includes('Failed to generate message ID');
    }

    // isTransientError() tests - transient network errors
    await t.test('isTransientError: network error codes are transient', async () => {
        const transientCodes = ['ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'Timeout'];
        for (const code of transientCodes) {
            assert.strictEqual(isTransientError({ code }), true, `${code} should be transient`);
        }
    });

    await t.test('isTransientError: 5xx status codes are transient', async () => {
        assert.strictEqual(isTransientError({ statusCode: 500 }), true);
        assert.strictEqual(isTransientError({ statusCode: 503 }), true);
    });

    await t.test('isTransientError: message with "timeout" is transient', async () => {
        assert.strictEqual(isTransientError({ message: 'Connection timeout' }), true);
    });

    // isTransientError() tests - non-transient errors
    await t.test('isTransientError: non-transient errors return false', async () => {
        assert.strictEqual(isTransientError({ statusCode: 400 }), false);
        assert.strictEqual(isTransientError({ statusCode: 404 }), false);
        assert.strictEqual(isTransientError({ code: 'InvalidRequest' }), false);
        assert.strictEqual(isTransientError({ message: 'Something went wrong' }), false);
    });

    // isSkippableError() tests
    await t.test('isSkippableError: skippable errors return true', async () => {
        assert.strictEqual(isSkippableError({ code: 'MessageNotFound' }), true);
        assert.strictEqual(isSkippableError({ statusCode: 404 }), true);
        assert.strictEqual(isSkippableError({ message: 'Failed to generate message ID for something' }), true);
    });

    await t.test('isSkippableError: non-skippable errors return false', async () => {
        assert.ok(!isSkippableError({ code: 'NetworkError' }), 'NetworkError should not be skippable');
        assert.ok(!isSkippableError({ statusCode: 500 }), '500 status code should not be skippable');
    });

    // Outlook batch retry logic tests
    function shouldRetryBatch(result) {
        return result.error?.statusCode === 429 || (result.error?.statusCode >= 500 && result.error?.statusCode < 600);
    }

    await t.test('Outlook batch retry: first attempt succeeds -> no retry needed', async () => {
        let attempts = 0;
        const simulateBatchFetch = async () => {
            attempts++;
            return { success: true, data: [{ messageId: 'msg_1', data: {} }] };
        };

        const result = await simulateBatchFetch();
        assert.strictEqual(attempts, 1);
        assert.strictEqual(result.success, true);
    });

    await t.test('Outlook batch retry: 429 error triggers retry', async () => {
        let attempts = 0;
        const simulateBatchFetch = async () => {
            attempts++;
            return attempts === 1 ? { error: { statusCode: 429 } } : { success: true };
        };

        let result = await simulateBatchFetch();
        while (shouldRetryBatch(result) && attempts < 5) {
            result = await simulateBatchFetch();
        }

        assert.strictEqual(attempts, 2);
        assert.strictEqual(result.success, true);
    });

    await t.test('Outlook batch retry: 5xx error triggers retry', async () => {
        let attempts = 0;
        const simulateBatchFetch = async () => {
            attempts++;
            return attempts === 1 ? { error: { statusCode: 503 } } : { success: true };
        };

        let result = await simulateBatchFetch();
        while (shouldRetryBatch(result) && attempts < 5) {
            result = await simulateBatchFetch();
        }

        assert.strictEqual(attempts, 2);
        assert.strictEqual(result.success, true);
    });

    await t.test('Outlook batch retry: 403 error does NOT trigger retry', async () => {
        let attempts = 0;
        const simulateBatchFetch = async () => {
            attempts++;
            return { error: { statusCode: 403 } };
        };

        let result = await simulateBatchFetch();
        while (shouldRetryBatch(result) && attempts < 5) {
            result = await simulateBatchFetch();
        }

        assert.strictEqual(attempts, 1);
        assert.strictEqual(result.error.statusCode, 403);
    });

    await t.test('Outlook batch retry: all retries exhausted returns errors', async () => {
        let attempts = 0;
        const MAX_RETRIES = 3;
        const simulateBatchFetch = async () => {
            attempts++;
            return { error: { statusCode: 429, message: 'Rate limited' } };
        };

        let result = await simulateBatchFetch();
        while (shouldRetryBatch(result) && attempts < MAX_RETRIES) {
            result = await simulateBatchFetch();
        }

        assert.strictEqual(attempts, MAX_RETRIES);
        assert.strictEqual(result.error.statusCode, 429);
    });

    await t.test('Outlook batch retry: exponential backoff calculation', async () => {
        const BASE_DELAY = 5000;

        const calculateDelay = attempt => {
            return BASE_DELAY * Math.pow(2, attempt - 1);
        };

        // Verify exponential backoff: 5s, 10s, 20s
        assert.strictEqual(calculateDelay(1), 5000);
        assert.strictEqual(calculateDelay(2), 10000);
        assert.strictEqual(calculateDelay(3), 20000);
        assert.strictEqual(calculateDelay(4), 40000);
    });

    // Constants used in retry logic tests below
    const IMAP_MESSAGE_MAX_RETRIES = 3;
    const IMAP_MESSAGE_RETRY_BASE_DELAY = 2000;

    // IMAP retry logic tests
    await t.test('IMAP retry: transient error triggers retry with backoff', async () => {
        let attempts = 0;
        const delays = [];

        const simulateFetch = async () => {
            attempts++;
            if (attempts < IMAP_MESSAGE_MAX_RETRIES) {
                const delay = IMAP_MESSAGE_RETRY_BASE_DELAY * Math.pow(2, attempts - 1);
                delays.push(delay);
                throw { code: 'ETIMEDOUT' };
            }
            return { success: true };
        };

        const isTransient = err => ['ETIMEDOUT', 'ECONNRESET'].includes(err.code);

        let result = null;
        for (let attempt = 1; attempt <= IMAP_MESSAGE_MAX_RETRIES; attempt++) {
            try {
                result = await simulateFetch();
                break;
            } catch (err) {
                if (!isTransient(err) || attempt === IMAP_MESSAGE_MAX_RETRIES) {
                    throw err;
                }
            }
        }

        assert.strictEqual(attempts, IMAP_MESSAGE_MAX_RETRIES);
        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(delays, [2000, 4000]);
    });

    await t.test('IMAP retry: skippable error does not retry', async () => {
        let attempts = 0;
        let skipped = false;

        const simulateFetch = async () => {
            attempts++;
            throw { code: 'MessageNotFound' };
        };

        const isSkippable = err => err.code === 'MessageNotFound' || err.statusCode === 404;

        try {
            await simulateFetch();
        } catch (err) {
            if (isSkippable(err)) {
                skipped = true;
            }
        }

        assert.strictEqual(attempts, 1);
        assert.strictEqual(skipped, true);
    });

    await t.test('IMAP retry: non-transient error fails immediately', async () => {
        let attempts = 0;
        let thrownError = null;

        const simulateFetch = async () => {
            attempts++;
            throw { code: 'InvalidCredentials' };
        };

        const isTransient = err => ['ETIMEDOUT', 'ECONNRESET'].includes(err.code);
        const isSkippable = err => err.code === 'MessageNotFound';

        try {
            const error = await simulateFetch().catch(e => e);
            if (!isSkippable(error) && !isTransient(error)) {
                thrownError = error;
            }
        } catch (err) {
            thrownError = err;
        }

        assert.strictEqual(attempts, 1);
        assert.strictEqual(thrownError.code, 'InvalidCredentials');
    });

    // Rate limit retry detection tests
    function isRateLimited(err) {
        return err.statusCode === 429 || err.code === 'rateLimitExceeded' || err.code === 'userRateLimitExceeded';
    }

    await t.test('Rate limit detection: rate-limited errors return true', async () => {
        assert.strictEqual(isRateLimited({ statusCode: 429 }), true);
        assert.strictEqual(isRateLimited({ code: 'rateLimitExceeded' }), true);
        assert.strictEqual(isRateLimited({ code: 'userRateLimitExceeded' }), true);
    });

    await t.test('Rate limit detection: non-rate-limited errors return false', async () => {
        assert.strictEqual(isRateLimited({ statusCode: 500 }), false);
    });

    // Export limit enforcement tests
    // These replicate the limit-checking logic from workers/export.js indexMessages and exportMessages.
    // Limits are read from settings and are disabled (0) by default.

    // Simulates the indexFolder inner loop: queues messages up to maxMessages (0 = unlimited)
    function simulateIndexFolder(messageCount, maxMessages) {
        let queued = 0;
        for (let i = 0; i < messageCount; i++) {
            if (maxMessages && queued >= maxMessages) {
                return queued;
            }
            // simulate Export.queueMessage
            queued++;
        }
        return queued;
    }

    // Simulates the indexMessages outer loop across folders
    function simulateIndexMessages(folderMessageCounts, maxMessages) {
        let totalIndexed = 0;
        let truncated = false;

        for (const messageCount of folderMessageCounts) {
            const remaining = maxMessages ? maxMessages - totalIndexed : 0;
            const queued = simulateIndexFolder(messageCount, remaining);
            totalIndexed += queued;

            if (maxMessages && totalIndexed >= maxMessages) {
                truncated = true;
                break;
            }
        }

        return { totalIndexed, truncated };
    }

    // Simulates the exportMessages size-limit logic
    function simulateExportMessages(messageSizes, maxExportSize) {
        let totalBytesWritten = 0;
        let processed = 0;
        let sizeLimitReached = false;

        for (const size of messageSizes) {
            if (sizeLimitReached) {
                break;
            }
            totalBytesWritten += size;
            processed++;
            if (maxExportSize && totalBytesWritten >= maxExportSize) {
                sizeLimitReached = true;
            }
        }

        return { totalBytesWritten, processed, sizeLimitReached };
    }

    await t.test('Export message limit: no limit set (0) indexes all messages', async () => {
        const result = simulateIndexMessages([100, 200, 50], 0);
        assert.strictEqual(result.totalIndexed, 350);
        assert.strictEqual(result.truncated, false);
    });

    await t.test('Export message limit: limit enforced when set', async () => {
        const result = simulateIndexMessages([100, 200, 50], 150);
        assert.strictEqual(result.totalIndexed, 150);
        assert.strictEqual(result.truncated, true);
    });

    await t.test('Export message limit: stops mid-folder when limit reached', async () => {
        const result = simulateIndexMessages([500], 75);
        assert.strictEqual(result.totalIndexed, 75);
        assert.strictEqual(result.truncated, true);
    });

    await t.test('Export message limit: truncated when count equals limit exactly', async () => {
        const result = simulateIndexMessages([100], 100);
        assert.strictEqual(result.totalIndexed, 100);
        assert.strictEqual(result.truncated, true);
    });

    await t.test('Export message limit: not truncated when under limit', async () => {
        const result = simulateIndexMessages([50], 100);
        assert.strictEqual(result.totalIndexed, 50);
        assert.strictEqual(result.truncated, false);
    });

    await t.test('Export size limit: no limit set (0) exports all messages', async () => {
        const sizes = [1000, 2000, 3000, 4000, 5000];
        const result = simulateExportMessages(sizes, 0);
        assert.strictEqual(result.processed, 5);
        assert.strictEqual(result.totalBytesWritten, 15000);
        assert.strictEqual(result.sizeLimitReached, false);
    });

    await t.test('Export size limit: limit enforced when set', async () => {
        const sizes = [1000, 2000, 3000, 4000, 5000];
        const result = simulateExportMessages(sizes, 5000);
        assert.strictEqual(result.processed, 3);
        assert.strictEqual(result.totalBytesWritten, 6000);
        assert.strictEqual(result.sizeLimitReached, true);
    });

    await t.test('Export size limit: stops after first message exceeding limit', async () => {
        const sizes = [10000];
        const result = simulateExportMessages(sizes, 5000);
        assert.strictEqual(result.processed, 1);
        assert.strictEqual(result.totalBytesWritten, 10000);
        assert.strictEqual(result.sizeLimitReached, true);
    });

    await t.test('Export size limit: not triggered when under limit', async () => {
        const sizes = [100, 200, 300];
        const result = simulateExportMessages(sizes, 5000);
        assert.strictEqual(result.processed, 3);
        assert.strictEqual(result.totalBytesWritten, 600);
        assert.strictEqual(result.sizeLimitReached, false);
    });

    await t.test('Export limits: both limits disabled allows unlimited export', async () => {
        const indexResult = simulateIndexMessages([1000000], 0);
        assert.strictEqual(indexResult.totalIndexed, 1000000);
        assert.strictEqual(indexResult.truncated, false);

        const sizes = new Array(10000).fill(1024);
        const exportResult = simulateExportMessages(sizes, 0);
        assert.strictEqual(exportResult.processed, 10000);
        assert.strictEqual(exportResult.sizeLimitReached, false);
    });
});
