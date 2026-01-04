'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_tokens';

const tokens = require('../lib/tokens');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

test('Token management tests', async t => {
    // Track created tokens for cleanup
    const createdTokens = [];

    t.after(async () => {
        // Cleanup test tokens
        for (const token of createdTokens) {
            try {
                await tokens.delete(token);
            } catch (err) {
                // Ignore cleanup errors
            }
        }

        // Clean up any remaining test keys
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length > 0) {
            await redis.del(keys);
        }

        redis.quit();

        // Force exit after cleanup to prevent hanging on any remaining connections
        setTimeout(() => process.exit(), 1000).unref();
    });

    // Session token tests
    await t.test('getSessionToken() generates valid format', async () => {
        const sessionId = 'test-session-123';
        const account = 'test-account';
        const ttl = 3600;

        const token = await tokens.getSessionToken(sessionId, account, ttl);

        assert.ok(token.startsWith('sess_'), 'Token should start with sess_ prefix');
        assert.strictEqual(token.length, 5 + 64, 'Token should be prefix (5) + 64 hex chars');

        const hexPart = token.substring(5);
        assert.ok(/^[0-9a-f]{64}$/i.test(hexPart), 'Hex part should be valid hex');
    });

    await t.test('validateSessionToken() accepts valid token', async () => {
        const sessionId = 'validate-session-123';
        const account = 'validate-account';
        const ttl = 3600;

        const token = await tokens.getSessionToken(sessionId, account, ttl);
        const isValid = await tokens.validateSessionToken(sessionId, token, account, ttl);

        assert.strictEqual(isValid, true);
    });

    await t.test('validateSessionToken() rejects wrong sessionId', async () => {
        const sessionId = 'correct-session';
        const account = 'test-account';
        const ttl = 3600;

        const token = await tokens.getSessionToken(sessionId, account, ttl);
        const isValid = await tokens.validateSessionToken('wrong-session', token, account, ttl);

        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects wrong account', async () => {
        const sessionId = 'session-for-account-test';
        const account = 'correct-account';
        const ttl = 3600;

        const token = await tokens.getSessionToken(sessionId, account, ttl);
        const isValid = await tokens.validateSessionToken(sessionId, token, 'wrong-account', ttl);

        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects invalid token format', async () => {
        const isValid = await tokens.validateSessionToken('session', 'invalid-token', 'account', 3600);
        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects null token', async () => {
        const isValid = await tokens.validateSessionToken('session', null, 'account', 3600);
        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects token with wrong prefix', async () => {
        const isValid = await tokens.validateSessionToken('session', 'wrong_' + 'a'.repeat(64), 'account', 3600);
        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects token with invalid hex', async () => {
        const isValid = await tokens.validateSessionToken('session', 'sess_' + 'g'.repeat(64), 'account', 3600);
        assert.strictEqual(isValid, false);
    });

    await t.test('validateSessionToken() rejects token with wrong length', async () => {
        const isValid = await tokens.validateSessionToken('session', 'sess_' + 'a'.repeat(32), 'account', 3600);
        assert.strictEqual(isValid, false);
    });

    // Access token tests
    await t.test('provision() creates token with correct format', async () => {
        const token = await tokens.provision({
            account: 'provision-test',
            description: 'Test token',
            nolog: true
        });

        createdTokens.push(token);

        assert.strictEqual(token.length, 64, 'Token should be 64 hex chars');
        assert.ok(/^[0-9a-f]{64}$/i.test(token), 'Token should be valid hex');
    });

    await t.test('provision() stores metadata correctly', async () => {
        const opts = {
            account: 'metadata-test',
            description: 'Test description',
            ip: '192.168.1.1',
            remoteAddress: '10.0.0.1',
            scopes: ['read', 'write'],
            metadata: { custom: 'data' },
            nolog: true
        };

        const token = await tokens.provision(opts);
        createdTokens.push(token);

        const tokenData = await tokens.get(token);

        assert.strictEqual(tokenData.account, opts.account);
        assert.strictEqual(tokenData.description, opts.description);
        assert.strictEqual(tokenData.ip, opts.ip);
        assert.strictEqual(tokenData.remoteAddress, opts.remoteAddress);
        assert.deepStrictEqual(tokenData.scopes, opts.scopes);
        assert.deepStrictEqual(tokenData.metadata, opts.metadata);
        assert.ok(tokenData.created instanceof Date);
    });

    await t.test('provision() creates root token when no account specified', async () => {
        const token = await tokens.provision({
            description: 'Root token',
            nolog: true
        });

        createdTokens.push(token);

        const tokenData = await tokens.get(token);
        assert.strictEqual(tokenData.account, undefined);
    });

    await t.test('get() retrieves token data correctly', async () => {
        const token = await tokens.provision({
            account: 'get-test',
            description: 'Get test token',
            nolog: true
        });

        createdTokens.push(token);

        const tokenData = await tokens.get(token);

        assert.ok(tokenData.id, 'Should have id (hashed token)');
        assert.strictEqual(tokenData.account, 'get-test');
        assert.strictEqual(tokenData.description, 'Get test token');
    });

    await t.test('get() throws for invalid token format', async () => {
        await assert.rejects(async () => tokens.get('invalid'), err => {
            assert.strictEqual(err.code, 'InvalidToken');
            return true;
        });
    });

    await t.test('get() throws for unknown token', async () => {
        const fakeToken = 'a'.repeat(64);
        await assert.rejects(async () => tokens.get(fakeToken), err => {
            assert.strictEqual(err.code, 'UnknownToken');
            return true;
        });
    });

    await t.test('get() can retrieve using hashed token', async () => {
        const token = await tokens.provision({
            account: 'hashed-get-test',
            nolog: true
        });

        createdTokens.push(token);

        // Get the hashed version
        const tokenData1 = await tokens.get(token);
        const hashedToken = tokenData1.id;

        // Retrieve using hashed token
        const tokenData2 = await tokens.get(hashedToken, true);
        assert.strictEqual(tokenData2.account, 'hashed-get-test');
    });

    await t.test('delete() removes token', async () => {
        const token = await tokens.provision({
            account: 'delete-test',
            nolog: true
        });

        // Verify exists
        const tokenData = await tokens.get(token);
        assert.ok(tokenData);

        // Delete
        const deleted = await tokens.delete(token);
        assert.strictEqual(deleted, true);

        // Verify gone
        await assert.rejects(async () => tokens.get(token), err => {
            assert.strictEqual(err.code, 'UnknownToken');
            return true;
        });
    });

    await t.test('delete() returns false for non-existent token', async () => {
        const fakeToken = 'b'.repeat(64);
        const deleted = await tokens.delete(fakeToken);
        assert.strictEqual(deleted, false);
    });

    await t.test('delete() throws for invalid format', async () => {
        await assert.rejects(async () => tokens.delete('short'), err => {
            assert.strictEqual(err.code, 'InvalidToken');
            return true;
        });
    });

    await t.test('list() returns account tokens with pagination', async () => {
        const account = 'list-test-account';

        // Create multiple tokens
        const token1 = await tokens.provision({ account, description: 'Token 1', nolog: true });
        const token2 = await tokens.provision({ account, description: 'Token 2', nolog: true });
        const token3 = await tokens.provision({ account, description: 'Token 3', nolog: true });

        createdTokens.push(token1, token2, token3);

        // List all
        const result = await tokens.list(account, 0, 10);

        assert.strictEqual(result.account, account);
        assert.strictEqual(result.total, 3);
        assert.strictEqual(result.tokens.length, 3);
        assert.ok(result.tokens.every(t => t.id && t.created));
    });

    await t.test('list() pagination works correctly', async () => {
        const account = 'pagination-test';

        // Create 5 tokens
        for (let i = 0; i < 5; i++) {
            const token = await tokens.provision({ account, description: `Token ${i}`, nolog: true });
            createdTokens.push(token);
        }

        // Get page 0 with size 2
        const page0 = await tokens.list(account, 0, 2);
        assert.strictEqual(page0.total, 5);
        assert.strictEqual(page0.pages, 3);
        assert.strictEqual(page0.page, 0);
        assert.strictEqual(page0.tokens.length, 2);

        // Get page 1
        const page1 = await tokens.list(account, 1, 2);
        assert.strictEqual(page1.page, 1);
        assert.strictEqual(page1.tokens.length, 2);

        // Get last page
        const page2 = await tokens.list(account, 2, 2);
        assert.strictEqual(page2.page, 2);
        assert.strictEqual(page2.tokens.length, 1);
    });

    await t.test('list() returns empty for non-existent account', async () => {
        const result = await tokens.list('non-existent-account', 0, 10);

        assert.strictEqual(result.total, 0);
        assert.strictEqual(result.tokens.length, 0);
    });

    await t.test('list() without account lists root tokens', async () => {
        const token = await tokens.provision({ description: 'Root list test', nolog: true });
        createdTokens.push(token);

        const result = await tokens.list(null, 0, 100);

        assert.strictEqual(result.account, null);
        assert.ok(result.total >= 1);
    });

    await t.test('getRawData() returns token data', async () => {
        const token = await tokens.provision({
            account: 'raw-data-test',
            description: 'Raw data test',
            nolog: true
        });

        createdTokens.push(token);

        const rawData = await tokens.getRawData(token);

        assert.ok(rawData);
        assert.strictEqual(rawData.account, 'raw-data-test');
    });

    await t.test('getRawData() returns false for unknown token', async () => {
        const result = await tokens.getRawData('c'.repeat(64));
        assert.strictEqual(result, false);
    });

    await t.test('setRawData() creates token from raw data', async () => {
        const hashedToken = 'd'.repeat(64);
        const tokenData = {
            id: hashedToken,
            account: 'set-raw-test',
            description: 'Set raw test'
        };

        const result = await tokens.setRawData(tokenData);

        assert.ok(result);
        assert.strictEqual(result.account, 'set-raw-test');

        // Verify it was stored
        const retrieved = await tokens.get(hashedToken, true);
        assert.strictEqual(retrieved.account, 'set-raw-test');

        // Cleanup
        await redis.hdel(`${REDIS_PREFIX}tokens`, hashedToken);
        await redis.hdel(`${REDIS_PREFIX}tokens:access`, hashedToken);
        await redis.srem(`${REDIS_PREFIX}iat:set-raw-test`, hashedToken);
    });

    await t.test('setRawData() returns false if token already exists', async () => {
        const token = await tokens.provision({
            account: 'existing-token-test',
            nolog: true
        });

        createdTokens.push(token);

        const tokenData = await tokens.get(token);

        // Try to set raw data with existing hash
        const result = await tokens.setRawData({
            id: tokenData.id,
            account: 'different-account'
        });

        assert.strictEqual(result, false);
    });

    await t.test('token hash is stored in Redis, not plaintext', async () => {
        const token = await tokens.provision({
            account: 'hash-storage-test',
            nolog: true
        });

        createdTokens.push(token);

        // Get all keys
        const keys = await redis.hkeys(`${REDIS_PREFIX}tokens`);

        // None of the keys should match the raw token
        assert.ok(!keys.includes(token), 'Raw token should not be stored');

        // Hash of token should be stored
        const expectedHash = crypto.createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex');
        assert.ok(keys.includes(expectedHash), 'Hashed token should be stored');
    });
});
