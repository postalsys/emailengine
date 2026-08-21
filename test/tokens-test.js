'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_tokens';

const tokens = require('../lib/tokens');
const tokenAuditLog = require('../lib/token-audit-log');
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
        await assert.rejects(
            async () => tokens.get('invalid'),
            err => {
                assert.strictEqual(err.code, 'InvalidToken');
                return true;
            }
        );
    });

    await t.test('get() throws for unknown token', async () => {
        const fakeToken = 'a'.repeat(64);
        await assert.rejects(
            async () => tokens.get(fakeToken),
            err => {
                assert.strictEqual(err.code, 'UnknownToken');
                return true;
            }
        );
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
        await assert.rejects(
            async () => tokens.get(token),
            err => {
                assert.strictEqual(err.code, 'UnknownToken');
                return true;
            }
        );
    });

    await t.test('delete() returns false for non-existent token', async () => {
        const fakeToken = 'b'.repeat(64);
        const deleted = await tokens.delete(fakeToken);
        assert.strictEqual(deleted, false);
    });

    await t.test('delete() throws for invalid format', async () => {
        await assert.rejects(
            async () => tokens.delete('short'),
            err => {
                assert.strictEqual(err.code, 'InvalidToken');
                return true;
            }
        );
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

    await t.test('list() with a scope filter keeps only tokens naming that scope', async () => {
        const account = 'scope-filter-test';

        const mcpToken = await tokens.provision({ account, description: 'Scoped agent', scopes: ['mcp'], nolog: true });
        const apiToken = await tokens.provision({ account, description: 'Plain API', scopes: ['api'], nolog: true });
        // Would serve the MCP surface, but was not minted for it - the filter answers
        // "which tokens were minted for this scope", so it must not match
        const wideToken = await tokens.provision({ account, description: 'All scopes', scopes: ['*'], nolog: true });
        createdTokens.push(mcpToken, apiToken, wideToken);

        const result = await tokens.list(account, 0, 10, null, { scope: 'mcp' });

        assert.strictEqual(result.total, 1);
        assert.strictEqual(result.pages, 1, 'pages must count the matches, not the unfiltered list');
        assert.strictEqual(result.tokens.length, 1);
        assert.strictEqual(result.tokens[0].description, 'Scoped agent');
        assert.deepStrictEqual(result.tokens[0].scopes, ['mcp']);
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
    await t.test('provision() stores an expiry and get() honors it', async () => {
        const token = await tokens.provision({
            description: 'expiring token',
            scopes: ['api'],
            expires: Date.now() + 60000,
            nolog: true
        });

        createdTokens.push(token);

        const tokenData = await tokens.get(token);
        assert.ok(tokenData.expires, 'expiry is stored on the token record');
        assert.ok(tokenData.expires > Date.now());
    });

    await t.test('get() rejects an expired token and cleans it up', async () => {
        const token = await tokens.provision({
            description: 'already expired',
            scopes: ['api'],
            expires: Date.now() - 1000,
            nolog: true
        });

        await assert.rejects(
            () => tokens.get(token),
            err => err.code === 'ExpiredToken'
        );

        // the record is removed rather than left to accumulate; the cleanup is fired
        // without awaiting inside get(), so give it a turn to land
        await new Promise(resolve => setTimeout(resolve, 50));

        const hashedToken = crypto.createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex');
        const stored = await redis.hget(`${REDIS_PREFIX}tokens`, hashedToken);
        assert.equal(stored, null, 'expired token is dropped from the token hash');
    });

    await t.test('a token with no expiry never expires', async () => {
        const token = await tokens.provision({
            description: 'permanent token',
            nolog: true
        });

        createdTokens.push(token);

        const tokenData = await tokens.get(token);
        assert.equal(typeof tokenData.expires, 'undefined');
    });

    await t.test('delete() can still remove an expired token', async () => {
        const token = await tokens.provision({
            description: 'expired but deletable',
            expires: Date.now() - 1000,
            nolog: true
        });

        // get() would reject it, but delete() resolves it with allowExpired
        assert.equal(await tokens.delete(token), true);
    });
    await t.test('provision() rejects a malformed expiry instead of dropping it', async () => {
        // Number('soon') is NaN, and NaN is falsy at the expiry check in get() - coercing
        // would silently mean "never expires" on the field that bounds a credential
        await assert.rejects(
            () => tokens.provision({ description: 'bad expiry', expires: 'soon', nolog: true }),
            err => err.code === 'InvalidExpiry'
        );
    });

    await t.test('list() exposes the expiry as a date', async () => {
        const expires = Date.now() + 60000;
        const token = await tokens.provision({
            account: 'expiry-list-test',
            description: 'listed expiring token',
            expires,
            nolog: true
        });

        createdTokens.push(token);

        const listed = await tokens.list('expiry-list-test', 0, 20);
        const entry = listed.tokens.find(item => item.description === 'listed expiring token');

        assert.ok(entry);
        assert.ok(entry.expires instanceof Date, 'expiry is a Date, matching created');
        assert.equal(entry.expires.getTime(), expires);
    });
    await t.test('list() drops and reaps an expired token', async () => {
        // The reap in get() only fires when someone presents the token, so a token that is
        // minted and never used was listed forever even though it could not authenticate -
        // exactly what a temporary API-reference token does when the tab is just closed.
        const token = await tokens.provision({
            description: 'expired and never used',
            scopes: ['api'],
            expires: Date.now() - 1000,
            nolog: true
        });

        const listed = await tokens.list(false, 0, 50);
        assert.ok(!listed.tokens.some(entry => entry.description === 'expired and never used'), 'an expired token must not be listed');

        // the record is actually removed, not just filtered out of the response
        await new Promise(resolve => setTimeout(resolve, 50));
        const hashedToken = crypto.createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex');
        assert.equal(await redis.hget(`${REDIS_PREFIX}tokens`, hashedToken), null);
        assert.equal(await redis.sismember(`${REDIS_PREFIX}iat`, hashedToken), 0);
    });

    await t.test('list() keeps a token that has not expired yet', async () => {
        const token = await tokens.provision({
            description: 'still valid',
            expires: Date.now() + 60000,
            nolog: true
        });

        createdTokens.push(token);

        const listed = await tokens.list(false, 0, 50);
        assert.ok(listed.tokens.some(entry => entry.description === 'still valid'));
    });

    await t.test('list() reports a page count that describes the total it returned', async () => {
        // `pages` used to be computed before the loop that reaps expired tokens, while `total` was
        // decremented inside it - so one response could claim more pages than its own total covers,
        // and a caller comparing the two could not tell a complete listing from a truncated one.
        const account = 'expired-paging-test';
        for (let i = 0; i < 3; i++) {
            await tokens.provision({ account, description: `expired ${i}`, expires: Date.now() - 1000, nolog: true });
        }

        // Page 0 of 3 at one per page: the single entry it slices is expired, so it is reaped and
        // dropped, leaving two tokens still to list and therefore two pages. Before this, `pages`
        // was derived before the reap and came back as 3.
        const page0 = await tokens.list(account, 0, 1);

        assert.equal(page0.tokens.length, 0, 'an expired token must not be listed');
        assert.equal(page0.total, 2);
        assert.equal(page0.pages, 2, 'pages and total in one response must be two views of one number');
    });

    await t.test('getAccess() reports the last use of a token', async () => {
        const token = await tokens.provision({ description: 'access probe', nolog: true });
        createdTokens.push(token);

        const id = tokens.tokenId(token);

        const fresh = await tokens.getAccess(id);
        assert.equal(fresh.time, null, 'a token that has never been used has no last-use time');
        assert.equal(fresh.ip, null);

        await tokens.get(token, false, { log: true, remoteAddress: '10.1.2.3' });

        const used = await tokens.getAccess(id);
        assert.ok(used.time instanceof Date, 'last use is a Date, matching the listing');
        assert.equal(used.ip, '10.1.2.3');
    });

    await t.test('deleteForAccount() takes an account credentials with it', async () => {
        // Deleting an account used to unlink only its token index, leaving credentials that still
        // authenticated behind it
        const account = 'token-revoke-test';
        const bound = await tokens.provision({ account, description: 'bound to a doomed account', nolog: true });
        const unrelated = await tokens.provision({ description: 'unrelated root token', nolog: true });
        createdTokens.push(unrelated);

        const boundId = tokens.tokenId(bound);
        // Stands in for an audit log without depending on the setting that writes one: what matters
        // is that the key named after the token id goes too, since nothing else would collect it
        await redis.set(tokenAuditLog.logKey(boundId), 'placeholder');

        assert.equal(await tokens.deleteForAccount(account), 1);

        assert.equal(await redis.hget(`${REDIS_PREFIX}tokens`, boundId), null, 'the record itself is gone, not just the index');
        assert.equal(await redis.hget(`${REDIS_PREFIX}tokens:access`, boundId), null);
        assert.equal(await redis.exists(tokenAuditLog.logKey(boundId)), 0);
        assert.equal(await redis.exists(`${REDIS_PREFIX}iat:${account}`), 0);

        await assert.rejects(() => tokens.get(bound), /Unknown token/, 'the token no longer authenticates');
        assert.ok(await tokens.get(unrelated), 'a token bound to nothing is untouched');

        assert.equal(await tokens.deleteForAccount('account-that-never-existed'), 0);
    });

    await t.test('list() reads past one batch and filters while it reads', async () => {
        // Records are read in batches and non-matches are dropped as they arrive, so a search across
        // an instance-sized listing never holds every record at once. Sized off the batch itself, so
        // that raising it cannot leave this test passing while no longer crossing a boundary: the
        // matching description below sits past the first batch, so a broken loop returns nothing.
        const account = 'batched-list-test';
        const count = tokens.TOKEN_BATCH_SIZE + 100;

        await Promise.all(Array.from({ length: count }, (v, i) => tokens.provision({ account, description: `batched ${i}`, nolog: true })));

        const all = await tokens.list(account, 0, count);
        assert.equal(all.total, count);
        assert.equal(all.tokens.length, count, 'every record is read, including the ones past the first batch');
        assert.ok(
            all.tokens.every(entry => entry.access && 'time' in entry.access),
            'the last-use record is attached to each listed token, though it is read separately'
        );

        const last = `batched ${count - 1}`;
        const filtered = await tokens.list(account, 0, 20, last);
        assert.equal(filtered.total, 1, 'the filter counts matches, not records read');
        assert.equal(filtered.tokens[0].description, last);

        assert.equal(await tokens.deleteForAccount(account), count);
    });

    await t.test('list() treats a whitespace-only query as no query', async () => {
        // The two halves used to disagree: `!query` took a single space for a real search term while
        // the filter trimmed it away and matched everything. A search box holding one space then put
        // the listing on the read-every-record path with nothing filtered out of it - the results
        // came back identical, so the only thing that told the two apart was the work done.
        const account = 'blank-query-test';
        const count = 12;
        const pageSize = 2;
        await Promise.all(Array.from({ length: count }, (v, i) => tokens.provision({ account, description: `blank ${i}`, nolog: true })));

        const recordReads = [];
        const hmgetBuffer = redis.hmgetBuffer.bind(redis);
        redis.hmgetBuffer = (key, ids) => {
            if (key === `${REDIS_PREFIX}tokens`) {
                recordReads.push(ids.length);
            }
            return hmgetBuffer(key, ids);
        };

        let blank;
        let none;
        try {
            blank = await tokens.list(account, 0, pageSize, '   ');
            const blankReads = recordReads.splice(0);
            none = await tokens.list(account, 0, pageSize, null);

            assert.deepEqual(blankReads, [pageSize], 'a whitespace-only query must read one page, not every record on the instance');
            assert.deepEqual(recordReads, [pageSize]);
        } finally {
            redis.hmgetBuffer = hmgetBuffer;
        }

        assert.deepEqual(
            { total: blank.total, pages: blank.pages, listed: blank.tokens.length },
            { total: none.total, pages: none.pages, listed: none.tokens.length },
            'a whitespace-only query must page exactly like no query at all'
        );

        assert.equal(await tokens.deleteForAccount(account), count);
    });

    await t.test('list({all}) covers bound and unbound tokens alike', async () => {
        // What GET /v1/tokens answers by default. "Which credentials exist on this instance" needed
        // one request per account before it, because root tokens and each account's lived behind
        // separate endpoints.
        const account = 'all-mode-test';
        const bound = await tokens.provision({ account, description: 'all-mode bound', nolog: true });
        const unbound = await tokens.provision({ description: 'all-mode unbound', nolog: true });
        createdTokens.push(bound, unbound);

        const rootOnly = await tokens.list(false, 0, 1000);
        assert.ok(!rootOnly.tokens.some(entry => entry.description === 'all-mode bound'), 'the root listing stays root-only');

        const all = await tokens.list(false, 0, 1000, null, { all: true });
        const listed = new Map(all.tokens.map(entry => [entry.description, entry]));

        assert.ok(listed.has('all-mode bound'));
        assert.ok(listed.has('all-mode unbound'));
        // One shape for both, so a client has a single type for a token
        assert.equal(listed.get('all-mode bound').account, account);
        assert.equal(listed.get('all-mode unbound').account, null);
    });
});
