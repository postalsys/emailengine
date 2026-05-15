'use strict';

require('dotenv').config({ quiet: true });

const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert').strict;
const Redis = require('ioredis');
const config = require('@zone-eu/wild-config');

const { GmailOauth } = require('../lib/oauth/gmail');
const oauth2AppsModule = require('../lib/oauth2-apps');
const { Account } = require('../lib/account');
const { REDIS_PREFIX } = require('../lib/consts');

// Skip the entire suite if Gmail test credentials aren't provisioned for this environment.
const hasGmailCredentials = !!(
    process.env.GMAIL_API_CLIENT_ID &&
    process.env.GMAIL_API_CLIENT_SECRET &&
    process.env.GMAIL_API_ACCOUNT_EMAIL_1 &&
    process.env.GMAIL_API_ACCOUNT_REFRESH_1
);

const TEST_GMAIL_APP = 'test-revoke-gmail-app';
const TEST_GMAIL_SERVICE_APP = 'test-revoke-gmail-service-app';

function makeStubLogger() {
    const noop = () => {};
    return { trace: noop, debug: noop, info: noop, warn: noop, error: noop, fatal: noop };
}

test('OAuth2 revoke on account delete', { skip: hasGmailCredentials ? false : 'Gmail test credentials not set in env' }, async t => {
    const redis = new Redis(config.dbs.redis);

    // Local capture server impersonates the OAuth2 revoke endpoint so the test does not actually
    // contact Google and invalidate the shared test refresh token.
    const captureState = {
        requests: [],
        responseStatus: 200,
        responseBody: '{}'
    };

    const captureServer = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            captureState.requests.push({
                method: req.method,
                url: req.url,
                contentType: req.headers['content-type'],
                body: Buffer.concat(chunks).toString()
            });
            res.writeHead(captureState.responseStatus, { 'Content-Type': 'application/json' });
            res.end(captureState.responseBody);
        });
    });

    await new Promise(resolve => captureServer.listen(0, '127.0.0.1', resolve));
    const { port: capturePort } = captureServer.address();
    const captureRevokeUrl = `http://127.0.0.1:${capturePort}/revoke`;

    // Override oauth2Apps.get/getClient for our synthetic provider ids so the real Gmail OAuth2 client
    // is constructed with the env-provided credentials but its revokeUrl points at the local capture
    // server. Other provider ids fall through to the original implementations.
    const originalGet = oauth2AppsModule.oauth2Apps.get.bind(oauth2AppsModule.oauth2Apps);
    const originalGetClient = oauth2AppsModule.oauth2Apps.getClient.bind(oauth2AppsModule.oauth2Apps);

    oauth2AppsModule.oauth2Apps.get = async id => {
        if (id === TEST_GMAIL_APP) {
            return { id, provider: 'gmail', enabled: true, name: 'Test Gmail App' };
        }
        if (id === TEST_GMAIL_SERVICE_APP) {
            return { id, provider: 'gmailService', enabled: true, name: 'Test Gmail Service App' };
        }
        return originalGet(id);
    };

    oauth2AppsModule.oauth2Apps.getClient = async (provider, opts) => {
        if (provider === TEST_GMAIL_APP) {
            const client = new GmailOauth({
                clientId: process.env.GMAIL_API_CLIENT_ID,
                clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
                redirectUrl: 'http://127.0.0.1:7003/oauth',
                scopes: ['https://www.googleapis.com/auth/gmail.modify'],
                googleProjectId: process.env.GMAIL_API_PROJECT_ID,
                setFlag: async () => {},
                logger: opts && opts.logger
            });
            client.revokeUrl = captureRevokeUrl;
            return client;
        }

        if (provider === TEST_GMAIL_SERVICE_APP) {
            const client = new GmailOauth({
                authMethod: 'serviceKey',
                serviceClient: process.env.GMAIL_API_SERVICE_CLIENT || 'stub-service-client',
                serviceClientEmail: process.env.GMAIL_API_SERVICE_EMAIL || 'stub-sa@example.com',
                serviceKey: process.env.GMAIL_API_SERVICE_KEY,
                scopes: ['https://www.googleapis.com/auth/gmail.modify'],
                googleProjectId: process.env.GMAIL_API_PROJECT_ID,
                setFlag: async () => {},
                logger: opts && opts.logger
            });
            client.revokeUrl = captureRevokeUrl;
            return client;
        }

        return originalGetClient(provider, opts);
    };

    t.after(async () => {
        oauth2AppsModule.oauth2Apps.get = originalGet;
        oauth2AppsModule.oauth2Apps.getClient = originalGetClient;
        await new Promise(resolve => captureServer.close(resolve));
        await redis.quit();
        setTimeout(() => process.exit(), 1000).unref();
    });

    function buildAccount(accountId) {
        return new Account({
            redis,
            account: accountId,
            documentsQueue: { add: async () => {} },
            secret: undefined,
            call: async () => 0,
            logger: makeStubLogger()
        });
    }

    async function seedAccount(accountId, accountData) {
        const account = buildAccount(accountId);
        const serialized = account.serializeAccountData(Object.assign({ account: accountId }, accountData));
        await redis.hmset(account.getAccountKey(), serialized);
        await redis.sadd(`${REDIS_PREFIX}ia:accounts`, accountId);
        return account;
    }

    async function cleanupAccount(accountId) {
        await redis.del(`${REDIS_PREFIX}iad:${accountId}`);
        await redis.srem(`${REDIS_PREFIX}ia:accounts`, accountId);
    }

    function resetCapture() {
        captureState.requests = [];
        captureState.responseStatus = 200;
        captureState.responseBody = '{}';
    }

    await t.test('delete with revoke=true revokes Gmail grant using refresh token', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-a`;
        const refreshToken = process.env.GMAIL_API_ACCOUNT_REFRESH_1;

        const account = await seedAccount(accountId, {
            name: 'Revoke Test',
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                refreshToken,
                accessToken: 'sentinel-access-token-should-not-be-used'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);

            assert.strictEqual(captureState.requests.length, 1, 'expected exactly one revoke request');
            const captured = captureState.requests[0];
            assert.strictEqual(captured.method, 'POST');
            assert.ok(captured.contentType && captured.contentType.includes('application/x-www-form-urlencoded'));
            assert.strictEqual(captured.body, `token=${encodeURIComponent(refreshToken)}`);

            const remaining = await redis.exists(`${REDIS_PREFIX}iad:${accountId}`);
            assert.strictEqual(remaining, 0, 'account hash should be deleted from Redis');
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete with revoke=true falls back to access token when no refresh token is stored', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-b`;
        const accessToken = 'access-token-fallback-value';

        const account = await seedAccount(accountId, {
            name: 'Revoke Fallback',
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                accessToken
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);

            assert.strictEqual(captureState.requests.length, 1);
            assert.strictEqual(captureState.requests[0].body, `token=${encodeURIComponent(accessToken)}`);
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete without revoke flag does not contact OAuth provider', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-c`;

        const account = await seedAccount(accountId, {
            name: 'No Revoke',
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                refreshToken: process.env.GMAIL_API_ACCOUNT_REFRESH_1
            }
        });

        try {
            const result = await account.delete();
            assert.strictEqual(result.deleted, true);
            assert.strictEqual(captureState.requests.length, 0);
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete with revoke=true is a no-op for gmailService provider', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-d`;

        const account = await seedAccount(accountId, {
            name: 'Service Account',
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            oauth2: {
                provider: TEST_GMAIL_SERVICE_APP,
                auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                accessToken: 'gmailService-access-token'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.strictEqual(captureState.requests.length, 0, 'gmailService accounts should skip revoke');
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete completes even when the OAuth provider returns an error', async () => {
        resetCapture();
        captureState.responseStatus = 400;
        captureState.responseBody = JSON.stringify({ error: 'invalid_token' });

        const accountId = `revoke-it-${Date.now()}-e`;

        const account = await seedAccount(accountId, {
            name: 'Revoke Error',
            email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                refreshToken: 'definitely-not-a-real-token'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true, 'deletion should succeed despite revoke error');
            assert.strictEqual(captureState.requests.length, 1);

            const remaining = await redis.exists(`${REDIS_PREFIX}iad:${accountId}`);
            assert.strictEqual(remaining, 0, 'account should be deleted even when revoke fails');
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete with revoke=true is a no-op for non-OAuth (IMAP) accounts', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-f`;

        const account = await seedAccount(accountId, {
            name: 'Plain IMAP',
            email: 'plain-imap@example.com',
            imap: {
                host: 'imap.example.com',
                port: 993,
                secure: true,
                auth: { user: 'plain', pass: 'plain' }
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.strictEqual(captureState.requests.length, 0);
        } finally {
            await cleanupAccount(accountId);
        }
    });
});
