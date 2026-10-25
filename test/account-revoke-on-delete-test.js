'use strict';

const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert').strict;
const Redis = require('ioredis');
const config = require('@zone-eu/wild-config');

const { GmailOauth } = require('../lib/oauth/gmail');
const oauth2AppsModule = require('../lib/oauth2-apps');
const { Account } = require('../lib/account');
const { REDIS_PREFIX } = require('../lib/consts');
const accountRoutes = require('../lib/api-routes/account-routes');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const { createMockLogger } = require('./helpers/mock-logger');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Module level, not inside the test: a `t.after()` registered in a test callback never runs when
// that test is skipped, and this file used to hang instead of skipping cleanly.
registerRedisTeardown();

// Fixed dummy values. Nothing here reaches Google: the revoke URL is the local capture server below
// and a revoke call sends the stored token verbatim, so opaque strings exercise the same path the
// real credentials did. The suite used to be gated on live Gmail secrets and silently skipped
// wherever they were missing (forks, dependabot, a fresh checkout).
const TEST_CLIENT_ID = 'revoke-test-client-id.apps.googleusercontent.com';
const TEST_CLIENT_SECRET = 'revoke-test-client-secret';
const TEST_PROJECT_ID = 'revoke-test-project';
const TEST_ACCOUNT_EMAIL = 'revoke-test@example.com';
const TEST_REFRESH_TOKEN = '1//revoke-test-refresh-token';

const TEST_GMAIL_APP = 'test-revoke-gmail-app';
const TEST_GMAIL_SERVICE_APP = 'test-revoke-gmail-service-app';
// Stands in for a provider with no revocation endpoint (Outlook): its client has no revokeToken
const TEST_UNSUPPORTED_APP = 'test-revoke-unsupported-app';

function makeStubLogger() {
    const noop = () => {};
    return { trace: noop, debug: noop, info: noop, warn: noop, error: noop, fatal: noop };
}

test('OAuth2 revoke on account delete', async t => {
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
    // is constructed with the dummy credentials but its revokeUrl points at the local capture
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
        if (id === TEST_UNSUPPORTED_APP) {
            return { id, provider: 'outlook', enabled: true, name: 'Test Outlook App' };
        }
        return originalGet(id);
    };

    oauth2AppsModule.oauth2Apps.getClient = async (provider, opts) => {
        if (provider === TEST_GMAIL_APP) {
            const client = new GmailOauth({
                clientId: TEST_CLIENT_ID,
                clientSecret: TEST_CLIENT_SECRET,
                redirectUrl: 'http://127.0.0.1:7003/oauth',
                scopes: ['https://www.googleapis.com/auth/gmail.modify'],
                googleProjectId: TEST_PROJECT_ID,
                setFlag: async () => {},
                logger: opts && opts.logger
            });
            client.revokeUrl = captureRevokeUrl;
            return client;
        }

        if (provider === TEST_GMAIL_SERVICE_APP) {
            const client = new GmailOauth({
                authMethod: 'serviceKey',
                serviceClient: 'stub-service-client',
                serviceClientEmail: 'stub-sa@example.com',
                serviceKey: 'stub-service-key',
                scopes: ['https://www.googleapis.com/auth/gmail.modify'],
                googleProjectId: TEST_PROJECT_ID,
                setFlag: async () => {},
                logger: opts && opts.logger
            });
            client.revokeUrl = captureRevokeUrl;
            return client;
        }

        if (provider === TEST_UNSUPPORTED_APP) {
            return {};
        }

        return originalGetClient(provider, opts);
    };

    t.after(async () => {
        oauth2AppsModule.oauth2Apps.get = originalGet;
        oauth2AppsModule.oauth2Apps.getClient = originalGetClient;
        await new Promise(resolve => captureServer.close(resolve));
        await redis.quit();
    });

    // Worker commands the Account sent, in order (teardown, reconnect, delete)
    let workerCommands = [];

    function buildAccount(accountId) {
        return new Account({
            redis,
            account: accountId,
            secret: undefined,
            call: async message => {
                workerCommands.push(message.cmd);
                return 0;
            },
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
        workerCommands = [];
        captureState.requests = [];
        captureState.responseStatus = 200;
        captureState.responseBody = '{}';
    }

    await t.test('delete with revoke=true revokes Gmail grant using refresh token', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-a`;
        const refreshToken = TEST_REFRESH_TOKEN;

        const account = await seedAccount(accountId, {
            name: 'Revoke Test',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: TEST_ACCOUNT_EMAIL },
                refreshToken,
                accessToken: 'sentinel-access-token-should-not-be-used'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.deepStrictEqual(result.revocation, { attempted: true, revoked: true, status: 200 });

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
            email: TEST_ACCOUNT_EMAIL,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: TEST_ACCOUNT_EMAIL },
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
            email: TEST_ACCOUNT_EMAIL,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: TEST_ACCOUNT_EMAIL },
                refreshToken: TEST_REFRESH_TOKEN
            }
        });

        try {
            const result = await account.delete();
            assert.strictEqual(result.deleted, true);
            assert.ok(!('revocation' in result), 'no revocation outcome when none was requested');
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
            email: TEST_ACCOUNT_EMAIL,
            oauth2: {
                provider: TEST_GMAIL_SERVICE_APP,
                auth: { user: TEST_ACCOUNT_EMAIL },
                accessToken: 'gmailService-access-token'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.strictEqual(captureState.requests.length, 0, 'gmailService accounts should skip revoke');
            assert.deepStrictEqual(result.revocation, { attempted: false, revoked: false, reason: 'ServiceAccount' });
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
            email: TEST_ACCOUNT_EMAIL,
            oauth2: {
                provider: TEST_GMAIL_APP,
                auth: { user: TEST_ACCOUNT_EMAIL },
                refreshToken: 'definitely-not-a-real-token'
            }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true, 'deletion should succeed despite revoke error');
            assert.strictEqual(captureState.requests.length, 1);
            assert.deepStrictEqual(result.revocation, { attempted: true, revoked: false, status: 400, reason: 'TokenInvalid', error: 'invalid_token' });

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
            assert.deepStrictEqual(result.revocation, { attempted: false, revoked: false, reason: 'NotOAuth2' });
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete with revoke=true reports a provider with no revocation endpoint and still deletes', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-g`;
        const account = await seedAccount(accountId, {
            name: 'Unsupported',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: { provider: TEST_UNSUPPORTED_APP, auth: { user: TEST_ACCOUNT_EMAIL }, refreshToken: TEST_REFRESH_TOKEN }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.deepStrictEqual(result.revocation, { attempted: false, revoked: false, reason: 'Unsupported' });
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('delete with revoke=true reports a missing token', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-h`;
        const account = await seedAccount(accountId, {
            name: 'No Token',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: { provider: TEST_GMAIL_APP, auth: { user: TEST_ACCOUNT_EMAIL } }
        });

        try {
            const result = await account.delete({ revoke: true });
            assert.strictEqual(result.deleted, true);
            assert.deepStrictEqual(result.revocation, { attempted: false, revoked: false, reason: 'NoToken' });
            assert.strictEqual(captureState.requests.length, 0);
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('revoke=required keeps the account when the provider does not confirm, and reconnects it', async () => {
        resetCapture();
        captureState.responseStatus = 503;
        captureState.responseBody = 'Service Unavailable';

        const accountId = `revoke-it-${Date.now()}-i`;
        const account = await seedAccount(accountId, {
            name: 'Required Failing',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: { provider: TEST_GMAIL_APP, auth: { user: TEST_ACCOUNT_EMAIL }, refreshToken: TEST_REFRESH_TOKEN }
        });

        try {
            await assert.rejects(account.delete({ revoke: 'required' }), err => {
                assert.strictEqual(err.code, 'RevocationNotConfirmed');
                assert.strictEqual(err.statusCode, 502);
                assert.deepStrictEqual(err.info.revocation, { attempted: true, revoked: false, status: 503, reason: 'ProviderRefused' });
                return true;
            });

            assert.strictEqual(await redis.exists(`${REDIS_PREFIX}iad:${accountId}`), 1, 'the account must be kept');
            assert.strictEqual(await redis.sismember(`${REDIS_PREFIX}ia:accounts`, accountId), 1);
            const stored = await account.loadAccountData(accountId);
            assert.strictEqual(stored.oauth2.refreshToken, TEST_REFRESH_TOKEN, 'the credentials must be kept');
            // The teardown stopped the watch, so the refusal has to set it up again
            assert.deepStrictEqual(workerCommands, ['teardown', 'reconnect']);

            // A retry once the provider recovers deletes the account
            captureState.responseStatus = 200;
            captureState.responseBody = '{}';
            const result = await account.delete({ revoke: 'required' });
            assert.strictEqual(result.deleted, true);
            assert.deepStrictEqual(result.revocation, { attempted: true, revoked: true, status: 200 });
            assert.strictEqual(await redis.exists(`${REDIS_PREFIX}iad:${accountId}`), 0);
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('revoke=required refuses before any teardown when revocation cannot be attempted', async () => {
        resetCapture();

        const accountId = `revoke-it-${Date.now()}-j`;
        const account = await seedAccount(accountId, {
            name: 'Required Unsupported',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: { provider: TEST_UNSUPPORTED_APP, auth: { user: TEST_ACCOUNT_EMAIL }, refreshToken: TEST_REFRESH_TOKEN }
        });

        try {
            await assert.rejects(account.delete({ revoke: 'required' }), err => {
                assert.strictEqual(err.code, 'RevocationNotConfirmed');
                assert.strictEqual(err.statusCode, 409);
                assert.deepStrictEqual(err.info.revocation, { attempted: false, revoked: false, reason: 'Unsupported' });
                return true;
            });
            assert.deepStrictEqual(workerCommands, [], 'nothing may be torn down for a refusal known up front');
            assert.strictEqual(await redis.exists(`${REDIS_PREFIX}iad:${accountId}`), 1);
        } finally {
            await cleanupAccount(accountId);
        }
    });

    await t.test('revoke=required deletes when there is no grant left to revoke', async () => {
        const cases = [
            {
                suffix: 'k',
                data: { oauth2: { provider: TEST_GMAIL_APP, auth: { user: TEST_ACCOUNT_EMAIL }, refreshToken: 'expired' } },
                reason: 'TokenInvalid'
            },
            {
                suffix: 'l',
                data: { oauth2: { provider: TEST_GMAIL_SERVICE_APP, auth: { user: TEST_ACCOUNT_EMAIL }, accessToken: 'x' } },
                reason: 'ServiceAccount'
            },
            { suffix: 'm', data: { imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } } }, reason: 'NotOAuth2' }
        ];

        for (const { suffix, data, reason } of cases) {
            resetCapture();
            captureState.responseStatus = 400;
            captureState.responseBody = JSON.stringify({ error: 'invalid_token' });

            const accountId = `revoke-it-${Date.now()}-${suffix}`;
            const account = await seedAccount(accountId, Object.assign({ name: 'Required No Grant', email: TEST_ACCOUNT_EMAIL }, data));
            try {
                const result = await account.delete({ revoke: 'required' });
                assert.strictEqual(result.deleted, true, reason);
                assert.strictEqual(result.revocation.reason, reason);
                assert.strictEqual(await redis.exists(`${REDIS_PREFIX}iad:${accountId}`), 0, reason);
            } finally {
                await cleanupAccount(accountId);
            }
        }
    });

    await t.test('DELETE /v1/account/{account} reports the outcome and logs it through the request logger', async () => {
        const routes = [];
        await accountRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }, { call: async () => 0 }));
        const route = routes.find(entry => entry.method === 'DELETE' && entry.path === '/v1/account/{account}');
        assert.ok(route, 'the route is registered');

        const { query } = route.options.validate;
        assert.strictEqual(query.validate({ revoke: 'required' }).value.revoke, 'required');
        assert.strictEqual(query.validate({ revoke: 'true' }).value.revoke, true);
        assert.strictEqual(query.validate({}).value.revoke, false);
        assert.ok(query.validate({ revoke: 'always' }).error, 'an unknown mode is refused');

        const requestLogger = createMockLogger();
        const request = (account, revoke) => ({ params: { account }, query: { revoke }, headers: {}, logger: requestLogger });

        resetCapture();
        captureState.responseStatus = 500;
        captureState.responseBody = 'boom';

        const accountId = `revoke-it-${Date.now()}-n`;
        await seedAccount(accountId, {
            name: 'Route Required',
            email: TEST_ACCOUNT_EMAIL,
            oauth2: { provider: TEST_GMAIL_APP, auth: { user: TEST_ACCOUNT_EMAIL }, refreshToken: TEST_REFRESH_TOKEN }
        });

        try {
            await assert.rejects(route.handler(request(accountId, 'required')), err => {
                assert.strictEqual(err.output.statusCode, 502);
                assert.strictEqual(err.output.payload.code, 'RevocationNotConfirmed');
                assert.strictEqual(err.output.payload.info.revocation.reason, 'ProviderRefused');
                assert.strictEqual(err.output.payload.info.revocation.status, 500);
                return true;
            });
            assert.ok(
                requestLogger.entries.some(entry => entry.msg === 'OAuth2 grant revocation before account delete' && entry.account === accountId),
                'the outcome is logged through the request logger, with the account'
            );

            captureState.responseStatus = 200;
            captureState.responseBody = '{}';
            const result = await route.handler(request(accountId, true));
            assert.deepStrictEqual(result, { account: accountId, deleted: true, revocation: { attempted: true, revoked: true, status: 200 } });
            assert.ifError(route.options.response.schema.validate(result).error);
        } finally {
            await cleanupAccount(accountId);
        }
    });
});
