'use strict';

// Smoke tests for the API routes extracted from workers/api.js into lib/api-routes/.
//
// The extraction was behavior-preserving (handlers moved verbatim), but roughly half
// of the extracted routes had no direct HTTP test. These smoke tests close that gap by
// verifying the two properties the extraction could realistically break:
//   1. Authentication is still enforced - every extracted route rejects an
//      unauthenticated request with 401 (proves the per-route `auth` config survived).
//   2. The read/list handlers actually execute end-to-end and return 200 with a valid
//      token (proves dependency injection / requires are wired correctly at runtime).
//
// Runs against the shared test server started by test/run-tests.js (config/test.toml,
// port 7077, prepared token with scope "*").

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;

// Provisioning a narrowed token directly is the only way to get one without an existing account, and
// it pulls in lib/db - whose Redis and BullMQ handles keep the event loop alive after the tests pass.
// registerRedisTeardown force-exits for exactly that reason; every other file in this tier talks to
// the server over HTTP only and needs none of this.
const tokens = require('../../lib/tokens');
const { redis } = require('../../lib/db');
const registerRedisTeardown = require('../helpers/redis-teardown');

// Static access token provisioned via `preparedToken` in config/test.toml (scope "*").
const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const baseUrl = `http://127.0.0.1:${config.api.port}`;

const authed = supertest.agent(baseUrl).auth(accessToken, { type: 'bearer' });

// Every route extracted during the route-module refactor (method + path). All of these
// declare `auth: { strategy: 'api-token', mode: 'required' }`, so an unauthenticated
// request must be rejected with 401 before any handler logic runs.
const AUTH_REQUIRED_ROUTES = [
    // token-routes.js
    ['post', '/v1/token'],
    ['delete', `/v1/token/${'a'.repeat(64)}`],
    ['get', '/v1/tokens'],
    ['get', '/v1/tokens/account/main-account'],

    // mailbox-routes.js
    ['get', '/v1/account/main-account/mailboxes'],
    ['post', '/v1/account/main-account/mailbox'],
    ['put', '/v1/account/main-account/mailbox'],
    ['delete', '/v1/account/main-account/mailbox?path=Test'],

    // settings-routes.js
    ['get', '/v1/settings'],
    ['post', '/v1/settings'],
    ['get', '/v1/settings/queue/notify'],
    ['put', '/v1/settings/queue/notify'],

    // stats-routes.js
    ['get', '/v1/stats'],

    // license-routes.js
    ['get', '/v1/license'],
    ['post', '/v1/license'],
    ['delete', '/v1/license'],

    // outbox-routes.js
    ['get', '/v1/outbox'],
    ['get', '/v1/outbox/test-queue-id'],
    ['delete', '/v1/outbox/test-queue-id'],

    // webhook-route-routes.js
    ['get', '/v1/webhookRoutes'],
    ['get', '/v1/webhookRoutes/webhookRoute/test-route'],

    // oauth2-app-routes.js
    ['get', '/v1/oauth2'],
    ['get', '/v1/oauth2/test-app'],
    ['post', '/v1/oauth2'],
    ['put', '/v1/oauth2/test-app'],
    ['delete', '/v1/oauth2/test-app'],
    ['post', '/v1/oauth2/test-app/verify'],

    // gateway-routes.js
    ['get', '/v1/gateways'],
    ['get', '/v1/gateway/test-gateway'],
    ['post', '/v1/gateway'],
    ['put', '/v1/gateway/edit/test-gateway'],
    ['delete', '/v1/gateway/test-gateway'],

    // delivery-test-routes.js
    ['post', '/v1/delivery-test/account/main-account'],
    ['get', '/v1/delivery-test/check/test-delivery'],

    // blocklist-routes.js
    ['get', '/v1/blocklists'],
    ['get', '/v1/blocklist/test-list'],
    ['post', '/v1/blocklist/test-list'],
    ['delete', '/v1/blocklist/test-list'],

    // submit-routes.js
    ['post', '/v1/account/main-account/submit'],
    ['post', '/v1/account/main-account/message/AAAAAQAACnA/submit'],

    // pubsub-routes.js
    ['get', '/v1/pubsub/status'],

    // account-routes.js (folded account-scoped routes)
    ['get', '/v1/account/main-account/oauth-token'],
    ['get', '/v1/account/main-account/server-signatures'],
    ['post', '/v1/authentication/form'],
    ['get', '/v1/logs/main-account'],
    ['post', '/v1/verifyAccount'],
    ['get', '/v1/autoconfig?email=user@example.com']
];

// Read/list endpoints that operate on global resources (Redis or the main thread only,
// no email account required) and must return 200 with a valid token, even on a clean DB.
const LIST_ENDPOINTS_OK = [
    '/v1/settings',
    '/v1/tokens',
    '/v1/outbox',
    '/v1/webhookRoutes',
    '/v1/oauth2',
    '/v1/gateways',
    '/v1/blocklists',
    '/v1/pubsub/status',
    '/v1/stats'
];

// Provisioned directly rather than through POST /v1/token, which needs an existing account. These
// write to the same Redis the shared test server reads.
const narrowedTokens = [];
async function narrowed(permissions, description) {
    const token = await tokens.provision({ scopes: ['api'], permissions, description, nolog: true });
    narrowedTokens.push(token);
    return supertest.agent(baseUrl).auth(token, { type: 'bearer' });
}

registerRedisTeardown(redis, async () => {
    for (const token of narrowedTokens) {
        try {
            await tokens.delete(token);
        } catch (err) {
            // ignore
        }
    }
});

// End-to-end proof that the api-token strategy in workers/api.js enforces the narrowing. The check
// itself is unit-tested in test/token-permissions-test.js; what only a live server can show is that
// it is wired into the strategy, sees the right route, and shapes the 403 the way an agent needs.
test('narrowed access tokens', async t => {
    await t.test('an un-narrowed token is unaffected', async () => {
        // The whole change is additive, so the prepared token - which carries no permissions - has to
        // keep reaching everything it reached before
        assert.equal((await authed.get('/v1/stats')).status, 200);
        assert.equal((await authed.get('/v1/settings?webhooks=true')).status, 200);
    });

    await t.test('a token narrowed to a group reaches that group and nothing else', async () => {
        const agent = await narrowed({ groups: ['diagnostics'] }, 'smoke: diagnostics only');

        assert.equal((await agent.get('/v1/stats')).status, 200, 'GET /v1/stats is in the diagnostics group');

        const denied = await agent.get('/v1/blocklists');
        assert.equal(denied.status, 403, 'GET /v1/blocklists is not in the diagnostics group');
        assert.deepEqual(denied.body.requiredPermission, { action: 'read', group: 'blocklist' });
    });

    await t.test('a token narrowed to read cannot call a destructive route in its own group', async () => {
        // The point of separating destructive from write: "may file and reply but not delete"
        const agent = await narrowed({ actions: ['read'], groups: ['blocklist'] }, 'smoke: read-only blocklist');

        assert.equal((await agent.get('/v1/blocklists')).status, 200);

        const denied = await agent.delete('/v1/blocklist/test-list?recipient=nobody@example.com');
        assert.equal(denied.status, 403, 'DELETE is destructive, which this token does not hold');
        assert.equal(denied.body.requiredPermission.action, 'destructive');
    });

    await t.test('no narrowed token reaches the admin group, whatever it asks for', async () => {
        // The safety property. A record cannot even name `admin` - the schema refuses it - so this
        // asks for everything that IS nameable and still has to be refused.
        const agent = await narrowed({ actions: ['read', 'write', 'send', 'destructive'] }, 'smoke: all actions');

        for (const path of ['/v1/settings?webhooks=true', '/v1/tokens', '/v1/oauth2']) {
            const denied = await agent.get(path);
            assert.equal(denied.status, 403, `GET ${path} must be refused: it is in the never-grantable admin group`);
            assert.equal(denied.body.requiredPermission.group, 'admin');
        }
    });

    await t.test('the API refuses to issue a token naming the admin group', async () => {
        // Belt and braces with the request-time deny above: the schema rejects it at issue time, so
        // the record never exists in the first place
        const res = await authed.post('/v1/token').send({
            account: 'main-account',
            description: 'smoke: should not be issued',
            scopes: ['api'],
            permissions: { groups: ['admin'] }
        });
        assert.equal(res.status, 400, `expected a validation failure, got ${res.status}`);
    });

    await t.test('the API refuses an empty permissions object', async () => {
        // Ambiguous between "no narrowing" and "grant nothing", so it is refused rather than guessed
        const res = await authed.post('/v1/token').send({
            account: 'main-account',
            description: 'smoke: empty permissions',
            scopes: ['api'],
            permissions: {}
        });
        assert.equal(res.status, 400, `expected a validation failure, got ${res.status}`);
    });
});

test('Extracted API routes smoke test', async t => {
    await t.test('every extracted route enforces authentication (401 without a token)', async () => {
        for (const [method, path] of AUTH_REQUIRED_ROUTES) {
            const res = await supertest(baseUrl)[method](path);
            assert.equal(res.status, 401, `${method.toUpperCase()} ${path} must reject unauthenticated requests with 401 (got ${res.status})`);
        }
    });

    await t.test('list endpoints execute and return 200 with a valid token', async () => {
        for (const path of LIST_ENDPOINTS_OK) {
            const res = await authed.get(path);
            assert.equal(res.status, 200, `GET ${path} should return 200 with a valid token (got ${res.status})`);
        }
    });

    await t.test('token listing exposes the SHA-256 id for each token', async () => {
        const res = await authed.get('/v1/tokens');
        assert.equal(res.status, 200, `GET /v1/tokens should return 200 (got ${res.status})`);
        assert.ok(Array.isArray(res.body.tokens) && res.body.tokens.length > 0, 'expected at least one root token in the listing');

        for (const token of res.body.tokens) {
            assert.match(token.id, /^[0-9a-f]{64}$/, 'each listed token should expose a 64-hex id (SHA-256 hash)');
        }

        // The id is the SHA-256 hash of the raw token, so the prepared token must appear by its hash.
        const expectedId = crypto.createHash('sha256').update(Buffer.from(accessToken, 'hex')).digest('hex');
        assert.ok(
            res.body.tokens.some(token => token.id === expectedId),
            'the prepared token should be listed with its SHA-256 id'
        );
    });
});
