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
// Runs against the shared test server started by the Grunt test task (config/test.toml,
// port 7077, prepared token with scope "*").

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;

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
