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
const settings = require('../../lib/settings');
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
    ['post', '/v1/tokens'],
    ['delete', `/v1/tokens/${'a'.repeat(64)}`],
    ['get', `/v1/tokens/${'a'.repeat(64)}`],
    ['get', `/v1/tokens/${'a'.repeat(64)}/log`],
    ['get', '/v1/tokens'],
    // deprecated pre-2.79 aliases
    ['post', '/v1/token'],
    ['delete', `/v1/token/${'a'.repeat(64)}`],
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

// Provisioned directly rather than through POST /v1/tokens so these fixtures do not depend on the
// route under test in the same file. They write to the same Redis the shared test server reads.
const narrowedTokens = [];
async function provision(opts) {
    const token = await tokens.provision(Object.assign({ scopes: ['api'], nolog: true }, opts));
    narrowedTokens.push(token);
    return token;
}

async function narrowed(permissions, description) {
    return supertest.agent(baseUrl).auth(await provision({ permissions, description }), { type: 'bearer' });
}

// The account an account-bound fixture names. Not one of the accounts the other integration files
// create: the tier runs serially in filename order and this file sorts first, so on a fresh Redis
// nothing else has created an account yet - a bound fixture that went through POST /v1/tokens failed
// its account lookup and took the listing tests with it.
const BOUND_ACCOUNT = 'smoke-bound-account';

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

    await t.test('a narrowed token can not redirect a submission through a proxy it names', async () => {
        // `submit` is grantable, and a submit payload's `proxy` takes precedence over the account's
        // own route while the SMTP session still carries the account's decrypted credentials - so a
        // send-only token could point the AUTH exchange at a host it controls and read them off the
        // wire. The route grant cannot see a payload field, so the narrowing has to.
        const agent = await narrowed({ actions: ['read', 'send'], groups: ['submit', 'outbox'] }, 'smoke: send only');

        // A non-existent account on purpose: the guard runs before the account is even loaded, which
        // is what the two statuses below show.
        const refused = await agent.post('/v1/account/no-such-account/message/AAAAAQAACnA/submit').send({ proxy: 'socks5://proxy.example.com:1080' });
        assert.equal(refused.status, 403, `a narrowed token must not set a submit-time proxy, got ${refused.status}`);
        assert.match(refused.body.message, /connection route/i);

        // Without the override the same token gets past the guard and fails on the account, so the
        // refusal above is about the field rather than about the credential
        const allowed = await agent.post('/v1/account/no-such-account/message/AAAAAQAACnA/submit').send({});
        assert.equal(allowed.status, 404, `expected the account lookup to be what fails, got ${allowed.status}`);
    });

    await t.test('the API refuses to issue a token naming the admin group', async () => {
        // Belt and braces with the request-time deny above: the schema rejects it at issue time, so
        // the record never exists in the first place
        const res = await authed.post('/v1/tokens').send({
            account: 'main-account',
            description: 'smoke: should not be issued',
            scopes: ['api'],
            permissions: { groups: ['admin'] }
        });
        assert.equal(res.status, 400, `expected a validation failure, got ${res.status}`);
    });

    await t.test('mints an instance-wide token when it is narrowed', async () => {
        // The route has no {account} parameter and sits in the never-grantable admin group, so an
        // account-bound token is refused by the binding check and a narrowed one by the group check.
        // The caller is therefore always a full-privilege root token, and anything it mints here is
        // strictly narrower than what it already holds.
        const res = await authed.post('/v1/tokens').send({
            description: 'smoke: instance-wide narrowed',
            scopes: ['api'],
            permissions: { actions: ['read'], groups: ['diagnostics'] }
        });
        assert.equal(res.status, 200, `expected the token to be issued, got ${res.status} ${JSON.stringify(res.body)}`);
        narrowedTokens.push(res.body.token);

        const agent = supertest.agent(baseUrl).auth(res.body.token, { type: 'bearer' });

        // Instance-wide: reaches a route with no account parameter, which an account-bound token
        // cannot do at all
        assert.equal((await agent.get('/v1/stats')).status, 200);

        // Still narrowed, on both axes
        assert.equal((await agent.get('/v1/blocklists')).status, 403);
        assert.equal((await agent.get('/v1/settings?webhooks=true')).status, 403);
    });

    await t.test('returns an id that identifies the new token in the listings', async () => {
        // The value is never shown again and the listings report only the id, so without this a
        // caller could not say which of its own tokens it had just created.
        const description = `smoke: id round trip ${Date.now()}`;
        const res = await authed.post('/v1/tokens').send({
            description,
            scopes: ['api'],
            permissions: { actions: ['read'], groups: ['diagnostics'] }
        });
        assert.equal(res.status, 200);
        narrowedTokens.push(res.body.token);

        assert.match(res.body.id, /^[0-9a-f]{64}$/);
        // The id the hash of the value, not a second random string
        assert.equal(res.body.id, crypto.createHash('sha256').update(Buffer.from(res.body.token, 'hex')).digest('hex'));

        const listing = await authed.get('/v1/tokens');
        const listed = listing.body.tokens.find(entry => entry.id === res.body.id);
        assert.ok(listed, 'the returned id does not appear in the token listing');
        assert.equal(listed.description, description, 'the id resolves to a different token than the one created');
    });

    await t.test('fetches one token by id, without ever returning its value', async () => {
        // Previously the only way to see a token's permissions or expiry was to list every token and
        // filter client-side - and the listing was capped at 1000 with no way to page past it.
        const description = `smoke: fetch one ${Date.now()}`;
        const created = await authed.post('/v1/tokens').send({
            description,
            scopes: ['api'],
            permissions: { actions: ['read'], groups: ['diagnostics'] }
        });
        assert.equal(created.status, 200);
        narrowedTokens.push(created.body.token);

        // The id from the create response addresses the record directly
        const byId = await authed.get(`/v1/tokens/${created.body.id}`);
        assert.equal(byId.status, 200, `expected the token record, got ${byId.status}`);
        assert.equal(byId.body.description, description);
        assert.deepEqual(byId.body.permissions, { actions: ['read'], groups: ['diagnostics'] });
        assert.equal(byId.body.account, null, 'an instance-wide token should report a null account');

        // The value is shown once, at creation, and never again
        assert.ok(!JSON.stringify(byId.body).includes(created.body.token), 'the token value came back from the getter');

        // The read routes take the id ONLY. A token value in a URL path is written to the access log
        // and to any proxy in front of it, and the create response returns the id, so there is no
        // case that needs the value here. DELETE still accepts either - it predates this and the
        // value may be all a caller kept.
        assert.equal((await authed.get(`/v1/tokens/${created.body.token}`)).status, 404);

        assert.equal((await authed.get(`/v1/tokens/${'a'.repeat(64)}`)).status, 404);

        // Same shape as an entry in the listings, which includes when the credential was last used.
        // It lives in a second hash, so leaving it out made the one endpoint that describes a single
        // token the one that could not answer the question most often asked of it.
        assert.ok(byId.body.access, 'the getter must carry the last-use record the listing reports');
        assert.equal(byId.body.access.time, null, 'a token that has never authenticated has no last use');
    });

    await t.test('the deprecated token endpoint aliases still work', async () => {
        // v2.79.0 renamed the token endpoints, which 404-ed every pre-2.79 integration on a minor
        // upgrade. The old paths are back as deprecated aliases of the same handlers, so a
        // provision-list-revoke round trip written against the old surface has to keep working.
        const description = `smoke: alias round trip ${Date.now()}`;
        const created = await authed.post('/v1/token').send({
            description,
            scopes: ['api'],
            permissions: { actions: ['read'], groups: ['diagnostics'] }
        });
        assert.equal(created.status, 200, `expected the alias to mint a token, got ${created.status} ${JSON.stringify(created.body)}`);
        narrowedTokens.push(created.body.token);

        // the pre-2.79 per-account listing shape: a bare `tokens` array, no paging metadata
        const bound = await provision({ account: BOUND_ACCOUNT, description: `smoke: alias listing ${Date.now()}` });
        const listed = await authed.get(`/v1/tokens/account/${BOUND_ACCOUNT}`);
        assert.equal(listed.status, 200);
        assert.ok(
            listed.body.tokens.some(entry => entry.id === tokens.tokenId(bound)),
            'the alias listing did not include the account token'
        );
        assert.ok(!Object.hasOwn(listed.body, 'total'), 'the alias keeps the pre-2.79 response shape');

        const deleted = await authed.delete(`/v1/token/${created.body.token}`);
        assert.equal(deleted.status, 200);
        assert.equal(deleted.body.deleted, true);
        assert.equal((await authed.get(`/v1/tokens/${created.body.id}`)).status, 404, 'the alias delete did not revoke the token');
    });

    await t.test('an account-bound token lists its own tokens and no others', async () => {
        // GET /v1/tokens/account/{account} carried the account in the path, so a bound token reached
        // its own tokens through the default branch of the binding check. The replacement takes the
        // account as a query argument, which that check never read - so this branch was added, and
        // the old path is registered again as a deprecated alias.
        const token = await provision({ account: BOUND_ACCOUNT, description: `smoke: bound self-listing ${Date.now()}` });
        const boundAgent = supertest.agent(baseUrl).auth(token, { type: 'bearer' });

        const own = await boundAgent.get(`/v1/tokens?account=${BOUND_ACCOUNT}&pageSize=1000`);
        assert.equal(own.status, 200, `a bound token must still reach its own account's tokens, got ${own.status}`);
        assert.ok(
            own.body.tokens.some(entry => entry.id === tokens.tokenId(token)),
            'the listing did not include the token that asked for it'
        );

        // And no wider than that: a bound credential must not enumerate the instance, and omitting
        // the argument is not a way around it
        assert.equal((await boundAgent.get('/v1/tokens')).status, 403, 'a bound token must not list every token on the instance');
        assert.equal((await boundAgent.get('/v1/tokens?account=some-other-account')).status, 403);
    });

    await t.test('lists every token on the instance, and narrows to one account', async () => {
        // "Which credentials exist here" used to need one request per account: root tokens and each
        // account's tokens sat behind separate endpoints with no union.
        const boundId = tokens.tokenId(await provision({ account: BOUND_ACCOUNT, description: `smoke: bound ${Date.now()}` }));

        const all = await authed.get('/v1/tokens?pageSize=1000');
        assert.ok(
            all.body.tokens.some(entry => entry.id === boundId),
            'an account-bound token is missing from the instance-wide listing'
        );
        assert.ok(
            all.body.tokens.some(entry => entry.account === null),
            'no instance-wide token in the listing'
        );

        // Every item carries the account, so a client has one shape rather than one per listing
        assert.ok(all.body.tokens.every(entry => Object.hasOwn(entry, 'account')));

        const scoped = await authed.get(`/v1/tokens?account=${BOUND_ACCOUNT}&pageSize=1000`);
        assert.ok(scoped.body.tokens.length >= 1);
        assert.ok(
            scoped.body.tokens.every(entry => entry.account === BOUND_ACCOUNT),
            'the account filter returned tokens bound elsewhere'
        );
        assert.ok(scoped.body.total <= all.body.total);
    });

    await t.test('pages and filters the token listing', async () => {
        // The routes used to hardcode a 1000-entry cap with a TODO, and returned no total - so a
        // caller could not tell a complete listing from a truncated one.
        const listing = await authed.get('/v1/tokens?pageSize=1');
        assert.equal(listing.status, 200);
        assert.equal(listing.body.tokens.length, 1, 'pageSize was ignored');
        assert.ok(listing.body.total >= 1, 'no total to page against');
        assert.ok(listing.body.pages >= 1);

        const description = `smoke: filter target ${Date.now()}`;
        const created = await authed.post('/v1/tokens').send({
            description,
            scopes: ['api'],
            permissions: { actions: ['read'], groups: ['diagnostics'] }
        });
        narrowedTokens.push(created.body.token);

        const filtered = await authed.get(`/v1/tokens?query=${encodeURIComponent(description)}`);
        assert.equal(filtered.body.total, 1, 'the query did not narrow the listing');
        assert.equal(filtered.body.tokens[0].id, created.body.id);
    });

    await t.test('refuses an instance-wide token that is not narrowed', async () => {
        // Without an account binding and without permissions there is nothing limiting the token at
        // all, so the API declines to mint one. That shape is still reachable deliberately, through
        // the admin UI or EENGINE_PREPARED_TOKEN.
        const res = await authed.post('/v1/tokens').send({
            description: 'smoke: instance-wide unnarrowed',
            scopes: ['api']
        });
        assert.equal(res.status, 400, `expected a validation failure, got ${res.status}`);

        // An explicit null has to be refused too. joi's required() is a presence check and the schema
        // allows null so the admin form can post "not narrowed", so `permissions: null` - which any
        // template rendering an unset variable produces - satisfied required() and minted a full
        // instance-wide token.
        const explicitNull = await authed.post('/v1/tokens').send({
            description: 'smoke: instance-wide null permissions',
            scopes: ['api'],
            permissions: null
        });
        assert.equal(explicitNull.status, 400, `permissions: null must not mint an unnarrowed instance-wide token, got ${explicitNull.status}`);

        // An axis that lists nothing grants nothing, so it is refused rather than issued as a token
        // that authenticates and then denies every request
        const emptyAxis = await authed.post('/v1/tokens').send({
            description: 'smoke: empty axis',
            scopes: ['api'],
            permissions: { actions: [] }
        });
        assert.equal(emptyAxis.status, 400, `expected an empty axis to be refused, got ${emptyAxis.status}`);
    });

    await t.test('the API refuses an empty permissions object', async () => {
        // Ambiguous between "no narrowing" and "grant nothing", so it is refused rather than guessed
        const res = await authed.post('/v1/tokens').send({
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

test('settings credential masking round trip', async t => {
    const WEBHOOK_URL = 'https://smoke-user:smoke-secret@webhook.example.com/hook';
    const MASKED_URL = 'https://******:******@webhook.example.com/hook';

    // The keys these tests overwrite carry the tier's LIVE webhook configuration: the prepared
    // settings in config/test.toml point the global webhooks target at the shared test receiver,
    // are applied only at server startup, and every later file in the serial tier depends on
    // them. RESTORE the values rather than clearing them - a clear() here silently broke every
    // messageSent/trackOpen/trackClick wait for the rest of the tier, which read as provider
    // latency until the webhook worker's silent no-target skip was traced.
    const RESTORE_KEYS = ['webhooks', 'webhooksCustomHeaders', 'notifyText'];
    const originalValues = new Map();
    t.before(async () => {
        for (const key of RESTORE_KEYS) {
            originalValues.set(key, await settings.get(key));
        }
    });

    t.after(async () => {
        for (const key of RESTORE_KEYS) {
            const value = originalValues.get(key);
            if (value === null || typeof value === 'undefined') {
                await settings.clear(key);
            } else {
                await settings.set(key, value);
            }
        }
    });

    await t.test('posting the masked echo back does not destroy the stored credential', async () => {
        const stored = await authed.post('/v1/settings').send({ webhooks: WEBHOOK_URL });
        assert.equal(stored.status, 200);
        assert.deepEqual(stored.body.updated, ['webhooks']);

        // what a read-modify-write client sees
        const read = await authed.get('/v1/settings?webhooks=true');
        assert.equal(read.body.webhooks, MASKED_URL, 'the read must return the masked value');

        // ...and posts back untouched next to some other change
        const echoed = await authed.post('/v1/settings').send({ webhooks: read.body.webhooks, notifyText: true });
        assert.equal(echoed.status, 200, `the masked echo must be accepted, got ${echoed.status} ${JSON.stringify(echoed.body)}`);
        assert.deepEqual(echoed.body.updated, ['notifyText'], 'the echoed masked key must not be reported as updated');

        // v2.79.0 stored the literal mask here, breaking webhook auth silently
        assert.equal(await settings.get('webhooks'), WEBHOOK_URL, 'the stored credential must survive the round trip');
    });

    await t.test('a masked value that is not the stored echo is refused', async () => {
        const res = await authed.post('/v1/settings').send({ webhooks: 'https://******:******@other.example.com/hook' });
        assert.equal(res.status, 400, `a mask over a different destination cannot be resolved, got ${res.status}`);
        assert.match(res.body.message, /masked placeholder/);
    });

    await t.test('masked custom header values round-trip without being stored', async () => {
        const headers = [{ key: 'Authorization', value: 'Bearer smoke-secret' }];
        assert.equal((await authed.post('/v1/settings').send({ webhooksCustomHeaders: headers })).status, 200);

        const read = await authed.get('/v1/settings?webhooksCustomHeaders=true');
        assert.equal(read.body.webhooksCustomHeaders[0].value, '******');

        const echoed = await authed.post('/v1/settings').send({ webhooksCustomHeaders: read.body.webhooksCustomHeaders });
        assert.equal(echoed.status, 200);
        assert.deepEqual(echoed.body.updated, []);

        assert.deepEqual(await settings.get('webhooksCustomHeaders'), headers, 'the stored header credential must survive the round trip');
    });
});

// The machine-facing header set (lib/security-headers.js) as the live worker sends it: nothing
// may render or frame an API response, and nothing caches it. Both on a success and on the 401
// the error extension rebuilds, which is where a header stamped too early would go missing.
test('security headers on the API', async t => {
    await t.test('a JSON response carries the machine-facing set', async () => {
        const res = await authed.get('/v1/settings');
        assert.equal(res.status, 200);
        assert.equal(res.headers['content-security-policy'], "default-src 'none'; frame-ancestors 'none'");
        assert.equal(res.headers['x-frame-options'], 'DENY');
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['cache-control'], 'no-store');
        assert.equal(res.headers['strict-transport-security'], undefined, 'the test instance has no https serviceUrl');
    });

    await t.test('a rebuilt 401 carries the same set', async () => {
        const res = await supertest(baseUrl).get('/v1/settings');
        assert.equal(res.status, 401);
        assert.equal(res.headers['content-security-policy'], "default-src 'none'; frame-ancestors 'none'");
        assert.equal(res.headers['x-frame-options'], 'DENY');
        assert.equal(res.headers['cache-control'], 'no-store');
    });
});
