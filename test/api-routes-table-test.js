'use strict';

// In-process route-table snapshot and authentication guardrail for the REST API routes.
//
// The admin UI routes already have this (test/ui-routes-table-test.js); the /v1 surface did
// not, even though it is the one reachable with a bearer token from the public internet. The
// integration smoke test (test/integration/api-routes-smoke-test.js) hand-lists a subset of
// routes, so a newly added route is not covered by it until somebody remembers to append it.
//
// What this guards:
//   1. Every /v1 route declares `auth: { strategy: 'api-token', mode: 'required' }`. A route
//      registered with no auth key inherits server.auth.default(), which is the ADMIN SESSION
//      strategy - and that default is applied conditionally on an admin password being set, so
//      the same route is unauthenticated on an instance with no password. Forgetting the auth
//      block is therefore an auth bypass, not a 401.
//   2. Every /v1 route carries the 'api' tag. Route tags drive both the Swagger grouping and
//      the Crumb CSRF skip list in workers/api.js - an untagged /v1 route starts demanding a
//      CSRF crumb that no API client sends.
//   3. The captured (METHOD, path) set matches a checked-in golden list, with no duplicate
//      registrations. A diff means a route was added, dropped, or renamed.
//
// workers/api.js can not be imported from a test (it boots a Hapi server on require), so the
// routes are captured by calling lib/api-routes/index.js - the same registration function the
// worker calls - against a mock Hapi server. Because that is the real wiring rather than a copy
// of it, a newly added route module is covered by checks 1-3 the moment it is registered.
// Requiring those modules transitively opens Redis/BullMQ handles, so the test force exits,
// mirroring the convention in test/ui-routes-table-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

// The complete, sorted set of routes registered by lib/api-routes/index.js, captured with the
// Document Store feature gate ON (so the deprecated document-store endpoints are included; the
// gate-off table is asserted below, in this same file).
//
// Not covered here, and deliberately so: lib/api-routes/bull-board-routes.js. It is wired
// separately from workers/api.js because it registers a third-party Hapi PLUGIN rather than
// routes, and everything it mounts lives under /admin/bull-board (the admin session surface),
// not /v1. Nothing else registers /v1 routes outside index.js - the 'no plugins are registered
// during route setup' test below is what keeps that true.
//
// POST /admin/config/document-store/chat/test is an admin-UI route that happens to live in
// chat-routes.js. It is under /admin, so it uses the session default like the rest of the
// admin surface and is exempt from the /v1 auth check below.
const GOLDEN_ROUTES = [
    'DELETE /v1/account/{account}',
    'DELETE /v1/account/{account}/export/{exportId}',
    'DELETE /v1/account/{account}/mailbox',
    'DELETE /v1/account/{account}/message/{message}',
    'DELETE /v1/blocklist/{listId}',
    'DELETE /v1/gateway/{gateway}',
    'DELETE /v1/license',
    'DELETE /v1/oauth2/{app}',
    'DELETE /v1/outbox/{queueId}',
    'DELETE /v1/templates/account/{account}',
    'DELETE /v1/templates/template/{template}',
    'DELETE /v1/token/{token}',
    'GET /v1/account/{account}',
    'GET /v1/account/{account}/attachment/{attachment}',
    'GET /v1/account/{account}/export/{exportId}',
    'GET /v1/account/{account}/export/{exportId}/download',
    'GET /v1/account/{account}/exports',
    'GET /v1/account/{account}/mailboxes',
    'GET /v1/account/{account}/message/{message}',
    'GET /v1/account/{account}/message/{message}/source',
    'GET /v1/account/{account}/messages',
    'GET /v1/account/{account}/oauth-token',
    'GET /v1/account/{account}/server-signatures',
    'GET /v1/account/{account}/text/{text}',
    'GET /v1/accounts',
    'GET /v1/autoconfig',
    'GET /v1/blocklist/{listId}',
    'GET /v1/blocklists',
    'GET /v1/changes',
    'GET /v1/delivery-test/check/{deliveryTest}',
    'GET /v1/gateway/{gateway}',
    'GET /v1/gateways',
    'GET /v1/license',
    'GET /v1/logs/{account}',
    'GET /v1/oauth2',
    'GET /v1/oauth2/{app}',
    'GET /v1/outbox',
    'GET /v1/outbox/{queueId}',
    'GET /v1/pubsub/status',
    'GET /v1/settings',
    'GET /v1/settings/queue/{queue}',
    'GET /v1/stats',
    'GET /v1/templates',
    'GET /v1/templates/template/{template}',
    'GET /v1/tokens',
    'GET /v1/tokens/account/{account}',
    'GET /v1/webhookRoutes',
    'GET /v1/webhookRoutes/webhookRoute/{webhookRoute}',
    'POST /admin/config/document-store/chat/test',
    'POST /v1/account',
    'POST /v1/account/{account}/export',
    'POST /v1/account/{account}/mailbox',
    'POST /v1/account/{account}/message',
    'POST /v1/account/{account}/message/{message}/submit',
    'POST /v1/account/{account}/search',
    'POST /v1/account/{account}/submit',
    'POST /v1/authentication/form',
    'POST /v1/blocklist/{listId}',
    'POST /v1/chat/{account}',
    'POST /v1/delivery-test/account/{account}',
    'POST /v1/gateway',
    'POST /v1/license',
    'POST /v1/oauth2',
    'POST /v1/oauth2/{app}/verify',
    'POST /v1/settings',
    'POST /v1/templates/template',
    'POST /v1/token',
    'POST /v1/unified/search',
    'POST /v1/verifyAccount',
    'PUT /v1/account/{account}',
    'PUT /v1/account/{account}/flush',
    'PUT /v1/account/{account}/mailbox',
    'PUT /v1/account/{account}/message/{message}',
    'PUT /v1/account/{account}/message/{message}/move',
    'PUT /v1/account/{account}/messages',
    'PUT /v1/account/{account}/messages/delete',
    'PUT /v1/account/{account}/messages/move',
    'PUT /v1/account/{account}/reconnect',
    'PUT /v1/account/{account}/sync',
    'PUT /v1/gateway/edit/{gateway}',
    'PUT /v1/oauth2/{app}',
    'PUT /v1/settings/queue/{queue}',
    'PUT /v1/templates/template/{template}'
];

// Force exit once the tests finish - requiring the route modules opens Redis/BullMQ handles.
registerRedisTeardown(redis);

test('API route table and authentication', async t => {
    const { routes: captured, registeredPlugins } = await captureApiRoutes();
    const v1Routes = captured.filter(route => route.path.startsWith('/v1/'));

    await t.test('no duplicate route registrations', () => {
        const seen = new Set();
        const duplicates = [];
        for (const route of captured) {
            if (seen.has(route.route)) {
                duplicates.push(route.route);
            }
            seen.add(route.route);
        }
        assert.deepEqual(duplicates, [], `duplicate (method, path) registrations: ${JSON.stringify(duplicates)}`);
    });

    await t.test('every /v1 route requires an API token', () => {
        const offenders = v1Routes
            .filter(route => route.authStrategy !== 'api-token' || route.authMode !== 'required')
            .map(route => `${route.route} (strategy: ${String(route.authStrategy)}, mode: ${String(route.authMode)})`);

        assert.deepEqual(
            offenders,
            [],
            'every /v1 route must declare auth: { strategy: "api-token", mode: "required" }. ' +
                'Without it the route falls back to server.auth.default(), which is the admin session strategy ' +
                'and is only installed when an admin password is set - so the route is open on a passwordless instance.\n' +
                `Offenders: ${JSON.stringify(offenders, null, 2)}`
        );
    });

    await t.test('every /v1 route is tagged "api"', () => {
        const untagged = v1Routes.filter(route => !route.tags.includes('api')).map(route => route.route);

        assert.deepEqual(
            untagged,
            [],
            'the "api" tag drives the Swagger grouping and the Crumb CSRF skip list in workers/api.js - ' +
                `an untagged /v1 route rejects every API client with a missing-crumb 403.\nUntagged: ${JSON.stringify(untagged)}`
        );
    });

    await t.test('registered routes match the golden snapshot exactly', () => {
        const unique = [...new Set(captured.map(route => route.route))].sort();
        const golden = [...GOLDEN_ROUTES].sort();

        const missing = golden.filter(r => !unique.includes(r));
        const added = unique.filter(r => !golden.includes(r));

        assert.deepEqual(
            unique,
            golden,
            `API route table changed.\n  Dropped (in golden, not registered): ${JSON.stringify(missing)}\n  New (registered, not in golden): ${JSON.stringify(added)}`
        );
    });

    await t.test('no plugins are registered during route setup', () => {
        // Routes mounted through server.register() never reach server.route(), so they are
        // invisible to every check above - a /v1 route added that way would silently skip the
        // auth and tag assertions. If a plugin genuinely has to be registered here, decide
        // explicitly how its routes get covered before updating this list.
        assert.deepEqual(
            registeredPlugins,
            [],
            `lib/api-routes/index.js registered a Hapi plugin: ${JSON.stringify(registeredPlugins)}. ` +
                'Plugin-registered routes bypass this guardrail entirely.'
        );
    });

    await t.test('the document-store endpoints disappear when the feature gate is off', async () => {
        // The gate is an argument to registerApiRoutes(), so the off state is captured directly.
        // Nothing previously asserted the /v1 side of it: with the gate pinned on, removing or
        // inverting the check in lib/api-routes/index.js was undetectable.
        const { routes: disabled } = await captureApiRoutes({ documentStoreFeatureEnabled: false });
        const paths = disabled.map(route => route.route);

        const documentStoreRoutes = paths.filter(route => /\/v1\/chat\/|\/v1\/unified\/search|\/admin\/config\/document-store/.test(route));
        assert.deepEqual(documentStoreRoutes, [], `expected no document-store routes with the gate off, got ${JSON.stringify(documentStoreRoutes)}`);

        // and the rest of the API surface is untouched
        assert.ok(paths.includes('GET /v1/accounts'), 'unrelated routes must still be registered');
        assert.ok(paths.includes('GET /v1/changes'));
        assert.ok(
            captured.map(route => route.route).includes('POST /v1/chat/{account}'),
            'sanity check: the gate-on capture really does include the document-store routes'
        );
    });
});
