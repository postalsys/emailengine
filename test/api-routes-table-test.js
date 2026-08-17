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
const { ACTION, GROUP, GRANTABLE_GROUPS, NEVER_GRANTABLE, IMPACT_ACTIONS, ROUTE_GROUPS, routeGrant } = require('../lib/api-routes/permission-map');
const { ENUM_DESCRIPTIONS } = require('../lib/enum-descriptions');
const { IMPACT } = require('../lib/api-routes/operation-impact');

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
    'DELETE /v1/tokens/{token}',
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
    'GET /v1/tokens/{token}',
    'GET /v1/tokens/{token}/log',
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
    'POST /v1/tokens',
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

    // The permission grant a route requires is what a narrowed access token is checked against, so
    // a /v1 route the map does not describe would be either ungoverned or unreachable depending on
    // which way the check failed. These assertions are what lets lib/api-routes/permission-map.js
    // keep the mapping in one central table instead of declaring it on each route.

    await t.test('every /v1 route resolves to a permission action and group', () => {
        const unresolved = v1Routes
            .map(route => ({ route: route.route, grant: routeGrant(route) }))
            .filter(entry => !entry.grant.action || !entry.grant.group)
            .map(entry => `${entry.route} (action: ${String(entry.grant.action)}, group: ${String(entry.grant.group)})`);

        assert.deepEqual(
            unresolved,
            [],
            'every /v1 route must resolve to an action and a group in lib/api-routes/permission-map.js. ' +
                'A route with no group is denied to every token that carries `permissions`, which reads as a bug ' +
                'rather than as a policy. Add it to ROUTE_GROUPS, choosing the group by what a grant EXPOSES: ' +
                'anything handing out a credential or widening what the instance can do belongs in GROUP.ADMIN.\n' +
                `Unresolved: ${JSON.stringify(unresolved, null, 2)}`
        );
    });

    await t.test('the route map has no entries for routes that do not exist', () => {
        // The other direction. A stale key is not merely dead: renaming a route and leaving the old
        // key behind silently drops the new one out of every grant. The map keys are in the same
        // `METHOD /path` form as `route.route` and GOLDEN_ROUTES, so the two listings of these
        // routes can be diffed directly.
        // Routes that authenticate with an API token but are registered outside
        // lib/api-routes/index.js, so captureApiRoutes() cannot see them. Kept to a named list
        // rather than a pattern: each one is a route this guardrail genuinely does not cover, and
        // that should be an explicit decision rather than a wildcard.
        const UNGUARDED_ROUTES = new Set(['GET /metrics']);

        const registered = new Set(v1Routes.map(route => route.route));
        const stale = [...ROUTE_GROUPS.keys()].filter(key => !registered.has(key) && !UNGUARDED_ROUTES.has(key));

        assert.deepEqual(stale, [], `lib/api-routes/permission-map.js maps routes that are not registered: ${JSON.stringify(stale)}`);

        // Guards the inversion of GROUP_ROUTES: a route listed under two groups would collapse to
        // one Map entry, and last-write-wins would silently pick the group.
        assert.equal(ROUTE_GROUPS.size, v1Routes.length + UNGUARDED_ROUTES.size, 'the route map and the /v1 route table differ in size');
    });

    await t.test('the group vocabulary is frozen', () => {
        // These slugs become public API the moment they ship: they go into /swagger.json and into
        // customers' token records. Renaming one silently widens or voids a token that named it, so
        // the list is asserted against a literal rather than derived from the enum it describes.
        assert.deepEqual(Object.values(GROUP).sort(), [
            'account',
            'admin',
            'blocklist',
            'diagnostics',
            'events',
            'export',
            'gateway',
            'logs',
            'mailbox',
            'message',
            'outbox',
            'submit',
            'template',
            'webhook'
        ]);

        assert.deepEqual(Object.values(ACTION).sort(), ['destructive', 'read', 'send', 'write']);

        // admin is the whole safety property of the model. If it ever becomes grantable, a narrowed
        // token can mint itself a wider one and every other rule here is decorative.
        assert.ok(NEVER_GRANTABLE.has(GROUP.ADMIN), 'the admin group must never be grantable');

        // The published per-value documentation spells all 17 slugs a second time, and it is what a
        // customer reads when choosing a grant. Nothing else asserts the two lists agree, so a group
        // added here without a description ships an undocumented option.
        assert.deepEqual(Object.keys(ENUM_DESCRIPTIONS.tokenGroup).sort(), [...GRANTABLE_GROUPS].sort());
        assert.deepEqual(Object.keys(ENUM_DESCRIPTIONS.tokenAction).sort(), Object.values(ACTION).sort());

        // admin has no description on purpose: it can never be granted, so it is not an option when
        // issuing a token and documenting it as one would be misleading.
        assert.ok(!Object.hasOwn(ENUM_DESCRIPTIONS.tokenGroup, GROUP.ADMIN));

        // Every impact has to map to an action. One that does not resolves to undefined, which reads
        // as an unclassifiable route and denies - and would only surface if some route happened to
        // declare that impact.
        assert.deepEqual(Object.keys(IMPACT_ACTIONS).sort(), Object.values(IMPACT).sort());
    });

    await t.test('nothing that hands out a credential sits outside the admin group', () => {
        // Derived from the path rather than from a list of the routes that exist today, so a NEW
        // credential-handling route is covered too. Moving one of these into a grantable group has
        // to fail here rather than in a customer's threat model.
        //
        // The oauth-token route is the sharpest of them: it returns a live OAuth2 access token,
        // which is a mail credential that outlives any narrowing on the token that read it.
        const sensitive = /\/v1\/(settings|oauth2|license|tokens?)\b|oauth-token|verifyAccount|authentication\/form/;

        const misfiled = v1Routes
            .filter(route => sensitive.test(route.path))
            .map(route => ({ route: route.route, group: routeGrant(route).group }))
            .filter(entry => entry.group !== GROUP.ADMIN)
            .map(entry => `${entry.route} -> ${String(entry.group)}`);

        assert.deepEqual(
            misfiled,
            [],
            'a route that hands out a credential or widens what the instance can do must be in GROUP.ADMIN, ' +
                `which no permissions record can name: ${JSON.stringify(misfiled)}`
        );

        // The pattern has to actually match something, or the assertion above passes vacuously
        assert.ok(v1Routes.filter(route => sensitive.test(route.path)).length >= 18);
    });

    await t.test('a write that can redirect where stored credentials are sent is never grantable', () => {
        // None of these names a credential in its payload, which is what makes them easy to misfile.
        // Both records keep their stored password across a partial update - Account.persistUpdate()
        // merges the STORED imap/smtp/oauth2 object over the payload, and Gateway.update() hmsets
        // only the keys it was given - so a request that changes nothing but `host` is enough to make
        // the next connection authenticate to the new host with the old credentials. Reading those
        // credentials back is masked; sending them somewhere is not.
        //
        // The gateway pair was missed on the first pass precisely because the account pair had
        // already been reasoned about: same shape, different module.
        const credentialRedirects = ['POST /v1/account', 'PUT /v1/account/{account}', 'POST /v1/gateway', 'PUT /v1/gateway/edit/{gateway}'];

        for (const route of credentialRedirects) {
            assert.equal(ROUTE_GROUPS.get(route), GROUP.ADMIN, `${route} must not be grantable`);
        }
    });

    await t.test('every /v1 DELETE requires the destructive action', () => {
        // The action axis exists so a token can be granted write but not destructive. That only
        // holds if no DELETE resolves to plain write, which used to be the method default and made
        // `destructive` opt-in: one forgotten x-ee-impact and the route became callable by a token
        // issued specifically without destructive rights.
        const notDestructive = v1Routes
            .filter(route => route.method === 'delete')
            .map(route => ({ route: route.route, action: routeGrant(route).action }))
            .filter(entry => entry.action !== ACTION.DESTRUCTIVE)
            .map(entry => `${entry.route} -> ${String(entry.action)}`);

        assert.deepEqual(notDestructive, [], `every DELETE must resolve to the destructive action: ${JSON.stringify(notDestructive)}`);
        assert.ok(v1Routes.filter(route => route.method === 'delete').length >= 12);
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
