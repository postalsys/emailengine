'use strict';

// Authentication guardrails for the admin UI and for the CSRF exemption.
//
// Admin routes are protected by the server-wide default strategy (the admin session), so a route
// that writes `auth: false` or `mode: 'try'` opts out of it with nothing else noticing. The first
// suite allows that only for the routes listed below, each with the reason it needs it.
//
// The CSRF check (crumb, in workers/api.js) skips every route for which isMachineRoute() holds
// (MACHINE_TAGS in lib/security-headers.js), because a machine client holds no browser session and
// therefore no crumb, unless the route also accepts the session cookie (acceptsSession()): such a
// route keeps the check whatever its tags say. The second suite asserts that no route is in that
// position to begin with, across both route tables.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { captureRouteConfigs } = require('./helpers/capture-ui-routes');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const { isMachineRoute, acceptsSession } = require('../lib/security-headers');
const { TOTP_EXEMPT_PATHS } = require('../lib/session-default');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Admin routes that read the session without requiring it: the login and second-factor steps run
// before a full session exists
const ADMIN_SESSION_OPTIONAL = new Set([
    'GET /admin/login',
    'POST /admin/login',
    'POST /admin/totp',
    'POST /admin/passkey/auth/options',
    'POST /admin/passkey/auth/verify'
]);

// The catch-all 404 is registered by workers/api.js, outside both route tables
const ROUTES_OUTSIDE_TABLES = new Set(['/{any*}']);

const routeEntries = cfg => [].concat(cfg.method).map(method => ({ key: `${String(method).toUpperCase()} ${cfg.path}`, cfg }));

test('admin and CSRF authentication guardrails', async t => {
    const uiRoutes = captureRouteConfigs().flatMap(routeEntries);
    const { routes: apiRoutes } = await captureApiRoutes();

    await t.test('every admin route requires the admin session unless it is listed', () => {
        for (const { key, cfg } of uiRoutes) {
            if (!cfg.path.startsWith('/admin')) {
                continue;
            }
            const auth = cfg.options && cfg.options.auth;
            if (ADMIN_SESSION_OPTIONAL.has(key)) {
                assert.deepEqual(auth, { strategy: 'session', mode: 'try' }, `${key} is listed as session-optional and must declare exactly that`);
                continue;
            }
            assert.equal(
                auth,
                undefined,
                `${key} overrides the admin session (auth: ${JSON.stringify(auth)}); add it to ADMIN_SESSION_OPTIONAL with a reason if that is intended`
            );
        }
    });

    await t.test('the session-optional list names only registered routes', () => {
        const registered = new Set(uiRoutes.map(entry => entry.key));
        for (const key of ADMIN_SESSION_OPTIONAL) {
            assert.ok(registered.has(key), `${key} is listed in ADMIN_SESSION_OPTIONAL but no such route is registered`);
        }
    });

    await t.test('every path exempt from the second factor is a registered route', () => {
        const paths = new Set(uiRoutes.map(entry => entry.cfg.path));
        for (const path of TOTP_EXEMPT_PATHS) {
            assert.ok(paths.has(path) || ROUTES_OUTSIDE_TABLES.has(path), `TOTP_EXEMPT_PATHS lists ${path}, which no route registers`);
        }
    });

    await t.test('every session-optional admin route is reachable before the second factor', () => {
        // Otherwise a session waiting for its TOTP code is redirected away from the very step that
        // would complete it
        for (const key of ADMIN_SESSION_OPTIONAL) {
            const path = key.slice(key.indexOf(' ') + 1);
            assert.ok(TOTP_EXEMPT_PATHS.includes(path), `${key} reads a partial session but is not in TOTP_EXEMPT_PATHS`);
        }
    });

    await t.test('acceptsSession() reads both the declared and the normalised auth shapes', () => {
        // hapi hands the skip the normalised form ({ strategies }), a route table the declared one
        assert.equal(acceptsSession(undefined), true);
        assert.equal(acceptsSession(false), false);
        assert.equal(acceptsSession({ strategy: 'session', mode: 'try' }), true);
        assert.equal(acceptsSession({ strategies: ['session'], mode: 'try' }), true);
        assert.equal(acceptsSession({ strategy: 'api-token', mode: 'required' }), false);
        assert.equal(acceptsSession({ strategies: ['api-token'], mode: 'required' }), false);
    });

    await t.test('no route that accepts the admin session carries a machine tag', () => {
        const offenders = [];
        for (const { key, cfg } of uiRoutes) {
            const options = cfg.options || {};
            const tags = options.tags || [];
            if (acceptsSession(options.auth) && isMachineRoute(tags)) {
                offenders.push(key);
            }
        }
        for (const route of apiRoutes) {
            const auth = route.authDeclared === 'false' ? false : route.authDeclared === 'inherited' ? undefined : { strategy: route.authStrategy };
            if (acceptsSession(auth) && isMachineRoute(route.tags)) {
                offenders.push(`${route.method.toUpperCase()} ${route.path}`);
            }
        }
        assert.deepEqual(offenders, [], `these routes accept the session cookie but skip the CSRF check: ${offenders.join(', ')}`);
    });
});

registerRedisTeardown(redis);
