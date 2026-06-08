'use strict';

// In-process route-table snapshot for the admin UI routes.
//
// This is the primary guardrail for the routes-ui.js -> ui-routes/ extraction. The
// extraction moves route handlers verbatim out of the lib/routes-ui.js monolith into
// focused modules under lib/ui-routes/, then wires each module back in from within
// applyRoutes(). Moving code must NOT change which routes are registered.
//
// We capture the exact set of (METHOD, path) pairs that routes-ui.js registers by
// invoking it with a mock Hapi server whose .route() simply records the route config.
// Route registration is synchronous and never touches Redis or the `call` RPC, so a
// bare mock is sufficient - handlers reference external state only inside their (never
// executed) closures. The captured set must equal the checked-in golden list below,
// and there must be no duplicate registrations.
//
// IMPORTANT: GOLDEN_ROUTES must stay byte-for-byte identical across every extraction
// batch. It changes ONLY when a route is intentionally added or removed by feature work
// (not by this refactor). A diff here means a route was dropped, duplicated, or its
// method/path was altered during a move - exactly the failure modes the extraction risks.
//
// server.table() is unreachable from the external Grunt test process and the Swagger
// spec omits UI routes, so this must run in-process. Because requiring routes-ui.js
// transitively opens a Redis connection and BullMQ queues (lib/db.js), the test force
// exits after running, mirroring the convention in test/tokens-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');

// The complete, sorted set of routes registered by lib/routes-ui.js (including the
// already-extracted admin-entities-routes.js it wires in). 128 routes.
const GOLDEN_ROUTES = [
    'DELETE /admin/accounts/{account}/export/{exportId}',
    'GET /.well-known/acme-challenge/{token}',
    'GET /accounts/new',
    'GET /admin',
    'GET /admin/account/password',
    'GET /admin/account/security',
    'GET /admin/accounts',
    'GET /admin/accounts/{account}',
    'GET /admin/accounts/{account}/browse',
    'GET /admin/accounts/{account}/edit',
    'GET /admin/accounts/{account}/export/{exportId}',
    'GET /admin/accounts/{account}/export/{exportId}/download',
    'GET /admin/accounts/{account}/exports',
    'GET /admin/accounts/{account}/logs.txt',
    'GET /admin/config/ai',
    'GET /admin/config/document-store',
    'GET /admin/config/document-store/chat',
    'GET /admin/config/document-store/mappings',
    'GET /admin/config/document-store/mappings/new',
    'GET /admin/config/document-store/pre-processing',
    'GET /admin/config/imap-proxy',
    'GET /admin/config/license',
    'GET /admin/config/logging',
    'GET /admin/config/network',
    'GET /admin/config/oauth',
    'GET /admin/config/oauth/app/{app}',
    'GET /admin/config/oauth/edit/{app}',
    'GET /admin/config/oauth/new',
    'GET /admin/config/oauth/subscriptions',
    'GET /admin/config/service',
    'GET /admin/config/smtp',
    'GET /admin/config/webhooks',
    'GET /admin/gateways',
    'GET /admin/gateways/edit/{gateway}',
    'GET /admin/gateways/gateway/{gateway}',
    'GET /admin/gateways/new',
    'GET /admin/internals',
    'GET /admin/internals/thread/{threadId}',
    'GET /admin/legal',
    'GET /admin/login',
    'GET /admin/logout',
    'GET /admin/swagger',
    'GET /admin/templates',
    'GET /admin/templates/new',
    'GET /admin/templates/template/{template}',
    'GET /admin/templates/template/{template}/edit',
    'GET /admin/tokens',
    'GET /admin/tokens/new',
    'GET /admin/totp',
    'GET /admin/upgrade',
    'GET /admin/webhooks',
    'GET /admin/webhooks/new',
    'GET /admin/webhooks/webhook/{webhook}',
    'GET /admin/webhooks/webhook/{webhook}/edit',
    'GET /unsubscribe',
    'POST /accounts/new',
    'POST /accounts/new/imap',
    'POST /accounts/new/imap/server',
    'POST /accounts/new/imap/test',
    'POST /admin/account/logout-all',
    'POST /admin/account/passkeys/delete',
    'POST /admin/account/passkeys/register/options',
    'POST /admin/account/passkeys/register/verify',
    'POST /admin/account/password',
    'POST /admin/account/tfa/disable',
    'POST /admin/account/tfa/enable',
    'POST /admin/accounts/new',
    'POST /admin/accounts/{account}/delete',
    'POST /admin/accounts/{account}/edit',
    'POST /admin/accounts/{account}/export',
    'POST /admin/accounts/{account}/logs',
    'POST /admin/accounts/{account}/logs-flush',
    'POST /admin/accounts/{account}/reconnect',
    'POST /admin/accounts/{account}/sync',
    'POST /admin/config/ai',
    'POST /admin/config/ai/reload-models',
    'POST /admin/config/ai/test-prompt',
    'POST /admin/config/browser',
    'POST /admin/config/clear-error',
    'POST /admin/config/document-store',
    'POST /admin/config/document-store/chat',
    'POST /admin/config/document-store/mappings/new',
    'POST /admin/config/document-store/pre-processing',
    'POST /admin/config/document-store/test',
    'POST /admin/config/imap-proxy',
    'POST /admin/config/license',
    'POST /admin/config/license/delete',
    'POST /admin/config/license/trial',
    'POST /admin/config/logging',
    'POST /admin/config/logging/reconnect',
    'POST /admin/config/network',
    'POST /admin/config/network/delete',
    'POST /admin/config/network/reload',
    'POST /admin/config/oauth/app/{app}/add-account',
    'POST /admin/config/oauth/delete',
    'POST /admin/config/oauth/edit',
    'POST /admin/config/oauth/new',
    'POST /admin/config/oauth/subscriptions',
    'POST /admin/config/oauth/verify/{app}',
    'POST /admin/config/service',
    'POST /admin/config/service/clean',
    'POST /admin/config/service/preview',
    'POST /admin/config/smtp',
    'POST /admin/config/smtp/certificate',
    'POST /admin/config/webhooks',
    'POST /admin/config/webhooks/test',
    'POST /admin/gateways/delete/{gateway}',
    'POST /admin/gateways/edit',
    'POST /admin/gateways/new',
    'POST /admin/gateways/test',
    'POST /admin/internals/kill',
    'POST /admin/internals/snapshot',
    'POST /admin/login',
    'POST /admin/passkey/auth/options',
    'POST /admin/passkey/auth/verify',
    'POST /admin/smtp/check-test',
    'POST /admin/smtp/create-test',
    'POST /admin/templates/delete',
    'POST /admin/templates/edit',
    'POST /admin/templates/new',
    'POST /admin/templates/test',
    'POST /admin/tokens/delete',
    'POST /admin/tokens/new',
    'POST /admin/totp',
    'POST /admin/webhooks/delete',
    'POST /admin/webhooks/edit',
    'POST /admin/webhooks/new',
    'POST /unsubscribe/address'
];

// Capture every route registered by routes-ui.js using a mock server.
function captureRoutes() {
    const captured = [];

    const record = cfg => {
        if (Array.isArray(cfg)) {
            cfg.forEach(record);
            return;
        }
        const methods = Array.isArray(cfg.method) ? cfg.method : [cfg.method];
        for (const method of methods) {
            captured.push(`${String(method).toUpperCase()} ${cfg.path}`);
        }
    };

    // Mock Hapi server. routes-ui.js (and the modules it wires) only call server.route()
    // at registration time; server.auth is touched only inside a handler. Any other
    // server.* access returns a harmless no-op.
    const mockServer = new Proxy(
        {
            route: record,
            auth: { settings: { default: null }, default() {} }
        },
        {
            get(target, prop) {
                if (prop in target) {
                    return target[prop];
                }
                return () => {};
            }
        }
    );

    // `call` is only awaited inside handlers, never during registration.
    const mockCall = async () => ({});

    const routesUi = require('../lib/routes-ui');
    routesUi(mockServer, mockCall);

    return captured;
}

test('UI route table is unchanged', async t => {
    t.after(() => {
        redis.quit();
        // Force exit after cleanup - requiring routes-ui.js opens Redis/BullMQ handles.
        setTimeout(() => process.exit(), 1000).unref();
    });

    const captured = captureRoutes();
    const unique = [...new Set(captured)].sort();

    await t.test('no duplicate route registrations', () => {
        assert.equal(captured.length, unique.length, `expected no duplicate (method, path) registrations, got ${captured.length - unique.length} duplicate(s)`);
    });

    await t.test('registered routes match the golden snapshot exactly', () => {
        const golden = [...GOLDEN_ROUTES].sort();

        const missing = golden.filter(r => !unique.includes(r));
        const added = unique.filter(r => !golden.includes(r));

        assert.deepEqual(
            unique,
            golden,
            `UI route table changed.\n  Dropped (in golden, not registered): ${JSON.stringify(missing)}\n  New (registered, not in golden): ${JSON.stringify(added)}`
        );
    });
});
