'use strict';

// Runtime smoke test for the admin UI routes, complementing the in-process route-table
// snapshot in test/ui-routes-table-test.js.
//
// The table test proves the exact SET of registered routes is unchanged across the
// routes-ui.js -> ui-routes/ extraction. This test proves the GET page handlers still
// EXECUTE end-to-end after a move - i.e. the extracted module's requires and shared
// helpers are wired correctly and nothing throws at runtime.
//
// It targets the two failure modes a move can introduce, and ONLY those:
//   - a dropped/renamed route  -> 404 (route no longer registered)
//   - a broken require / missing symbol in the new module -> 5xx (handler crashes)
// So each route must respond with something OTHER than 404 and below 500. We deliberately
// do NOT assert a specific 2xx/3xx: the shared test server's auth state depends on what
// earlier tests configured (an unauthenticated /admin page may legitimately 302 to the
// login screen, or 200 when no admin password is set), and either is fine here.
//
// Only parameterless GET routes are probed - a route with a path parameter (e.g.
// /admin/accounts/{account}) cannot distinguish "route dropped" (404) from "handler
// returned not-found for a bogus id" (also 404). Those, plus all POST routes, are covered
// by the route-table snapshot test instead.
//
// Runs against the shared test server started by the Grunt test task (config/test.toml,
// port 7077), same harness as test/api-routes-smoke-test.js.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;

const baseUrl = `http://127.0.0.1:${config.api.port}`;

// Parameterless GET routes from the UI route table (test/ui-routes-table-test.js golden).
// Routes with a `{param}` segment and all POST routes are intentionally excluded (see header).
const GET_ROUTES = [
    '/accounts/new',
    '/admin',
    '/admin/account/password',
    '/admin/account/security',
    '/admin/accounts',
    '/admin/config/ai',
    '/admin/config/document-store',
    '/admin/config/document-store/chat',
    '/admin/config/document-store/mappings',
    '/admin/config/document-store/mappings/new',
    '/admin/config/document-store/pre-processing',
    '/admin/config/imap-proxy',
    '/admin/config/license',
    '/admin/config/logging',
    '/admin/config/network',
    '/admin/config/oauth',
    '/admin/config/oauth/new',
    '/admin/config/oauth/subscriptions',
    '/admin/config/service',
    '/admin/config/smtp',
    '/admin/config/webhooks',
    '/admin/gateways',
    '/admin/gateways/new',
    '/admin/internals',
    '/admin/legal',
    '/admin/login',
    '/admin/swagger',
    '/admin/templates',
    '/admin/templates/new',
    '/admin/tokens',
    '/admin/tokens/new',
    // NOTE: GET /admin/totp is intentionally omitted. Its handler reads the logged-in
    // user off request.auth.credentials, so a direct GET without a partial-auth login
    // session returns a pre-existing 500 (lib/routes-ui.js, the 2FA page). That is not a
    // regression this refactor can cause; the route's registration is still covered by
    // the route-table snapshot test.
    '/admin/upgrade',
    '/admin/webhooks',
    '/admin/webhooks/new',
    '/unsubscribe'
];

test('Admin UI routes smoke test', async t => {
    await t.test('every parameterless GET route is registered and does not crash', async () => {
        for (const path of GET_ROUTES) {
            const res = await supertest(baseUrl).get(path);
            assert.notEqual(res.status, 404, `GET ${path} returned 404 - route is not registered (dropped or renamed during extraction)`);
            assert.ok(res.status < 500, `GET ${path} returned ${res.status} - handler crashed (likely a broken require or missing symbol after extraction)`);
        }
    });
});
