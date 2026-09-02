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
// Runs against the shared test server started by test/run-tests.js (config/test.toml,
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
    '/admin/account/passkeys',
    '/admin/account/password',
    '/admin/account/security',
    '/admin/accounts',
    '/admin/accounts/suggestions',
    '/admin/config/ai',
    '/admin/config/branding',
    '/admin/config/document-store',
    '/admin/config/document-store/chat',
    '/admin/config/document-store/mappings',
    '/admin/config/document-store/mappings/new',
    '/admin/config/document-store/pre-processing',
    '/admin/config/email-processing',
    '/admin/config/imap-proxy',
    '/admin/config/license',
    '/admin/config/logging',
    '/admin/config/mcp',
    '/admin/config/network',
    '/admin/config/oauth',
    '/admin/config/oauth/new',
    '/admin/config/oauth/subscriptions',
    '/admin/config/security',
    '/admin/config/service',
    '/admin/config/smtp',
    '/admin/config/webhooks',
    '/admin/gateways',
    '/admin/gateways/new',
    '/admin/internals',
    '/admin/legal',
    '/admin/legal/sbom.json',
    '/admin/login',
    '/admin/reference',
    '/admin/suppression-lists',
    '/admin/swagger',
    '/admin/templates',
    '/admin/templates/new',
    '/admin/tokens',
    '/admin/tokens/new',
    '/admin/totp',
    '/admin/upgrade',
    '/admin/webhooks',
    '/admin/webhooks/new',
    '/unsubscribe'
];

const { inlineScriptAttrs, NONCE_RE } = require('../helpers/inline-scripts');

test('Admin UI routes smoke test', async t => {
    await t.test('every parameterless GET route is registered and does not crash', async () => {
        for (const path of GET_ROUTES) {
            const res = await supertest(baseUrl).get(path);
            assert.notEqual(res.status, 404, `GET ${path} returned 404 - route is not registered (dropped or renamed during extraction)`);
            assert.ok(res.status < 500, `GET ${path} returned ${res.status} - handler crashed (likely a broken require or missing symbol after extraction)`);
        }
    });

    // The unit test proves the extension on a hand-built server; this proves the real worker
    // wires it, seeds the nonce before rendering, and that every page's inline scripts carry the
    // nonce the header names - the one mismatch a browser would answer with a dead page
    await t.test('every admin page carries a Content-Security-Policy whose nonce its inline scripts use', async () => {
        const nonces = new Set();

        for (const path of GET_ROUTES.filter(path => path.startsWith('/admin'))) {
            const res = await supertest(baseUrl).get(path);
            const csp = res.headers['content-security-policy'];
            assert.ok(csp, `GET ${path} (${res.status}) has no content-security-policy`);
            assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN', path);
            assert.equal(res.headers['cache-control'], 'no-store', path);

            if (res.status !== 200 || !/text\/html/.test(res.headers['content-type'])) {
                // a redirect to the login page or a JSON body has no inline script to match
                continue;
            }

            if (/'unsafe-inline'/.test(csp.match(/script-src ([^;]+)/)[1])) {
                // a public-layout page on an admin path: relaxed on purpose, keeps admin framing
                assert.match(csp, /frame-ancestors 'self'/, path);
                continue;
            }

            const nonce = csp.match(NONCE_RE);
            assert.ok(nonce, `GET ${path} policy names no nonce: ${csp}`);
            nonces.add(nonce[1]);

            for (const attrs of inlineScriptAttrs(res.text)) {
                assert.match(attrs, new RegExp(`\\bnonce="${nonce[1]}"`), `GET ${path}: inline <script${attrs}> does not carry the header nonce`);
            }
        }

        assert.ok(nonces.size > 1, 'every response carries its own nonce');
    });

    await t.test('a public page gets the relaxed policy and stays frameable', async () => {
        // No signed form data, so this is the public error page - which is exactly the response
        // an operator's own application would embed a failure of
        const res = await supertest(baseUrl).get('/accounts/new');
        const csp = res.headers['content-security-policy'];
        assert.ok(csp);
        assert.match(csp, /script-src 'self' https: 'unsafe-inline'/);
        assert.doesNotMatch(csp, /nonce|frame-ancestors/);
        assert.equal(res.headers['x-frame-options'], undefined);
        assert.notEqual(res.headers['cache-control'], 'no-store');
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
    });

    await t.test('static assets carry no policy', async () => {
        const res = await supertest(baseUrl).get('/static/js/app.js');
        assert.equal(res.status, 200);
        assert.equal(res.headers['content-security-policy'], undefined);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
    });
});
