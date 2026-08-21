'use strict';

// The MCP OAuth consent flow (lib/ui-routes/mcp-consent-routes.js), driven end to end through a
// real Hapi server: GET authorize rendering, the no-redirect-before-consent policy, the Deny and
// Approve decisions, and the approved code redeeming into a read-only mcp-scoped token.
//
// The consent module is registered on a bare @hapi/hapi server with three stand-ins for what
// workers/api.js provides around it: a `view` toolkit decoration that returns the template name
// and context instead of rendering Handlebars (the assertions are about which branch rendered
// with what, not about HTML), a session strategy in `try` mode that authenticates exactly when
// the request carries an x-test-admin header (both request principals the handlers key on), and
// a request logger. Everything else - the OAuth core, settings, Redis, the token store, the
// permission model - is the real thing.

const test = require('node:test');
const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { pkcePair } = require('./helpers/pkce');
const settings = require('../lib/settings');
const tokens = require('../lib/tokens');
const tokenPermissions = require('../lib/token-permissions');
const { MCP_READ_ONLY_PERMISSIONS } = require('../lib/token-permission-view');
const { registerClient, redeemAuthorizationCode } = require('../lib/mcp/oauth');
const mcpConsentRoutes = require('../lib/ui-routes/mcp-consent-routes');

const ORIGIN = 'https://ee-consent-test.example.com';
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

// The three settings oauthOrigin() reads. The unit tier flushes its Redis database before the
// run, so there is nothing to snapshot - the teardown just clears them again.
const FLOW_SETTINGS = { mcpEnabled: true, mcpOAuthEnabled: true, serviceUrl: ORIGIN };

let server;
let client;

function authorizeQuery(overrides) {
    const params = new URLSearchParams(
        Object.assign(
            {
                client_id: client.client_id,
                redirect_uri: REDIRECT_URI,
                response_type: 'code',
                state: 'test-state',
                code_challenge: 'a'.repeat(43),
                code_challenge_method: 'S256'
            },
            overrides || {}
        )
    );
    return `/admin/mcp/authorize?${params.toString()}`;
}

function approvalPayload(overrides) {
    return Object.assign(
        {
            client_id: client.client_id,
            redirect_uri: REDIRECT_URI,
            state: 'test-state',
            code_challenge: 'a'.repeat(43),
            resource: `${ORIGIN}/mcp`,
            decision: 'approve'
        },
        overrides || {}
    );
}

registerRedisTeardown(redis, () => Promise.all(Object.keys(FLOW_SETTINGS).map(key => settings.set(key, null))));

test('MCP consent flow', async t => {
    t.before(async () => {
        await Promise.all(Object.entries(FLOW_SETTINGS).map(([key, value]) => settings.set(key, value)));

        server = Hapi.server({});

        server.auth.scheme('stub-session', () => ({
            authenticate(request, h) {
                if (request.headers['x-test-admin']) {
                    return h.authenticated({ credentials: { user: 'admin' } });
                }
                throw Boom.unauthorized('No session');
            }
        }));
        server.auth.strategy('stub-session', 'stub-session');
        // `try` mode runs the handler either way, which is exactly the passwordless-instance
        // behavior the handlers' own request.auth.isAuthenticated checks exist for
        server.auth.default({ strategy: 'stub-session', mode: 'try' });

        server.decorate('toolkit', 'view', function (template, context) {
            return this.response({ template, context });
        });
        server.ext('onRequest', (request, h) => {
            request.logger = { info() {}, error() {}, debug() {}, warn() {} };
            return h.continue;
        });

        mcpConsentRoutes({ server, call: async () => ({ accounts: [] }) });
        await server.initialize();

        client = await registerClient({ redirectUris: [REDIRECT_URI], clientName: 'Consent flow test' });
    });

    await t.test('GET renders the consent form for a valid authorization request', async () => {
        const res = await server.inject({ method: 'GET', url: authorizeQuery(), headers: { 'x-test-admin': '1' } });

        assert.equal(res.statusCode, 200);
        assert.equal(res.result.template, 'mcp/authorize');
        assert.equal(res.result.context.clientName, 'Consent flow test');
        assert.equal(res.result.context.canProvision, true);
        assert.equal(res.result.context.readOnlyChecked, true, 'read-only must be the default');
        assert.equal(res.result.context.values.client_id, client.client_id);
        assert.ok(!res.result.context.errorMessage);
    });

    await t.test('an unauthenticated GET still renders, marked unable to approve', async () => {
        const res = await server.inject({ method: 'GET', url: authorizeQuery() });

        assert.equal(res.statusCode, 200);
        assert.equal(res.result.context.canProvision, false);
    });

    await t.test('every pre-consent failure renders in place, never redirects', async () => {
        for (const [label, url] of [
            ['unknown client', authorizeQuery({ client_id: 'f'.repeat(32) })],
            ['unregistered redirect_uri', authorizeQuery({ redirect_uri: 'https://claude.ai/other' })],
            ['unsupported response_type', authorizeQuery({ response_type: 'token' })],
            ['unsupported PKCE method', authorizeQuery({ code_challenge_method: 'plain' })],
            ['foreign resource', authorizeQuery({ resource: 'https://elsewhere.example.com/mcp' })],
            ['malformed request', '/admin/mcp/authorize?client_id=nope']
        ]) {
            const res = await server.inject({ method: 'GET', url, headers: { 'x-test-admin': '1' } });

            assert.equal(res.statusCode, 200, label);
            assert.ok(!res.headers.location, `${label} must not redirect`);
            assert.equal(res.result.template, 'mcp/authorize', label);
            assert.ok(res.result.context.errorMessage, `${label} must render the error branch`);
        }
    });

    await t.test('Deny redirects with access_denied and needs no session', async () => {
        const res = await server.inject({ method: 'POST', url: '/admin/mcp/authorize', payload: approvalPayload({ decision: 'deny' }) });

        assert.equal(res.statusCode, 302);
        const location = new URL(res.headers.location);
        assert.equal(location.origin, new URL(REDIRECT_URI).origin);
        assert.equal(location.searchParams.get('error'), 'access_denied');
        assert.equal(location.searchParams.get('state'), 'test-state');
        assert.equal(location.searchParams.get('iss'), ORIGIN);
    });

    await t.test('Approve without an authenticated session is refused', async () => {
        const res = await server.inject({ method: 'POST', url: '/admin/mcp/authorize', payload: approvalPayload() });
        assert.equal(res.statusCode, 403);
    });

    await t.test('approving an unknown account re-renders with the field error', async () => {
        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload({ account: 'consent-test-no-such-account' }),
            headers: { 'x-test-admin': '1' }
        });

        assert.equal(res.statusCode, 200);
        assert.equal(res.result.context.errors.account, 'No such account');
        assert.ok(!res.headers.location);
    });

    await t.test('Approve mints a code that redeems into a read-only mcp token', async () => {
        const { verifier, challenge } = pkcePair();

        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload({ code_challenge: challenge, readOnly: 'on' }),
            headers: { 'x-test-admin': '1' }
        });

        assert.equal(res.statusCode, 302);
        const location = new URL(res.headers.location);
        assert.equal(location.origin, new URL(REDIRECT_URI).origin);
        assert.equal(location.searchParams.get('state'), 'test-state');
        assert.equal(location.searchParams.get('iss'), ORIGIN);
        const code = location.searchParams.get('code');
        assert.ok(code, 'approval must carry the authorization code');

        // the client's half of the exchange, exactly as the token endpoint runs it
        const tokenResponse = await redeemAuthorizationCode({
            code,
            clientId: client.client_id,
            redirectUri: REDIRECT_URI,
            codeVerifier: verifier,
            resource: `${ORIGIN}/mcp`,
            origin: ORIGIN,
            ip: '198.51.100.7'
        });

        assert.equal(tokenResponse.token_type, 'Bearer');
        assert.equal(tokenResponse.scope, 'mcp');

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp']);
            assert.match(tokenData.description, /Consent flow test/);

            // the checkbox the operator saw is the narrowing the credential carries: the exact
            // read-only record, refusing send and destructive operations
            assert.deepEqual(tokenData.permissions, MCP_READ_ONLY_PERMISSIONS);
            assert.equal(tokenPermissions.check({ tokenData, operation: { action: 'send', group: 'submit' } }).allowed, false);
            assert.equal(tokenPermissions.check({ tokenData, operation: { action: 'destructive', group: 'message' } }).allowed, false);
            assert.equal(tokenPermissions.check({ tokenData, operation: { action: 'read', group: 'message' } }).allowed, true);
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('clearing the read-only box mints an unnarrowed token', async () => {
        const { verifier, challenge } = pkcePair();

        // an unchecked checkbox posts nothing, so the payload simply omits readOnly
        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload({ code_challenge: challenge }),
            headers: { 'x-test-admin': '1' }
        });
        assert.equal(res.statusCode, 302);
        const code = new URL(res.headers.location).searchParams.get('code');

        const tokenResponse = await redeemAuthorizationCode({
            code,
            clientId: client.client_id,
            redirectUri: REDIRECT_URI,
            codeVerifier: verifier,
            resource: `${ORIGIN}/mcp`,
            origin: ORIGIN,
            ip: '198.51.100.7'
        });

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp']);
            assert.ok(!tokenData.permissions, 'the wide grant carries no permissions record - the mcp scope itself is the bound');
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });
});
