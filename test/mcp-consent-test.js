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
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { pkcePair } = require('./helpers/pkce');
const settings = require('../lib/settings');
const tokens = require('../lib/tokens');
const tokenPermissions = require('../lib/token-permissions');
const { MCP_SECTIONS, mcpGrantsFor } = require('../lib/token-permission-view');
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

// The authorization URL with no code_challenge_method at all - authorizeQuery() cannot express an
// absent key, since URLSearchParams would spell an undefined override out as the string "undefined"
function withoutPkceMethod(url) {
    const parsed = new URL(url, 'http://localhost');
    parsed.searchParams.delete('code_challenge_method');
    return parsed.pathname + parsed.search;
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

        mcpConsentRoutes({ server });
        await server.initialize();

        client = await registerClient({ redirectUris: [REDIRECT_URI], clientName: 'Consent flow test' });
    });

    await t.test('GET renders the consent form for a valid authorization request', async () => {
        const res = await server.inject({ method: 'GET', url: authorizeQuery(), headers: { 'x-test-admin': '1' } });

        assert.equal(res.statusCode, 200);
        assert.equal(res.result.template, 'mcp/authorize');
        assert.equal(res.result.context.clientName, 'Consent flow test');
        assert.equal(res.result.context.canProvision, true);
        assert.equal(res.result.context.manageLevel, 'observe', 'observing the instance must be the default management level');
        assert.equal(res.result.context.mailEnabled, false, 'mail access must be off unless asked for');
        assert.equal(res.result.context.values.client_id, client.client_id);
        assert.ok(!res.result.context.errorMessage);

        // What the tool count under the radios reads. This server registers only the consent
        // routes, so its catalog is empty - which is the case worth pinning here: the count is a
        // nicety and the decision is not, so an empty or failed catalog still has to render a
        // usable consent page rather than throw. A populated count is covered where a real route
        // table exists (the MCP config page's e2e test, and test/mcp-tools-test.js for the rule).
        assert.ok(Array.isArray(res.result.context.mcpTools), 'the consent page needs a tool list, even an empty one');
        assert.deepEqual(Object.keys(res.result.context.mcpSections), ['manage', 'mail']);
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
            ['absent PKCE method', withoutPkceMethod(authorizeQuery())],
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

    await t.test('an absent PKCE method is refused as unsupported, not treated as S256', async () => {
        // RFC 7636 defaults a missing code_challenge_method to "plain", which the token endpoint
        // refuses. Passing consent on that request would only fail at the exchange, where nobody
        // is looking - so it has to render the same error the explicit "plain" gets, here.
        const res = await server.inject({ method: 'GET', url: withoutPkceMethod(authorizeQuery()), headers: { 'x-test-admin': '1' } });

        assert.equal(res.statusCode, 200);
        assert.match(res.result.context.errorMessage, /unsupported PKCE method/);
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

    await t.test('approving for a foreign resource renders rather than minting a dead code', async () => {
        // The GET checks this too, but the GET is not what supplies the value - a hand-crafted form
        // can name any resource. Redemption refuses a code whose resource is not this server, so
        // without the check here the approval succeeds and the exchange fails, which reads to the
        // operator as an approval that did nothing.
        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload({ resource: 'https://elsewhere.example.com/mcp' }),
            headers: { 'x-test-admin': '1' }
        });

        assert.equal(res.statusCode, 200);
        assert.match(res.payload, /names a different server as its resource/);
        assert.ok(!res.headers.location, 'a pre-consent failure must not redirect off the origin');
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
        // The account picker is handed nothing to show back, because there is no such account to
        // describe. The id itself survives in `values`, which is what the field renders as the
        // unresolved choice it is.
        assert.equal(res.result.context.selectedAccount, null);
        assert.equal(res.result.context.values.account, 'consent-test-no-such-account');
    });

    await t.test('the scope hint sets where the form starts, and only that', async () => {
        // A client asking for the mail scope is asking for mail access, so the box starts ticked;
        // one asking only for mail starts with no management access, since it asked for none. It
        // is a starting position: the person still decides, and the POST reads the controls.
        const context = async scope => {
            const res = await server.inject({ method: 'GET', url: authorizeQuery(scope === undefined ? {} : { scope }), headers: { 'x-test-admin': '1' } });
            assert.equal(res.statusCode, 200);
            return res.result.context;
        };

        const mailOnly = await context('mcp');
        assert.equal(mailOnly.manageLevel, 'none');
        assert.equal(mailOnly.mailEnabled, true);
        assert.equal(mailOnly.mailLevel, 'read');

        const both = await context('mcp-manage mcp');
        assert.equal(both.manageLevel, 'observe');
        assert.equal(both.mailEnabled, true);

        const manageOnly = await context('mcp-manage');
        assert.equal(manageOnly.manageLevel, 'observe');
        assert.equal(manageOnly.mailEnabled, false);

        // Unknown scope values are noise, not a request for anything
        const unknown = await context('offline_access openid');
        assert.equal(unknown.manageLevel, 'observe');
        assert.equal(unknown.mailEnabled, false);
    });

    // Approval and the client's half of the exchange, exactly as the token endpoint runs it.
    // Shared by every access-level case; hands back the redirect target too, so the case that
    // asserts on the authorization response does not have to inline the flow.
    const approveAndRedeem = async payloadOverrides => {
        const { verifier, challenge } = pkcePair();

        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload(Object.assign({ code_challenge: challenge }, payloadOverrides)),
            headers: { 'x-test-admin': '1' }
        });
        assert.equal(res.statusCode, 302, res.payload);
        const location = new URL(res.headers.location);
        const code = location.searchParams.get('code');
        assert.ok(code, 'approval must carry the authorization code');

        const tokenResponse = await redeemAuthorizationCode({
            code,
            clientId: client.client_id,
            redirectUri: REDIRECT_URI,
            codeVerifier: verifier,
            resource: `${ORIGIN}/mcp`,
            origin: ORIGIN,
            ip: '198.51.100.7'
        });

        return { location, tokenResponse };
    };

    const allowed = (tokenData, action, group) => tokenPermissions.check({ tokenData, operation: { action, group } }).allowed;

    await t.test('Approve mints a code that redeems into an observe-only management token', async () => {
        const { location, tokenResponse } = await approveAndRedeem({ manage: 'observe' });

        assert.equal(location.origin, new URL(REDIRECT_URI).origin);
        assert.equal(location.searchParams.get('state'), 'test-state');
        assert.equal(location.searchParams.get('iss'), ORIGIN);

        assert.equal(tokenResponse.token_type, 'Bearer');
        assert.equal(tokenResponse.scope, 'mcp-manage');

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp-manage']);
            assert.match(tokenData.description, /Consent flow test/);

            // the level the operator saw is the narrowing the credential carries: the exact
            // pair list of the observe level, refusing every write and every mail read
            assert.deepEqual(tokenData.permissions, mcpGrantsFor({ manage: 'observe' }).permissions);
            assert.ok(allowed(tokenData, 'read', 'settings'));
            assert.ok(allowed(tokenData, 'read', 'account'));
            assert.ok(!allowed(tokenData, 'write', 'settings'));
            assert.ok(!allowed(tokenData, 'destructive', 'account'));
            assert.ok(!allowed(tokenData, 'read', 'message'));
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('management plus read-only mail mints one token holding both scopes, without crossing them', async () => {
        const { tokenResponse } = await approveAndRedeem({ manage: 'operate', mailEnabled: 'on', mailLevel: 'read' });

        assert.equal(tokenResponse.scope, 'mcp-manage mcp');

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp-manage', 'mcp']);
            assert.deepEqual(tokenData.permissions, mcpGrantsFor({ manage: 'operate', mail: 'read' }).permissions);

            // the whole reason the record is a pair list: writing settings does not make the
            // token able to write messages
            assert.ok(allowed(tokenData, 'write', 'settings'));
            assert.ok(allowed(tokenData, 'read', 'message'));
            assert.ok(!allowed(tokenData, 'write', 'message'));
            assert.ok(!allowed(tokenData, 'send', 'submit'));
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('full mail access with no management mints a mail-only token with an explicit grant list', async () => {
        const { tokenResponse } = await approveAndRedeem({ manage: 'none', mailEnabled: 'on', mailLevel: 'full' });

        assert.equal(tokenResponse.scope, 'mcp');

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp']);
            // never an absent record: the widest choice still lists what it grants, so a tool
            // shipped later is not silently included
            assert.deepEqual(tokenData.permissions, { grants: MCP_SECTIONS.mail.levels.full });
            assert.ok(allowed(tokenData, 'send', 'submit'));
            assert.ok(allowed(tokenData, 'destructive', 'message'));
            assert.ok(!allowed(tokenData, 'read', 'settings'));
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('a mail level posted without the mail checkbox grants no mail access', async () => {
        // The radios are hidden while the box is unticked, but a stale form still posts them
        const { tokenResponse } = await approveAndRedeem({ manage: 'observe', mailLevel: 'full' });

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp-manage']);
            assert.ok(!allowed(tokenData, 'read', 'message'));
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('a payload naming no level mints the observe-only token, never a wide one', async () => {
        // The fail-safe direction of the schema defaults: a stale form or a hand-crafted POST
        // that omits every field gets the narrowest useful credential
        const { tokenResponse } = await approveAndRedeem({});

        const tokenData = await tokens.get(tokenResponse.access_token, false);
        try {
            assert.deepEqual(tokenData.scopes, ['mcp-manage']);
            assert.deepEqual(tokenData.permissions, mcpGrantsFor({ manage: 'observe' }).permissions);
        } finally {
            await tokens.delete(tokenResponse.access_token);
        }
    });

    await t.test('declining every section re-renders with the reason rather than minting a token that can do nothing', async () => {
        const res = await server.inject({
            method: 'POST',
            url: '/admin/mcp/authorize',
            payload: approvalPayload({ manage: 'none' }),
            headers: { 'x-test-admin': '1' }
        });

        assert.equal(res.statusCode, 200);
        assert.ok(!res.headers.location, 'nothing to mint must not redirect');
        assert.equal(res.result.template, 'mcp/authorize');
        assert.match(res.result.context.errors.access, /at least one kind of access/);
        // and the form comes back the way it was posted
        assert.equal(res.result.context.manageLevel, 'none');
    });

    await t.test('a management token bound to one account is minted with the binding', async () => {
        // A bound management credential is a per-account operator; the binding is enforced on
        // every injected request and the tool count reflects it, so the mint only has to carry it
        // What accountExists() reads: the account's own hash carrying its id
        await redis.hset(`${REDIS_PREFIX}iad:consent-test-bound`, 'account', 'consent-test-bound', 'name', 'Bound');
        try {
            const { tokenResponse } = await approveAndRedeem({ manage: 'operate', account: 'consent-test-bound' });
            const tokenData = await tokens.get(tokenResponse.access_token, false);
            try {
                assert.equal(tokenData.account, 'consent-test-bound');
                assert.deepEqual(tokenData.scopes, ['mcp-manage']);
                assert.match(tokenData.description, /\(consent-test-bound\)/);
            } finally {
                await tokens.delete(tokenResponse.access_token);
            }
        } finally {
            await redis.del(`${REDIS_PREFIX}iad:consent-test-bound`);
        }
    });
});
