'use strict';

// End-to-end coverage for the MCP endpoint against the shared test server: the runtime setting
// gate, both protocol eras over real HTTP, tool dispatch through the actual auth strategy, the
// mcp scope's surface binding, and the OAuth discovery/registration/token routes.
//
// Runs against the server started by test/run-tests.js (config/test.toml, prepared token with
// scope "*"). The mcpEnabled setting starts out false on a fresh database, which is itself the
// first thing asserted; the suite then enables it over the API and leaves it on - nothing else
// in the tier touches /mcp.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;

// The live server shares the test Redis database with this process (the same recipe as
// token-scope-test.js), so tokens and authorization codes provisioned through the libraries
// below are honored by the HTTP endpoints under test.
const tokens = require('../../lib/tokens');
const { redis } = require('../../lib/db');
const { createAuthorizationCode } = require('../../lib/mcp/oauth');
const { MCP_READ_ONLY_PERMISSIONS } = require('../../lib/token-permission-view');
const registerRedisTeardown = require('../helpers/redis-teardown');
const { pkcePair } = require('../helpers/pkce');

// Force the process to exit once tests finish; lib/db keeps connections open.
registerRedisTeardown(redis);

// Static access token provisioned via `preparedToken` in config/test.toml (scope "*").
const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const baseUrl = `http://127.0.0.1:${config.api.port}`;

const server = supertest.agent(baseUrl);
const authed = supertest.agent(baseUrl).auth(accessToken, { type: 'bearer' });

const MODERN = '2026-07-28';
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';

// The callback address every OAuth test registers; what claude.ai actually uses
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

let requestCounter = 0;

// Enables the OAuth flow settings around one test body and restores them after, so no other
// test in the serial tier sees the flow open
async function withOAuthEnabled(fn) {
    const stored = await authed.get('/v1/settings?serviceUrl=true');
    const previousServiceUrl = (stored.body && stored.body.serviceUrl) || '';

    const setup = await authed.post('/v1/settings').send({ mcpOAuthEnabled: true, serviceUrl: baseUrl });
    assert.equal(setup.status, 200);

    try {
        await fn();
    } finally {
        await authed.post('/v1/settings').send({ mcpOAuthEnabled: false, serviceUrl: previousServiceUrl });
    }
}

// Tool names from a tools/list response, in catalog order
const toolNames = res => res.body.result.tools.map(tool => tool.name);

// The three assertions that make a list_accounts tool call a success end to end: the door
// admitted it, the injected inner request succeeded, and the result carries the listing
function assertListAccountsOk(res) {
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 512));
    assert.ok(!res.body.result.isError, JSON.stringify(res.body.result).slice(0, 512));
    assert.ok(Array.isArray(res.body.result.structuredContent.accounts));
}

// A legacy-era (initialize-handshake revisions) JSON-RPC request
function legacyRpc(method, params) {
    return server
        .post('/mcp')
        .auth(accessToken, { type: 'bearer' })
        .set('MCP-Protocol-Version', '2025-06-18')
        .send({ jsonrpc: '2.0', id: ++requestCounter, method, params: params || {} });
}

// A modern-era request with the mirrored routing headers the revision requires
function modernRpc(method, params, opts) {
    opts = opts || {};
    params = Object.assign({}, params || {}, { _meta: { [META_VERSION]: opts.metaVersion || MODERN } });

    const req = server
        .post('/mcp')
        .auth(opts.token || accessToken, { type: 'bearer' })
        .set('MCP-Protocol-Version', opts.headerVersion || MODERN)
        .set('Mcp-Method', opts.headerMethod || method);

    if (params.name) {
        req.set('Mcp-Name', opts.headerName || params.name);
    }

    return req.send({ jsonrpc: '2.0', id: ++requestCounter, method, params });
}

test('MCP endpoint', async t => {
    await t.test('answers 404 while the mcpEnabled setting is off', async () => {
        const res = await legacyRpc('ping');
        assert.equal(res.status, 404);
        // the first error every integrator hits has to say where the switch is
        assert.match(res.body.message, /Configuration > MCP/);
    });

    await t.test('setting mcpEnabled over the API turns the endpoint on', async () => {
        const res = await authed.post('/v1/settings').send({ mcpEnabled: true });
        assert.equal(res.status, 200);

        const ping = await legacyRpc('ping');
        assert.equal(ping.status, 200);
        assert.deepEqual(ping.body.result, {});
    });

    await t.test('requires a valid access token', async () => {
        const res = await server.post('/mcp').set('MCP-Protocol-Version', '2025-06-18').send({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} });
        assert.equal(res.status, 401);
    });

    await t.test('GET and DELETE answer 405', async () => {
        for (const method of ['get', 'delete']) {
            const res = await server[method]('/mcp');
            assert.equal(res.status, 405);
            assert.equal(res.headers.allow, 'POST');
        }
    });

    await t.test('legacy era: initialize, tools/list, tools/call', async () => {
        const init = await legacyRpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } });
        assert.equal(init.status, 200);
        assert.equal(init.body.result.protocolVersion, '2025-06-18');
        assert.equal(init.body.result.serverInfo.name, 'EmailEngine');
        assert.ok(!init.headers['mcp-session-id'], 'stateless server must not mint a session');

        // a notification carries no id - the helper would add one, which turns it into a request
        const initialized = await server
            .post('/mcp')
            .auth(accessToken, { type: 'bearer' })
            .set('MCP-Protocol-Version', '2025-06-18')
            .send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        assert.equal(initialized.status, 202);

        const list = await legacyRpc('tools/list');
        assert.equal(list.status, 200);
        const names = toolNames(list);
        assert.ok(names.includes('list_accounts'));
        assert.ok(names.includes('send_message'));
        assert.equal(new Set(names).size, names.length);

        assertListAccountsOk(await legacyRpc('tools/call', { name: 'list_accounts', arguments: {} }));
    });

    await t.test('modern era: discover, tools/call, header enforcement', async () => {
        const discover = await modernRpc('server/discover');
        assert.equal(discover.status, 200);
        assert.equal(discover.body.result.resultType, 'complete');
        assert.ok(discover.body.result.supportedVersions.includes(MODERN));

        const call = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} });
        assert.equal(call.status, 200);
        assert.equal(call.body.result.resultType, 'complete');
        assert.ok(Array.isArray(call.body.result.structuredContent.accounts));

        // header/body version mismatch
        const mismatch = await modernRpc('ping', {}, { headerVersion: '2025-11-25' });
        assert.equal(mismatch.status, 400);
        assert.equal(mismatch.body.error.code, -32020);

        // unknown version
        const unsupported = await modernRpc('ping', {}, { headerVersion: '2030-01-01', metaVersion: '2030-01-01' });
        assert.equal(unsupported.status, 400);
        assert.equal(unsupported.body.error.code, -32022);
        assert.ok(unsupported.body.error.data.supported.includes(MODERN));

        // wrong Mcp-Name for the called tool
        const badName = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { headerName: 'other_tool' });
        assert.equal(badName.status, 400);
        assert.equal(badName.body.error.code, -32020);

        // unknown method is a 404 in the modern era
        const unknown = await modernRpc('prompts/list');
        assert.equal(unknown.status, 404);
        assert.equal(unknown.body.error.code, -32601);
    });

    await t.test('tool errors surface as results, not protocol failures', async () => {
        const unknownTool = await legacyRpc('tools/call', { name: 'no_such_tool', arguments: {} });
        assert.equal(unknownTool.status, 200);
        assert.equal(unknownTool.body.error.code, -32602);
        assert.match(unknownTool.body.error.message, /tools\/list/);

        const badArgs = await legacyRpc('tools/call', { name: 'list_accounts', arguments: { bogus: true } });
        assert.equal(badArgs.status, 200);
        assert.equal(badArgs.body.result.isError, true);
        assert.match(badArgs.body.result.content[0].text, /bogus/);
    });

    await t.test('an mcp-scoped token works here and nowhere else', async () => {
        const provision = await authed.post('/v1/tokens').send({
            description: 'mcp integration test token',
            scopes: ['mcp'],
            permissions: { actions: ['read'], groups: ['account'] }
        });
        assert.equal(provision.status, 200, JSON.stringify(provision.body));
        const mcpToken = provision.body.token;

        try {
            // admitted at the door and through the injected inner request
            assertListAccountsOk(await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: mcpToken }));

            // refused on plain REST with the scope error
            const rest = await server.get('/v1/accounts').auth(mcpToken, { type: 'bearer' });
            assert.equal(rest.status, 403);
            assert.match(rest.body.message, /scope/i);

            // the token's own permission narrowing still applies inside MCP
            const outbox = await modernRpc('tools/call', { name: 'get_outbox', arguments: {} }, { token: mcpToken });
            assert.equal(outbox.status, 200);
            assert.equal(outbox.body.result.isError, true);
            assert.match(outbox.body.result.content[0].text, /permission/i);

            // and the narrowing shapes the advertised catalog: read across the account group
            // is exactly two tools, so the agent never plans around a tool it cannot call
            const list = await modernRpc('tools/list', {}, { token: mcpToken });
            assert.equal(list.status, 200);
            assert.deepEqual(toolNames(list), ['get_account', 'list_accounts']);
        } finally {
            await tokens.delete(mcpToken);
        }
    });

    await t.test('a referrer-restricted token works over MCP when the outer request carries the Referer', async () => {
        const restricted = await tokens.provision({
            scopes: ['api'],
            restrictions: { referrers: ['https://allowed.example.com/*'] },
            description: 'mcp referrer restriction test',
            nolog: true
        });

        try {
            // no Referer refuses at the door, same as REST
            const bare = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: restricted });
            assert.equal(bare.status, 403);
            assert.match(bare.body.message, /referrer/i);

            // with a matching Referer the door passes AND the injected inner request passes -
            // the inner request re-runs the restriction, so this only works because the outer
            // Referer is forwarded to it
            assertListAccountsOk(
                await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: restricted }).set(
                    'Referer',
                    'https://allowed.example.com/dashboard'
                )
            );
        } finally {
            await tokens.delete(restricted);
        }
    });

    await t.test('a rate-limited token gets its whole budget as tool calls', async () => {
        // Each tool call is one outer /mcp request plus one injected inner request. The inner
        // one must not count against restrictions.rateLimit, or a token allowed N requests
        // silently got N/2 tool calls.
        const limited = await tokens.provision({
            scopes: ['api'],
            restrictions: { rateLimit: { maxRequests: 4, timeWindow: 3600 } },
            description: 'mcp rate limit test',
            nolog: true
        });

        try {
            for (let i = 0; i < 4; i++) {
                const call = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: limited });
                assert.equal(call.status, 200, `call ${i + 1} of 4 must fit the budget: ${JSON.stringify(call.body).slice(0, 512)}`);
                assert.ok(!call.body.result.isError, `call ${i + 1} of 4 must succeed: ${JSON.stringify(call.body.result).slice(0, 512)}`);
            }

            const over = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: limited });
            assert.equal(over.status, 429, 'the call past the budget is refused at the door');
        } finally {
            await tokens.delete(limited);
        }
    });

    await t.test('an account-bound token sees only the tools it can call', async () => {
        // A token can only be bound to an account that exists; the unreachable IMAP endpoint is
        // fine, the account never has to connect (same recipe as unsubscribe-events-test.js)
        const boundAccount = 'mcp-bound-test-account';
        const created = await authed.post('/v1/account').send({
            account: boundAccount,
            name: 'MCP bound test',
            email: 'mcp-bound@example.com',
            imap: { host: '127.0.0.1', port: 1, secure: false, auth: { user: 'mcp-bound@example.com', pass: 'secret' } },
            smtp: { host: '127.0.0.1', port: 1, secure: false, auth: { user: 'mcp-bound@example.com', pass: 'secret' } }
        });
        assert.equal(created.status, 200, JSON.stringify(created.body));

        try {
            const provision = await authed.post('/v1/tokens').send({
                description: 'mcp bound integration test token',
                scopes: ['mcp'],
                account: boundAccount
            });
            assert.equal(provision.status, 200, JSON.stringify(provision.body));

            const list = await modernRpc('tools/list', {}, { token: provision.body.token });
            assert.equal(list.status, 200);
            const names = toolNames(list);

            // the instance-wide listings would only ever answer a bound credential with a 403
            assert.ok(!names.includes('list_accounts'), 'list_accounts must be hidden from a bound credential');
            assert.ok(!names.includes('get_outbox'), 'get_outbox must be hidden from a bound credential');
            assert.ok(names.includes('get_message'));
            assert.ok(names.includes('list_mailboxes'));
        } finally {
            // removing the account also revokes the tokens bound to it
            await authed.delete(`/v1/account/${boundAccount}`);
        }
    });

    await t.test('OAuth discovery is closed until mcpOAuthEnabled and serviceUrl are set', async () => {
        const closed = await server.get('/.well-known/oauth-authorization-server');
        assert.equal(closed.status, 404);

        await withOAuthEnabled(async () => {
            const asMeta = await server.get('/.well-known/oauth-authorization-server');
            assert.equal(asMeta.status, 200);
            assert.equal(asMeta.body.issuer, baseUrl);
            assert.deepEqual(asMeta.body.code_challenge_methods_supported, ['S256']);

            const prm = await server.get('/.well-known/oauth-protected-resource/mcp');
            assert.equal(prm.status, 200);
            assert.equal(prm.body.resource, `${baseUrl}/mcp`);
            assert.deepEqual(prm.body.authorization_servers, [baseUrl]);

            // an unauthenticated /mcp request now advertises the resource metadata
            const challenge = await server.post('/mcp').set('MCP-Protocol-Version', '2025-06-18').send({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} });
            assert.equal(challenge.status, 401);
            assert.match(challenge.headers['www-authenticate'] || '', /resource_metadata=/);

            // dynamic registration refuses a list carrying any unacceptable redirect URI
            // (RFC 7591), naming the refused entry instead of silently registering the rest
            const rejected = await server
                .post('/mcp/oauth/register')
                .send({ redirect_uris: [REDIRECT_URI, 'http://evil.example.com/cb'], client_name: 'Integration test client' });
            assert.equal(rejected.status, 400);
            assert.equal(rejected.body.error, 'invalid_redirect_uri');
            assert.match(rejected.body.error_description, /evil\.example\.com/);

            const registration = await server.post('/mcp/oauth/register').send({ redirect_uris: [REDIRECT_URI], client_name: 'Integration test client' });
            assert.equal(registration.status, 201);
            assert.deepEqual(registration.body.redirect_uris, [REDIRECT_URI]);
            assert.equal(registration.body.token_endpoint_auth_method, 'none');

            // a bogus code is refused with an OAuth error shape
            const redeem = await server
                .post('/mcp/oauth/token')
                .type('form')
                .send({
                    grant_type: 'authorization_code',
                    code: crypto.randomBytes(32).toString('base64url'),
                    client_id: registration.body.client_id,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: crypto.randomBytes(48).toString('base64url'),
                    resource: `${baseUrl}/mcp`
                });
            assert.equal(redeem.status, 400);
            assert.equal(redeem.body.error, 'invalid_grant');
        });
    });

    await t.test('the consent page never redirects off-origin before a human decides', async () => {
        // Its own cookie jar: the consent form is CSRF-protected, so the crumb cookie set by the
        // GET has to be presented with the POST
        const browser = supertest.agent(baseUrl);

        await withOAuthEnabled(async () => {
            const registration = await server.post('/mcp/oauth/register').send({ redirect_uris: [REDIRECT_URI], client_name: 'Consent test client' });
            assert.equal(registration.status, 201);

            const params = new URLSearchParams({
                client_id: registration.body.client_id,
                redirect_uri: REDIRECT_URI,
                response_type: 'code',
                state: 'test-state',
                code_challenge: 'a'.repeat(43),
                code_challenge_method: 'S256'
            });

            // Registration is open and unauthenticated, so a validated redirect_uri is not
            // enough to make an automatic redirect safe: anyone can register their own address
            // and aim these at it. Every pre-consent failure has to render, not redirect.
            for (const [key, value] of [
                ['response_type', 'token'],
                ['code_challenge_method', 'plain'],
                ['resource', 'https://elsewhere.example.com/mcp']
            ]) {
                const probe = new URLSearchParams(params);
                probe.set(key, value);

                const res = await browser.get(`/admin/mcp/authorize?${probe.toString()}`);
                assert.equal(res.status, 200, `${key}=${value} must render, not redirect`);
                assert.ok(!res.headers.location, `${key}=${value} must not send a Location header`);
                assert.ok(!(res.text || '').includes(REDIRECT_URI), `${key}=${value} must not link the client address`);
            }

            const consent = await browser.get(`/admin/mcp/authorize?${params.toString()}`);
            assert.equal(consent.status, 200);
            // the three access levels, with read-only pre-selected as the default
            for (const level of ['read', 'mail', 'full']) {
                assert.match(consent.text, new RegExp(`name="access" value="${level}"`), `the consent form offers the ${level} level`);
            }
            assert.match(consent.text, /value="read"\s+checked/, 'read-only must be the pre-selected level');

            const crumb = (consent.text.match(/name="crumb"\s+value="([^"]+)"/) || [])[1];
            assert.ok(crumb, 'the consent form carries a crumb');

            // Denying is the one decision that needs no admin session - this tier runs with no
            // admin password, so the page hides Approve and tells the operator exactly that
            const denied = await browser
                .post('/admin/mcp/authorize')
                .type('form')
                .send({
                    crumb,
                    client_id: registration.body.client_id,
                    redirect_uri: REDIRECT_URI,
                    state: 'test-state',
                    code_challenge: 'a'.repeat(43),
                    decision: 'deny'
                });

            assert.equal(denied.status, 302, 'Deny must answer the client, not 403');
            assert.match(denied.headers.location, /error=access_denied/);
            assert.match(denied.headers.location, /state=test-state/);
        });
    });

    await t.test('an approved authorization redeems over HTTP into a token that works at /mcp', async () => {
        await withOAuthEnabled(async () => {
            const registration = await server.post('/mcp/oauth/register').send({ redirect_uris: [REDIRECT_URI], client_name: 'Redeem flow client' });
            assert.equal(registration.status, 201);

            const { verifier, challenge } = pkcePair();

            // The consent POST's outcome, minted directly into the shared Redis: the browser
            // half (render, session gate, Deny/Approve) is covered by test/mcp-consent-test.js;
            // what this tier adds is the half that needs the live server - the HTTP token
            // endpoint and the minted credential hitting the real /mcp door.
            const code = await createAuthorizationCode({
                clientId: registration.body.client_id,
                redirectUri: REDIRECT_URI,
                codeChallenge: challenge,
                resource: `${baseUrl}/mcp`,
                account: null,
                permissions: MCP_READ_ONLY_PERMISSIONS,
                description: 'MCP: Redeem flow client'
            });

            const redeem = await server
                .post('/mcp/oauth/token')
                .type('form')
                .send({
                    grant_type: 'authorization_code',
                    code,
                    client_id: registration.body.client_id,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: verifier,
                    resource: `${baseUrl}/mcp`
                });
            assert.equal(redeem.status, 200, JSON.stringify(redeem.body));
            assert.equal(redeem.body.token_type, 'Bearer');
            assert.equal(redeem.body.scope, 'mcp');
            assert.match(redeem.headers['cache-control'] || '', /no-store/);

            const oauthToken = redeem.body.access_token;
            try {
                // reads work through the real door and the injected inner request
                assertListAccountsOk(await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: oauthToken }));

                // the advertised catalog reflects the read-only narrowing: nothing that sends,
                // writes or deletes is listed to the agent
                const list = await modernRpc('tools/list', {}, { token: oauthToken });
                assert.equal(list.status, 200);
                const names = toolNames(list);
                assert.ok(names.includes('list_messages'));
                assert.ok(names.includes('search_messages'));
                for (const hidden of ['send_message', 'delete_message', 'update_message', 'move_message', 'create_draft']) {
                    assert.ok(!names.includes(hidden), `${hidden} must be hidden from a read-only credential`);
                }

                // the read-only narrowing the consent page defaults to reaches the wire: send
                // and destructive tools are refused by the token's own permission record
                for (const [name, toolArgs] of [
                    ['send_message', { account: 'redeem-flow-account' }],
                    ['delete_message', { account: 'redeem-flow-account', message: 'AAAAAQAACnA' }]
                ]) {
                    const refused = await modernRpc('tools/call', { name, arguments: toolArgs }, { token: oauthToken });
                    assert.equal(refused.status, 200, name);
                    assert.equal(refused.body.result.isError, true, name);
                    assert.match(refused.body.result.content[0].text, /permission/i, name);
                }

                // and the credential stays surface-bound: plain REST refuses it
                const rest = await server.get('/v1/accounts').auth(oauthToken, { type: 'bearer' });
                assert.equal(rest.status, 403);
            } finally {
                await tokens.delete(oauthToken);
            }
        });
    });

    // Last on purpose: it exhausts the per-IP registration budget, which stays spent for an
    // hour, and every earlier test that registers a client has already drawn from it
    await t.test('unauthenticated OAuth endpoints are rate limited per IP', async () => {
        // The budget is counted before the feature gate answers, so this needs no OAuth setup.
        // Walk to the refusal rather than assuming a fresh bucket.
        let refused;
        for (let i = 0; i < 25 && !refused; i++) {
            const res = await server.post('/mcp/oauth/register').send({ redirect_uris: ['https://claude.ai/cb'], client_name: `rate limit probe ${i}` });
            if (res.status === 429) {
                refused = res;
            }
        }

        assert.ok(refused, 'the per-IP registration budget must run out');
        assert.ok(refused.body.ttl > 0, 'the refusal names when to come back');
        assert.ok(Number(refused.headers['retry-after']) > 0, 'a 429 carries the conventional Retry-After header');
    });
});
