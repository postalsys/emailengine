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

// Static access token provisioned via `preparedToken` in config/test.toml (scope "*").
const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const baseUrl = `http://127.0.0.1:${config.api.port}`;

const server = supertest.agent(baseUrl);
const authed = supertest.agent(baseUrl).auth(accessToken, { type: 'bearer' });

const MODERN = '2026-07-28';
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';

let requestCounter = 0;

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
        const names = list.body.result.tools.map(tool => tool.name);
        assert.ok(names.includes('list_accounts'));
        assert.ok(names.includes('send_message'));
        assert.equal(new Set(names).size, names.length);

        const call = await legacyRpc('tools/call', { name: 'list_accounts', arguments: {} });
        assert.equal(call.status, 200);
        assert.ok(!call.body.result.isError, JSON.stringify(call.body.result).slice(0, 512));
        assert.ok(Array.isArray(call.body.result.structuredContent.accounts));
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

        // admitted at the door and through the injected inner request
        const call = await modernRpc('tools/call', { name: 'list_accounts', arguments: {} }, { token: mcpToken });
        assert.equal(call.status, 200, JSON.stringify(call.body).slice(0, 512));
        assert.ok(Array.isArray(call.body.result.structuredContent.accounts));

        // refused on plain REST with the scope error
        const rest = await server.get('/v1/accounts').auth(mcpToken, { type: 'bearer' });
        assert.equal(rest.status, 403);
        assert.match(rest.body.message, /scope/i);

        // the token's own permission narrowing still applies inside MCP
        const outbox = await modernRpc('tools/call', { name: 'get_outbox', arguments: {} }, { token: mcpToken });
        assert.equal(outbox.status, 200);
        assert.equal(outbox.body.result.isError, true);
        assert.match(outbox.body.result.content[0].text, /permission/i);
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
            const names = list.body.result.tools.map(tool => tool.name);

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

        const stored = await authed.get('/v1/settings?serviceUrl=true');
        const previousServiceUrl = (stored.body && stored.body.serviceUrl) || '';

        const setup = await authed.post('/v1/settings').send({ mcpOAuthEnabled: true, serviceUrl: baseUrl });
        assert.equal(setup.status, 200);

        try {
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

            // dynamic registration filters redirect URIs by policy
            const registration = await server
                .post('/mcp/oauth/register')
                .send({ redirect_uris: ['https://claude.ai/api/mcp/auth_callback', 'http://evil.example.com/cb'], client_name: 'Integration test client' });
            assert.equal(registration.status, 201);
            assert.deepEqual(registration.body.redirect_uris, ['https://claude.ai/api/mcp/auth_callback']);
            assert.equal(registration.body.token_endpoint_auth_method, 'none');

            // a bogus code is refused with an OAuth error shape
            const redeem = await server
                .post('/mcp/oauth/token')
                .type('form')
                .send({
                    grant_type: 'authorization_code',
                    code: crypto.randomBytes(32).toString('base64url'),
                    client_id: registration.body.client_id,
                    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
                    code_verifier: crypto.randomBytes(48).toString('base64url'),
                    resource: `${baseUrl}/mcp`
                });
            assert.equal(redeem.status, 400);
            assert.equal(redeem.body.error, 'invalid_grant');
        } finally {
            // restore rather than clear, mirroring how the webhook suites treat tier settings
            await authed.post('/v1/settings').send({ mcpOAuthEnabled: false, serviceUrl: previousServiceUrl });
        }
    });
});
