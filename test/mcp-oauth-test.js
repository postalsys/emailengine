'use strict';

// The MCP OAuth authorization server core (lib/mcp/oauth.js): client registration policy, PKCE,
// and the single-use code exchange. Talks to the test Redis database like the other unit-tier
// suites; the HTTP shells around these functions are covered by the integration tier.

const crypto = require('crypto');

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const tokens = require('../lib/tokens');
const {
    registerClient,
    getClient,
    isAcceptableRedirectUri,
    isAcceptableResource,
    createAuthorizationCode,
    redeemAuthorizationCode,
    verifyPkce
} = require('../lib/mcp/oauth');

registerRedisTeardown(redis);

const ORIGIN = 'https://emailengine.example.com';

function pkcePair() {
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

test('MCP OAuth', async t => {
    await t.test('redirect URI policy', () => {
        assert.ok(isAcceptableRedirectUri('https://claude.ai/api/mcp/auth_callback'));
        assert.ok(isAcceptableRedirectUri('http://localhost:33418/callback'));
        assert.ok(isAcceptableRedirectUri('http://127.0.0.1:8080/cb'));
        assert.ok(isAcceptableRedirectUri('com.example.app:/oauth/callback'));

        assert.ok(!isAcceptableRedirectUri('http://example.com/callback'), 'plain http off the loopback');
        assert.ok(!isAcceptableRedirectUri('https://example.com/cb#fragment'), 'fragments are refused');
        assert.ok(!isAcceptableRedirectUri('javascript:alert(1)'));
        assert.ok(!isAcceptableRedirectUri('data:text/html,x'));
        assert.ok(!isAcceptableRedirectUri('not a url'));
    });

    await t.test('resource indicator validation', () => {
        assert.ok(isAcceptableResource(undefined, ORIGIN), 'absent is tolerated');
        assert.ok(isAcceptableResource(`${ORIGIN}/mcp`, ORIGIN));
        assert.ok(isAcceptableResource(`${ORIGIN}/mcp/`, ORIGIN), 'trailing slash normalized');
        assert.ok(isAcceptableResource(ORIGIN, ORIGIN), 'bare origin accepted');
        assert.ok(!isAcceptableResource('https://elsewhere.example.com/mcp', ORIGIN));
    });

    await t.test('registration keeps only acceptable redirect URIs and refuses none at all', async () => {
        const client = await registerClient({
            redirectUris: ['https://claude.ai/cb', 'http://example.com/evil'],
            clientName: 'Test client'
        });

        assert.match(client.client_id, /^[0-9a-f]{32}$/);
        assert.deepEqual(client.redirect_uris, ['https://claude.ai/cb']);
        assert.equal(client.token_endpoint_auth_method, 'none');

        const stored = await getClient(client.client_id);
        assert.equal(stored.client_name, 'Test client');

        await assert.rejects(registerClient({ redirectUris: ['http://example.com/evil'] }), /redirect_uris/);
    });

    await t.test('PKCE S256 verification', () => {
        const { verifier, challenge } = pkcePair();
        assert.ok(verifyPkce(verifier, challenge));
        assert.ok(!verifyPkce(verifier + 'x', challenge));
        assert.ok(!verifyPkce('too-short', challenge));
    });

    await t.test('a code redeems exactly once, for the right client, redirect and verifier', async () => {
        const client = await registerClient({ redirectUris: ['https://claude.ai/cb'], clientName: 'Redeemer' });
        const { verifier, challenge } = pkcePair();

        const mint = () =>
            createAuthorizationCode({
                clientId: client.client_id,
                redirectUri: 'https://claude.ai/cb',
                codeChallenge: challenge,
                resource: `${ORIGIN}/mcp`,
                account: null,
                description: 'MCP: Redeemer'
            });

        const base = {
            clientId: client.client_id,
            redirectUri: 'https://claude.ai/cb',
            codeVerifier: verifier,
            resource: `${ORIGIN}/mcp`,
            origin: ORIGIN,
            ip: '198.51.100.7'
        };

        // wrong client
        await assert.rejects(redeemAuthorizationCode(Object.assign({}, base, { code: await mint(), clientId: 'f'.repeat(32) })), /another client/);
        // wrong redirect
        await assert.rejects(redeemAuthorizationCode(Object.assign({}, base, { code: await mint(), redirectUri: 'https://claude.ai/other' })), /redirect_uri/);
        // wrong verifier
        await assert.rejects(redeemAuthorizationCode(Object.assign({}, base, { code: await mint(), codeVerifier: 'x'.repeat(64) })), /PKCE/);
        // wrong resource
        await assert.rejects(
            redeemAuthorizationCode(Object.assign({}, base, { code: await mint(), resource: 'https://elsewhere.example.com/mcp' })),
            /resource/
        );

        // the happy path issues a real mcp-scoped token...
        const code = await mint();
        const response = await redeemAuthorizationCode(Object.assign({}, base, { code }));
        assert.equal(response.token_type, 'Bearer');
        assert.equal(response.scope, 'mcp');

        const tokenData = await tokens.get(response.access_token, false);
        assert.deepEqual(tokenData.scopes, ['mcp']);
        assert.equal(tokenData.description, 'MCP: Redeemer');

        // ...and the code is spent
        await assert.rejects(redeemAuthorizationCode(Object.assign({}, base, { code })), /expired/);

        await tokens.delete(response.access_token);
    });
});
