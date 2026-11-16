'use strict';

// The admin SSO strategies registered on a real hapi server with @hapi/bell, the way workers/api.js
// registers them. bell validates its options with joi when a strategy is registered, so this is
// also what proves the joi it resolves to (package.json `overrides` points it at the root joi 18)
// accepts the options EmailEngine passes.

// lib/sso reads these when it loads
process.env.OIDC_ISSUER = 'https://idp.example.com/realms/ee';
process.env.OIDC_CLIENT_ID = 'emailengine';
process.env.OIDC_CLIENT_SECRET = 'oidc-secret';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const pathlib = require('node:path');

const Hapi = require('@hapi/hapi');
const Bell = require('@hapi/bell');

const { registerOktaAuth, registerOidcAuth } = require('../lib/sso-routes');
const sso = require('../lib/sso');
const { createMockLogger } = require('./helpers/mock-logger');
const exitWhenStandalone = require('./helpers/exit-standalone');

exitWhenStandalone();

const DISCOVERY = {
    issuer: 'https://idp.example.com/realms/ee',
    authorization_endpoint: 'https://idp.example.com/realms/ee/protocol/openid-connect/auth',
    token_endpoint: 'https://idp.example.com/realms/ee/protocol/openid-connect/token',
    userinfo_endpoint: 'https://idp.example.com/realms/ee/protocol/openid-connect/userinfo',
    end_session_endpoint: 'https://idp.example.com/realms/ee/protocol/openid-connect/logout'
};

async function createServer() {
    const server = Hapi.server();
    await server.register(Bell);

    const flashes = [];
    server.ext('onRequest', (request, h) => {
        request.app.ip = '127.0.0.1';
        // workers/api.js gets this from lib/hapi-request-logger.js
        request.logger = createMockLogger();
        request.flash = async message => {
            flashes.push(message);
        };
        return h.continue;
    });

    const ctx = {
        secureCookie: false,
        getCookiePassword: async () => 'a-cookie-password-of-at-least-32-characters',
        getServiceRedirectUrl: async () => new URL('https://ee.example.com'),
        sessionPasswordVersion: async () => 1,
        logger: createMockLogger()
    };

    return { server, ctx, flashes };
}

// A probe route to call the toolkit decorations from
function addProbe(server) {
    server.route({
        method: 'GET',
        path: '/probe',
        async handler(request, h) {
            return {
                oktaValid: typeof h.validateOktaConfig === 'function' ? await h.validateOktaConfig() : null,
                oidcValid: typeof h.validateOidcConfig === 'function' ? await h.validateOidcConfig() : null,
                logoutUrl: typeof h.oidcLogoutUrl === 'function' ? h.oidcLogoutUrl('id-token') : null
            };
        }
    });
}

test('bell resolves to the root joi', () => {
    const lock = JSON.parse(fs.readFileSync(pathlib.join(__dirname, '..', 'package-lock.json'), 'utf8'));
    const nested = Object.keys(lock.packages).filter(key => key.startsWith('node_modules/@hapi/bell/node_modules/'));
    assert.deepEqual(nested, [], 'bell carries no copy of its own of joi or anything joi pulls in');
    assert.equal(require.resolve('joi', { paths: [pathlib.dirname(require.resolve('@hapi/bell'))] }), require.resolve('joi'));
});

test('Okta strategy', async t => {
    await t.test('registers and sends the browser to the Okta authorize endpoint', async () => {
        const { server, ctx } = await createServer();
        await registerOktaAuth(server, ctx, { baseUrl: 'https://dev-1.okta.com', clientId: 'okta-client', clientSecret: 'okta-secret' });

        const res = await server.inject({ method: 'GET', url: '/admin/login/okta' });
        assert.equal(res.statusCode, 302);
        const location = new URL(res.headers.location);
        assert.equal(location.origin + location.pathname, 'https://dev-1.okta.com/oauth2/v1/authorize');
        assert.equal(location.searchParams.get('client_id'), 'okta-client');
        assert.equal(location.searchParams.get('redirect_uri'), 'https://ee.example.com/admin/login/okta');
    });

    await t.test('a sign-in the IdP denied flashes and returns to the login form', async () => {
        const { server, ctx, flashes } = await createServer();
        await registerOktaAuth(server, ctx, { baseUrl: 'https://dev-1.okta.com', clientId: 'okta-client', clientSecret: 'okta-secret' });

        const res = await server.inject({ method: 'GET', url: '/admin/login/okta?error=access_denied' });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, '/admin/login?sso_denied=1');
        assert.equal(flashes.length, 1);
        assert.equal(flashes[0].type, 'danger');
    });

    await t.test('validateOktaConfig follows the service URL origin', async () => {
        const { server, ctx } = await createServer();
        let serviceUrl = 'https://ee.example.com';
        ctx.getServiceRedirectUrl = async () => new URL(serviceUrl);
        await registerOktaAuth(server, ctx, { baseUrl: 'https://dev-1.okta.com', clientId: 'okta-client', clientSecret: 'okta-secret' });
        addProbe(server);

        assert.equal(JSON.parse((await server.inject('/probe')).payload).oktaValid, true);
        serviceUrl = 'https://moved.example.com';
        assert.equal(JSON.parse((await server.inject('/probe')).payload).oktaValid, false);
    });
});

test('OIDC strategy', async t => {
    const allow = { allowList: sso.parseAllowList(null), allowGroups: sso.parseGroupList(null) };

    await t.test('with discovery at boot: registers and sends the browser to the IdP with PKCE', async () => {
        const { server, ctx } = await createServer();
        const { retry } = await registerOidcAuth(server, ctx, { ...allow, fetchDiscovery: async () => DISCOVERY });
        assert.equal(retry, null);
        addProbe(server);

        const res = await server.inject({ method: 'GET', url: '/admin/login/oidc' });
        assert.equal(res.statusCode, 302);
        const location = new URL(res.headers.location);
        assert.equal(location.origin + location.pathname, DISCOVERY.authorization_endpoint);
        assert.equal(location.searchParams.get('client_id'), 'emailengine');
        assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
        assert.ok(location.searchParams.get('code_challenge'));
        assert.equal(location.searchParams.get('redirect_uri'), 'https://ee.example.com/admin/login/oidc');

        const probe = JSON.parse((await server.inject('/probe')).payload);
        assert.equal(probe.oidcValid, true);
    });

    await t.test('a sign-in the IdP denied flashes and returns to the login form', async () => {
        const { server, ctx, flashes } = await createServer();
        await registerOidcAuth(server, ctx, { ...allow, fetchDiscovery: async () => DISCOVERY });

        const res = await server.inject({ method: 'GET', url: '/admin/login/oidc?error=access_denied' });
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, '/admin/login?sso_denied=1');
        assert.equal(flashes.length, 1);
    });

    await t.test('with discovery failing at boot: SSO stays off until the retry succeeds', async () => {
        const { server, ctx } = await createServer();
        let resolveRetry;
        const retried = new Promise(resolve => {
            resolveRetry = resolve;
        });
        const { retry } = await registerOidcAuth(server, ctx, {
            ...allow,
            fetchDiscovery: async () => {
                throw new Error('IdP unreachable');
            },
            retryDiscovery: () => retried
        });
        assert.ok(retry, 'a background retry is running');
        addProbe(server);

        assert.equal(JSON.parse((await server.inject('/probe')).payload).oidcValid, false);
        assert.equal(JSON.parse((await server.inject('/probe')).payload).logoutUrl, null);

        // the callback route exists from the start, so nothing is added to the table after the server starts
        assert.ok(server.table().some(route => route.path === '/admin/login/oidc'));
        // and a sign-in started before discovery succeeded fails back to the login form
        const early = await server.inject({ method: 'GET', url: '/admin/login/oidc' });
        assert.equal(early.statusCode, 302);
        assert.equal(early.headers.location, '/admin/login?sso_denied=1');

        resolveRetry(DISCOVERY);
        await retry;

        assert.equal(JSON.parse((await server.inject('/probe')).payload).oidcValid, true);
        const res = await server.inject({ method: 'GET', url: '/admin/login/oidc' });
        assert.equal(res.statusCode, 302);
        assert.equal(new URL(res.headers.location).origin + new URL(res.headers.location).pathname, DISCOVERY.authorization_endpoint);
    });

    await t.test('a retry that gives up leaves SSO off and the server serving', async () => {
        const { server, ctx } = await createServer();
        const { retry } = await registerOidcAuth(server, ctx, {
            ...allow,
            fetchDiscovery: async () => {
                throw new Error('IdP unreachable');
            },
            retryDiscovery: async () => {
                throw new Error('gave up');
            }
        });
        await retry;
        addProbe(server);
        assert.equal(JSON.parse((await server.inject('/probe')).payload).oidcValid, false);
    });
});
