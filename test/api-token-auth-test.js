'use strict';

// lib/api-token-auth.js: the api-token strategy's decision, exercised against the real route table
// (routes come from the same capture the route-table guardrail uses, so grants, bindings and MCP
// metadata are the ones production registers) with every I/O dependency stood in.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createMockLogger } = require('./helpers/mock-logger');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const { createApiTokenValidator } = require('../lib/api-token-auth');

function makeDeps(overrides = {}) {
    const audit = { allowed: [], denied: [] };
    const state = { rateLimitCalls: [], templateLookups: [] };
    const deps = {
        settings: { get: async key => (overrides.settings || {})[key] },
        tokens: {
            get: async token => {
                const tokenData = (overrides.tokens || {})[token];
                if (!tokenData) {
                    throw Object.assign(new Error('Unknown token'), { code: 'UnknownToken' });
                }
                return tokenData;
            },
            validateSessionToken: async (sid, token, account) => !!overrides.sessionTokenValid && sid === 'sid1' && account === 'acc1'
        },
        tokenAuditLog: {
            allowed: entry => audit.allowed.push(entry),
            denied: (entry, reason) => audit.denied.push({ entry, reason })
        },
        redis: {
            sismember: async (key, member) => {
                state.templateLookups.push({ key, member });
                return (overrides.ownTemplates || []).includes(member) ? 1 : 0;
            }
        },
        checkRateLimit: async (key, count, allowed, windowSize) => {
            state.rateLimitCalls.push({ key, count, allowed, windowSize });
            return overrides.rateLimit || { success: true, allowed, count: 1, ttl: 30 };
        },
        sessionPasswordVersion: async () => overrides.passwordVersion || 0,
        adminAccessAddresses: overrides.adminAccessAddresses || null,
        logger: createMockLogger()
    };
    return { validate: createApiTokenValidator(deps), audit, state };
}

test('api-token strategy decision', async t => {
    const { routes } = await captureApiRoutes();
    const routeFor = key => {
        const [method, path] = key.split(' ');
        const route = routes.find(entry => entry.method === method && entry.path === path);
        assert.ok(route, `${key} is registered`);
        return route;
    };

    const makeRequest = (key, { params = {}, query = {}, headers = {}, state = {}, app = {} } = {}) => {
        const route = routeFor(key);
        return {
            method: route.method,
            route: { method: route.method, path: route.path, settings: Object.assign({}, route.settings, { tags: route.tags }) },
            params,
            query,
            headers,
            state,
            app: Object.assign({ ip: '192.0.2.10' }, app)
        };
    };

    const MESSAGES = 'get /v1/account/{account}/messages';
    const messagesRequest = (opts = {}) => makeRequest(MESSAGES, Object.assign({ params: { account: 'acc1' } }, opts));

    const rejects = async (promise, statusCode, message) => {
        await assert.rejects(promise, err => {
            assert.equal(err.output.statusCode, statusCode);
            if (message) {
                assert.equal(err.output.payload.message, message);
            }
            return true;
        });
    };

    await t.test('tokens disabled: a request with no credential passes as preauth', async () => {
        const { validate } = makeDeps({ settings: { disableTokens: true } });
        const result = await validate(messagesRequest(), 'preauth');
        assert.deepEqual(result.credentials, { preauth: true });
    });

    await t.test('tokens disabled: a real token is still checked', async () => {
        const { validate } = makeDeps({ settings: { disableTokens: true } });
        await rejects(validate(messagesRequest(), 'deadbeef'), 401);
    });

    await t.test('an unknown token is refused with its reason code', async () => {
        const { validate } = makeDeps();
        await assert.rejects(validate(messagesRequest(), 'nope'), err => {
            assert.equal(err.output.statusCode, 401);
            assert.equal(err.output.payload.code, 'UnknownToken');
            return true;
        });
    });

    await t.test('an unrestricted token is accepted and audited once', async () => {
        const tokenData = { id: 't1', scopes: ['api'] };
        const { validate, audit } = makeDeps({ tokens: { tok: tokenData } });
        const result = await validate(messagesRequest(), 'tok');
        assert.equal(result.isValid, true);
        assert.deepEqual(result.credentials, { token: 'tok' });
        assert.equal(result.artifacts, tokenData);
        assert.equal(audit.allowed.length, 1);
        assert.equal(audit.allowed[0].account, 'acc1');
        assert.equal(audit.denied.length, 0);
    });

    await t.test('a token without the route scope is refused', async () => {
        const { validate, audit } = makeDeps({ tokens: { tok: { id: 't1', scopes: ['smtp'] } } });
        await assert.rejects(validate(messagesRequest(), 'tok'), err => {
            assert.equal(err.output.statusCode, 403);
            assert.equal(err.output.payload.requestedScope, 'api');
            return true;
        });
        assert.deepEqual(
            audit.denied.map(entry => entry.reason),
            ['scope']
        );
        assert.equal(audit.allowed.length, 0);
    });

    await t.test('the wildcard scope admits any route', async () => {
        const { validate } = makeDeps({ tokens: { tok: { id: 't1', scopes: ['*'] } } });
        assert.equal((await validate(messagesRequest(), 'tok')).isValid, true);
    });

    await t.test('an MCP surface scope is only honored on requests the MCP endpoint dispatched', async () => {
        const tokenData = { id: 't1', scopes: ['mcp'] };
        const { validate } = makeDeps({ tokens: { tok: tokenData } });
        await rejects(validate(messagesRequest(), 'tok'), 403, 'Unauthorized scope');
        assert.equal((await validate(messagesRequest({ app: { mcpInternal: true } }), 'tok')).isValid, true);
    });

    await t.test('a permissions record that lacks the grant is refused with the grant it lacked', async () => {
        const tokenData = { id: 't1', scopes: ['api'], permissions: { grants: [{ action: 'read', group: 'mailbox' }] } };
        const { validate, audit } = makeDeps({ tokens: { tok: tokenData } });
        await assert.rejects(validate(messagesRequest(), 'tok'), err => {
            assert.equal(err.output.statusCode, 403);
            assert.equal(err.output.payload.message, 'Unauthorized permission');
            assert.ok(err.output.payload.requiredPermission);
            return true;
        });
        assert.equal(audit.denied.length, 1);
    });

    await t.test('a scope refusal comes before a permission refusal', async () => {
        const tokenData = { id: 't1', scopes: ['smtp'], permissions: { grants: [] } };
        const { validate, audit } = makeDeps({ tokens: { tok: tokenData } });
        await rejects(validate(messagesRequest(), 'tok'), 403, 'Unauthorized scope');
        assert.equal(audit.denied[0].reason, 'scope');
    });

    await t.test('a bound token reaches its own account and no other', async () => {
        const { validate, audit } = makeDeps({ tokens: { tok: { id: 't1', account: 'acc1' } } });
        assert.equal((await validate(messagesRequest(), 'tok')).isValid, true);
        await rejects(validate(messagesRequest({ params: { account: 'acc2' } }), 'tok'), 403, 'Unauthorized account');
        assert.equal(audit.denied[0].reason, 'account');
        assert.equal(audit.denied[0].entry.account, 'acc2');
    });

    await t.test('a bound token on a query-bound route has to name its own account', async () => {
        const { validate } = makeDeps({ tokens: { tok: { id: 't1', account: 'acc1' } } });
        assert.equal((await validate(makeRequest('get /v1/tokens', { query: { account: 'acc1' } }), 'tok')).isValid, true);
        await rejects(validate(makeRequest('get /v1/tokens', { query: { account: 'acc2' } }), 'tok'), 403, 'Unauthorized account');
        await rejects(validate(makeRequest('get /v1/tokens'), 'tok'), 403, 'Unauthorized account');
        // a repeated ?account= arrives as an array and names no account
        await rejects(validate(makeRequest('get /v1/tokens', { query: { account: ['acc1', 'acc2'] } }), 'tok'), 403, 'Unauthorized account');
    });

    await t.test('a bound token reaches a template only when its account owns it', async () => {
        const { validate, state } = makeDeps({ tokens: { tok: { id: 't1', account: 'acc1' } }, ownTemplates: ['mine'] });
        const key = 'get /v1/templates/template/{template}';
        assert.equal((await validate(makeRequest(key, { params: { template: 'mine' } }), 'tok')).isValid, true);
        await rejects(validate(makeRequest(key, { params: { template: 'theirs' } }), 'tok'), 403, 'Unauthorized account');
        assert.deepEqual(state.templateLookups[0], { key: `${REDIS_PREFIX}tpl:acc1:i`, member: 'mine' });
    });

    await t.test('a bound token creating a template is pinned to its account', async () => {
        const { validate } = makeDeps({ tokens: { tok: { id: 't1', account: 'acc1' } } });
        const request = makeRequest('post /v1/templates/template');
        assert.equal((await validate(request, 'tok')).isValid, true);
        assert.equal(request.app.enforceAccount, 'acc1');
    });

    await t.test('an address restriction is enforced', async () => {
        const { validate, audit } = makeDeps({ tokens: { tok: { id: 't1', restrictions: { addresses: ['198.51.100.0/24'] } } } });
        await assert.rejects(validate(messagesRequest(), 'tok'), err => {
            assert.equal(err.output.payload.message, 'Unauthorized address');
            assert.equal(err.output.payload.remoteAddress, '192.0.2.10');
            return true;
        });
        assert.equal(audit.denied[0].reason, 'address');
        assert.equal((await validate(messagesRequest({ app: { ip: '198.51.100.7' } }), 'tok')).isValid, true);
    });

    await t.test('a referrer restriction is enforced', async () => {
        const { validate } = makeDeps({ tokens: { tok: { id: 't1', restrictions: { referrers: ['https://app.example.com/*'] } } } });
        await rejects(validate(messagesRequest({ headers: { referer: 'https://evil.example.net/' } }), 'tok'), 403, 'Unauthorized referrer');
        assert.equal((await validate(messagesRequest({ headers: { referer: 'https://app.example.com/page' } }), 'tok')).isValid, true);
    });

    await t.test('a rate limit sets headers on success and refuses with Retry-After when spent', async () => {
        const restrictions = { rateLimit: { maxRequests: 10, timeWindow: 60 } };
        const allowedRun = makeDeps({ tokens: { tok: { id: 't1', restrictions } } });
        const request = messagesRequest();
        await allowedRun.validate(request, 'tok');
        assert.deepEqual(allowedRun.state.rateLimitCalls, [{ key: 'api:t1', count: 1, allowed: 10, windowSize: 60 }]);
        assert.deepEqual(request.app.rateLimitHeaders, { 'X-RateLimit-Limit': 10, 'X-RateLimit-Reset': 30, 'X-RateLimit-Remaining': 9 });

        const spent = makeDeps({ tokens: { tok: { id: 't1', restrictions } }, rateLimit: { success: false, allowed: 10, count: 11, ttl: 12.2 } });
        await assert.rejects(spent.validate(messagesRequest(), 'tok'), err => {
            assert.equal(err.output.statusCode, 429);
            assert.equal(err.output.headers['Retry-After'], 13);
            return true;
        });
        assert.equal(spent.audit.denied[0].reason, 'rateLimit');
    });

    await t.test('an MCP-dispatched request does not spend the rate limit again', async () => {
        const { validate, state } = makeDeps({ tokens: { tok: { id: 't1', restrictions: { rateLimit: { maxRequests: 1, timeWindow: 60 } } } } });
        await validate(messagesRequest({ app: { mcpInternal: true } }), 'tok');
        assert.equal(state.rateLimitCalls.length, 0);
    });

    await t.test('the MCP endpoint defers the permission and account checks and writes no allow row', async () => {
        const mcpRoute = routes.find(route => route.path === '/mcp' && route.method === 'post');
        assert.ok(mcpRoute, 'the MCP endpoint is registered');
        const tokenData = { id: 't1', account: 'acc1', scopes: ['mcp'], permissions: { grants: [] } };
        const { validate, audit } = makeDeps({ tokens: { tok: tokenData } });
        const request = makeRequest('post /mcp');
        assert.equal((await validate(request, 'tok')).isValid, true);
        assert.equal(request.app.mcpBoundAccount, 'acc1');
        assert.equal(audit.allowed.length, 0);
    });

    await t.test('a session token inside the message browser grants is accepted', async () => {
        const { validate } = makeDeps({ sessionTokenValid: true });
        const request = messagesRequest({ state: { ee: { sid: 'sid1' } } });
        const result = await validate(request, 'sess_abc');
        assert.equal(result.isValid, true);
        assert.equal(request.app.sessionToken, true);
    });

    await t.test('a session token outside the message browser grants is refused', async () => {
        const { validate } = makeDeps({ sessionTokenValid: true });
        const request = makeRequest('put /v1/account/{account}', { params: { account: 'acc1' }, state: { ee: { sid: 'sid1' } } });
        await rejects(validate(request, 'sess_abc'), 403, 'Unauthorized permission');
    });

    await t.test('a session token from outside the admin perimeter is refused', async () => {
        const { validate } = makeDeps({ sessionTokenValid: true, adminAccessAddresses: ['203.0.113.0/24'] });
        await rejects(validate(messagesRequest({ state: { ee: { sid: 'sid1' } } }), 'sess_abc'), 403, 'Unauthorized address');
    });

    await t.test('a session token of an ended session is refused', async () => {
        const { validate } = makeDeps({ sessionTokenValid: true, passwordVersion: 5 });
        await rejects(validate(messagesRequest({ state: { ee: { sid: 'sid1', passwordVersion: 4 } } }), 'sess_abc'), 401, 'Session has ended');
    });

    await t.test('an invalid session token falls through to the token store', async () => {
        const { validate } = makeDeps({ sessionTokenValid: false });
        await rejects(validate(messagesRequest({ state: { ee: { sid: 'sid1' } } }), 'sess_abc'), 401, 'Bad token');
    });
});

registerRedisTeardown(redis);
