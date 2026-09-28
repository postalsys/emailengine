'use strict';

// POST /v1/tokens must not mint a token less restricted than the one calling it. Drives the real
// handler from lib/api-routes/token-routes.js against a recording mock server, with
// tokens.provision stubbed so nothing is written, plus the pure rule in
// lib/api-routes/mint-bounds.js for the containment edge cases.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const tokens = require('../lib/tokens');
const tokenRoutes = require('../lib/api-routes/token-routes');
const { mintWidenings } = require('../lib/api-routes/mint-bounds');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const logger = { warn() {}, error() {}, debug() {} };
const HOUR = 3600 * 1000;

test('mintWidenings', async t => {
    await t.test('an unrestricted, non-expiring creator may mint anything', () => {
        assert.deepEqual(mintWidenings({ id: 'x' }, { description: 'a' }), []);
        assert.deepEqual(mintWidenings(undefined, { description: 'a' }), []);
        assert.deepEqual(mintWidenings({ restrictions: { addresses: null, referrers: null, rateLimit: null } }, {}), []);
    });

    await t.test('addresses must be repeated within the creator allowlist', () => {
        const creator = { restrictions: { addresses: ['10.0.0.0/8', '192.168.1.5'] } };
        assert.equal(mintWidenings(creator, {}).length, 1, 'absent list is wider');
        assert.equal(mintWidenings(creator, { restrictions: { addresses: null } }).length, 1);
        assert.deepEqual(mintWidenings(creator, { restrictions: { addresses: ['10.1.2.3', '192.168.1.5'] } }), []);
        assert.deepEqual(mintWidenings(creator, { restrictions: { addresses: ['10.20.0.0/16'] } }), []);
        assert.deepEqual(mintWidenings(creator, { restrictions: { addresses: ['::ffff:10.1.2.3'] } }), [], 'mapped form of a covered address');
        assert.equal(mintWidenings(creator, { restrictions: { addresses: ['0.0.0.0/0'] } }).length, 1, 'a wider range');
        assert.equal(mintWidenings(creator, { restrictions: { addresses: ['10.1.2.3', '8.8.8.8'] } }).length, 1, 'one address outside');
        assert.equal(mintWidenings(creator, { restrictions: { addresses: ['192.168.1.0/24'] } }).length, 1, 'range around a single address');
        assert.equal(mintWidenings(creator, { restrictions: { addresses: ['::/0'] } }).length, 1, 'other family');
    });

    await t.test('referrers must be a subset of the creator list', () => {
        const creator = { restrictions: { referrers: ['https://a.example/*', 'https://b.example/*'] } };
        assert.equal(mintWidenings(creator, {}).length, 1);
        assert.deepEqual(mintWidenings(creator, { restrictions: { referrers: ['https://a.example/*'] } }), []);
        assert.equal(mintWidenings(creator, { restrictions: { referrers: ['*'] } }).length, 1);
    });

    await t.test('the rate limit may not be higher in burst or in rate', () => {
        const creator = { restrictions: { rateLimit: { maxRequests: 10, timeWindow: 60 } } };
        assert.equal(mintWidenings(creator, {}).length, 1);
        assert.deepEqual(mintWidenings(creator, { restrictions: { rateLimit: { maxRequests: 10, timeWindow: 60 } } }), []);
        assert.deepEqual(mintWidenings(creator, { restrictions: { rateLimit: { maxRequests: 5, timeWindow: 60 } } }), []);
        assert.equal(mintWidenings(creator, { restrictions: { rateLimit: { maxRequests: 10, timeWindow: 1 } } }).length, 1, 'same burst, faster rate');
        assert.equal(mintWidenings(creator, { restrictions: { rateLimit: { maxRequests: 100, timeWindow: 600 } } }).length, 1, 'same rate, bigger burst');
    });

    await t.test('the expiry may not be later than the creator expiry', () => {
        const expires = Date.now() + HOUR;
        const creator = { expires };
        assert.equal(mintWidenings(creator, {}).length, 1, 'a non-expiring token outlives its creator');
        assert.equal(mintWidenings(creator, { expires: new Date(expires + 1000) }).length, 1);
        assert.deepEqual(mintWidenings(creator, { expires: new Date(expires) }), []);
        assert.deepEqual(mintWidenings(creator, { expires: new Date(expires - HOUR / 2) }), []);
        // tokens.get() hands the expiry back as a Date on some paths
        assert.deepEqual(mintWidenings({ expires: new Date(expires) }, { expires: new Date(expires - 1000) }), []);
    });
});

test('POST /v1/tokens refuses to widen the calling token', async t => {
    const routes = [];
    await tokenRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }));
    const mint = routes.filter(r => r.method === 'POST' && ['/v1/tokens', '/v1/token'].includes(r.path));
    assert.equal(mint.length, 2, 'the current path and the deprecated alias');

    const originalProvision = tokens.provision;
    let provisioned = [];
    t.beforeEach(() => {
        provisioned = [];
        tokens.provision = async opts => {
            provisioned.push(opts);
            return 'a'.repeat(64);
        };
    });
    t.afterEach(() => {
        tokens.provision = originalProvision;
    });

    const payload = { description: 'child', scopes: ['api'], permissions: { groups: ['messages'], actions: ['read'] } };
    const call = (route, artifacts, extra) =>
        route.handler({
            payload: Object.assign({}, payload, extra),
            auth: { credentials: { token: 'x' }, artifacts },
            app: { ip: '127.0.0.1' },
            headers: {},
            logger
        });

    for (const route of mint) {
        await t.test(`${route.path}: an address-restricted token can not mint an unrestricted one`, async () => {
            await assert.rejects(call(route, { restrictions: { addresses: ['127.0.0.1'] } }), err => {
                assert.equal(err.output.statusCode, 403);
                assert.equal(err.output.payload.code, 'MintWidensRestrictions');
                return true;
            });
            assert.equal(provisioned.length, 0, 'nothing minted');
        });

        await t.test(`${route.path}: an expiring token can not mint a non-expiring one`, async () => {
            await assert.rejects(call(route, { expires: Date.now() + HOUR }), err => err.output.statusCode === 403);
            assert.equal(provisioned.length, 0);
        });

        await t.test(`${route.path}: repeating the limits at least as narrowly mints`, async () => {
            const expires = Date.now() + HOUR;
            const result = await call(
                route,
                { restrictions: { addresses: ['127.0.0.0/8'], rateLimit: { maxRequests: 10, timeWindow: 10 } }, expires },
                { restrictions: { addresses: ['127.0.0.1'], rateLimit: { maxRequests: 5, timeWindow: 10 } }, expires: new Date(expires - 1000) }
            );
            assert.equal(result.token.length, 64);
            assert.equal(provisioned.length, 1);
        });

        await t.test(`${route.path}: an unrestricted caller is unaffected`, async () => {
            const result = await call(route, { id: 'root' });
            assert.equal(result.token.length, 64);
        });
    }
});
