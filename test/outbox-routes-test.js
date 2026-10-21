'use strict';

// The outbox routes for one account (/v1/account/{account}/outbox...) and the account and state
// filters of GET /v1/outbox, driven through the real route module on a bare Hapi server with a
// stand-in api-token strategy. The account routes exist so a token bound to one account can see
// and manage its own outbox; what has to hold is that a queue ID of another account's message is
// not found there, whichever action is asked for.

const test = require('node:test');

// Own key prefix, set before any module reads it: the test files of the tier run in parallel on one
// database, and a job these put into a queue would otherwise be picked up by another file's worker
process.env.EENGINE_REDIS_PREFIX = 'test_outbox_routes';

const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');

const { redis, submitQueue } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const outboxRoutes = require('../lib/api-routes/outbox-routes');
const { routeAdmitsBoundToken } = require('../lib/api-routes/account-binding');
const registerRedisTeardown = require('./helpers/redis-teardown');

const ACCOUNT = 'outbox-routes-a';
const OTHER = 'outbox-routes-b';
const QUEUE_IDS = ['outbox-routes-a-1', 'outbox-routes-a-2', 'outbox-routes-b-1'];

async function queueMessage(account, queueId) {
    await redis.hsetBuffer(`${REDIS_PREFIX}iaq:${account}`, queueId, Buffer.from('encoded-message'));
    await submitQueue.add(
        'queued',
        { account, queueId, envelope: { from: 'sender@example.com', to: ['rcpt@example.com'] }, subject: 'Scheduled message' },
        { jobId: queueId, delay: 365 * 24 * 3600 * 1000, removeOnComplete: true, removeOnFail: true }
    );
}

async function cleanup() {
    await Promise.all(QUEUE_IDS.map(queueId => submitQueue.remove(queueId).catch(() => false)));
    await redis.unlink(`${REDIS_PREFIX}iaq:${ACCOUNT}`, `${REDIS_PREFIX}iaq:${OTHER}`);
}

registerRedisTeardown(redis, cleanup);

test('outbox routes', async t => {
    let server;

    t.before(async () => {
        server = Hapi.server({});
        server.auth.scheme('test-token', () => ({
            authenticate: (request, h) => h.authenticated({ credentials: { token: 'test' }, artifacts: {} })
        }));
        server.auth.strategy('api-token', 'test-token');
        server.ext('onRequest', (request, h) => {
            request.logger = { info() {}, error() {}, debug() {}, warn() {}, child: () => request.logger };
            // what failAction translates validation errors with
            request.app.gt = { gettext: text => text };
            return h.continue;
        });
        await outboxRoutes({ server, CORS_CONFIG: false });
        await server.initialize();

        await cleanup();
        await queueMessage(ACCOUNT, 'outbox-routes-a-1');
        await queueMessage(ACCOUNT, 'outbox-routes-a-2');
        await queueMessage(OTHER, 'outbox-routes-b-1');
    });

    await t.test('every account outbox route is reachable by a token bound to the account', () => {
        const accountRoutes = server.table().filter(route => route.path.startsWith('/v1/account/{account}/outbox'));
        assert.equal(accountRoutes.length, 5, 'list, get, retry, promote and delete');
        for (const route of accountRoutes) {
            assert.ok(routeAdmitsBoundToken(route.method, route.path), `${route.method} ${route.path}`);
            assert.ok(!route.settings.plugins.mcp, `${route.method} ${route.path} duplicates an instance tool, so it is not one`);
        }
    });

    await t.test('the account listing holds only that account', async () => {
        const res = await server.inject({ method: 'GET', url: `/v1/account/${ACCOUNT}/outbox` });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result.messages.map(message => message.queueId).sort(), ['outbox-routes-a-1', 'outbox-routes-a-2']);
        assert.equal(res.result.total, 2);
    });

    await t.test('GET /v1/outbox takes the same account filter, and a state filter', async () => {
        const res = await server.inject({ method: 'GET', url: `/v1/outbox?account=${OTHER}&state=delayed` });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(
            res.result.messages.map(message => message.queueId),
            ['outbox-routes-b-1']
        );

        const none = await server.inject({ method: 'GET', url: `/v1/outbox?account=${OTHER}&state=failed` });
        assert.equal(none.result.total, 0);

        const invalid = await server.inject({ method: 'GET', url: '/v1/outbox?state=completed' });
        assert.equal(invalid.statusCode, 400, 'only the outbox states can be asked for');
    });

    await t.test("another account's queue ID is not found on any account route, and nothing changes", async () => {
        const base = `/v1/account/${OTHER}/outbox/outbox-routes-a-1`;
        for (const [method, url] of [
            ['GET', base],
            ['POST', `${base}/retry`],
            ['POST', `${base}/promote`]
        ]) {
            const res = await server.inject({ method, url });
            assert.equal(res.statusCode, 404, `${method} ${url}`);
            assert.equal(res.result.code, 'NotFound', `${method} ${url} carries a code`);
        }

        const del = await server.inject({ method: 'DELETE', url: base });
        assert.equal(del.statusCode, 200);
        assert.equal(del.result.deleted, false);

        assert.equal(await submitQueue.getJobState('outbox-routes-a-1'), 'delayed');
        assert.equal(await redis.hexists(`${REDIS_PREFIX}iaq:${ACCOUNT}`, 'outbox-routes-a-1'), 1);
    });

    await t.test('the owning account reaches its message', async () => {
        const get = await server.inject({ method: 'GET', url: `/v1/account/${ACCOUNT}/outbox/outbox-routes-a-1` });
        assert.equal(get.statusCode, 200);
        assert.equal(get.result.queueId, 'outbox-routes-a-1');

        const promote = await server.inject({ method: 'POST', url: `/v1/account/${ACCOUNT}/outbox/outbox-routes-a-2/promote` });
        assert.equal(promote.statusCode, 200);
        assert.equal(promote.result.promoted, true);

        const del = await server.inject({ method: 'DELETE', url: `/v1/account/${ACCOUNT}/outbox/outbox-routes-a-1` });
        assert.equal(del.result.deleted, true);
        assert.equal(await redis.hexists(`${REDIS_PREFIX}iaq:${ACCOUNT}`, 'outbox-routes-a-1'), 0, 'the content goes with the job');
    });
});
