'use strict';

// lib/webhook-failures.js and the failed webhook delivery routes on a bare Hapi server: the failed
// set of the notify queue, listed without payloads, retried and removed, and held to one account
// on the account routes.

const test = require('node:test');

// Own key prefix, set before any module reads it: the test files of the tier run in parallel on one
// database, and a job these put into a queue would otherwise be picked up by another file's worker
process.env.EENGINE_REDIS_PREFIX = 'test_webhook_failures';

const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');
const { Worker } = require('bullmq');

const { redis, notifyQueue, queueConf } = require('../lib/db');
const webhookFailures = require('../lib/webhook-failures');
const webhookDeliveryRoutes = require('../lib/api-routes/webhook-delivery-routes');
const { routeAdmitsBoundToken } = require('../lib/api-routes/account-binding');
const { routeGrant, GROUP } = require('../lib/api-routes/permission-map');
const registerRedisTeardown = require('./helpers/redis-teardown');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {}, child: () => logger };

const ACCOUNT = 'webhook-failures-a';
const OTHER = 'webhook-failures-b';

registerRedisTeardown(redis, () => notifyQueue.obliterate({ force: true }).catch(() => false));

test('failed webhook deliveries', async t => {
    const worker = new Worker('notify', null, Object.assign({ autorun: false }, queueConf));
    await worker.waitUntilReady();
    let token = 0;

    // Queues an event and fails its only attempt the way the notify worker would, recording the
    // receiver's answer on the progress field
    async function failDelivery(jobId, account, data = {}) {
        await notifyQueue.add(
            'messageNew',
            Object.assign(
                { account, path: 'INBOX', eventId: `${jobId}-event`, data: { messageId: `<${jobId}@example.com>`, subject: 'Secret subject', text: 'body' } },
                data
            ),
            { jobId, attempts: 1, removeOnComplete: true, removeOnFail: false }
        );
        const lock = `lock-${++token}`;
        const job = await worker.getNextJob(lock, { block: false });
        assert.equal(job.id, jobId, 'the fetched job is the one just added');
        await job.updateProgress({ status: 'error', error: { message: 'Request failed with status 503', statusCode: 503 } });
        await job.moveToFailed(new Error('Request failed with status 503'), lock, false);
        return job;
    }

    let server;
    t.before(async () => {
        await notifyQueue.obliterate({ force: true }).catch(() => false);
        // apart in time, so the failed set has an order to list them in
        const pause = () => new Promise(resolve => setTimeout(resolve, 10));
        await failDelivery('wf-a-1', ACCOUNT);
        await pause();
        await failDelivery('wf-b-1', OTHER);
        await pause();
        await failDelivery('wf-a-2', ACCOUNT);

        server = Hapi.server({});
        server.auth.scheme('test-token', () => ({ authenticate: (request, h) => h.authenticated({ credentials: { token: 'test' }, artifacts: {} }) }));
        server.auth.strategy('api-token', 'test-token');
        server.ext('onRequest', (request, h) => {
            request.logger = logger;
            request.app.gt = { gettext: text => text };
            return h.continue;
        });
        await webhookDeliveryRoutes({ server, CORS_CONFIG: false });
        await server.initialize();
    });

    t.after(() => worker.close());

    await t.test('every route is in the webhook-deliveries group, and the account routes admit a bound token', () => {
        const routes = server.table();
        assert.equal(routes.length, 6);
        for (const route of routes) {
            assert.equal(routeGrant(route).group, GROUP.WEBHOOK_DELIVERIES, `${route.method} ${route.path}`);
            if (route.path.startsWith('/v1/account/{account}/')) {
                assert.ok(routeAdmitsBoundToken(route.method, route.path), `${route.method} ${route.path}`);
            }
        }
    });

    await t.test('list() returns the failed set most recent first, without payloads', async () => {
        const listing = await webhookFailures.list({ logger });
        assert.deepEqual(
            listing.deliveries.map(entry => entry.id),
            ['wf-a-2', 'wf-b-1', 'wf-a-1']
        );
        assert.equal(listing.total, 3);
        const entry = listing.deliveries[0];
        assert.equal(entry.event, 'messageNew');
        assert.equal(entry.account, ACCOUNT);
        assert.equal(entry.path, 'INBOX');
        assert.equal(entry.messageId, '<wf-a-2@example.com>');
        assert.equal(entry.eventId, 'wf-a-2-event');
        assert.equal(entry.error.statusCode, 503);
        assert.equal(entry.error.message, 'Request failed with status 503');
        assert.ok(!JSON.stringify(listing).includes('Secret subject'), 'the event payload is not part of a listing');
    });

    await t.test('the account listing and the account filter hold only that account', async () => {
        const res = await server.inject({ method: 'GET', url: `/v1/account/${ACCOUNT}/webhooks/failed` });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(
            res.result.deliveries.map(entry => entry.id),
            ['wf-a-2', 'wf-a-1']
        );
        assert.equal(res.result.scanLimited, false);

        const filtered = await server.inject({ method: 'GET', url: `/v1/webhooks/failed?account=${OTHER}` });
        assert.deepEqual(
            filtered.result.deliveries.map(entry => entry.id),
            ['wf-b-1']
        );
    });

    await t.test("another account's delivery is not found on the account routes, and stays failed", async () => {
        for (const [method, url] of [
            ['POST', `/v1/account/${OTHER}/webhooks/failed/wf-a-1/retry`],
            ['DELETE', `/v1/account/${OTHER}/webhooks/failed/wf-a-1`]
        ]) {
            const res = await server.inject({ method, url });
            assert.equal(res.statusCode, 404, `${method} ${url}`);
            assert.equal(res.result.code, 'NotFound');
        }
        assert.equal(await notifyQueue.getJobState('wf-a-1'), 'failed');
    });

    await t.test('retry puts a failed delivery back with a fresh set of attempts, and refuses one that is not failed', async () => {
        const res = await server.inject({ method: 'POST', url: `/v1/account/${ACCOUNT}/webhooks/failed/wf-a-1/retry` });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result, { retried: true, id: 'wf-a-1' });
        assert.equal(await notifyQueue.getJobState('wf-a-1'), 'waiting');

        const again = await server.inject({ method: 'POST', url: '/v1/webhooks/failed/wf-a-1/retry' });
        assert.equal(again.statusCode, 409);
        assert.equal(again.result.code, 'NotFailed');

        const unknown = await server.inject({ method: 'POST', url: '/v1/webhooks/failed/no-such-delivery/retry' });
        assert.equal(unknown.statusCode, 404);
    });

    await t.test('remove takes a failed delivery out of the queue, and only a failed one', async () => {
        const waiting = await server.inject({ method: 'DELETE', url: '/v1/webhooks/failed/wf-a-1' });
        assert.equal(waiting.statusCode, 409, 'the retried delivery is waiting, not failed');

        const res = await server.inject({ method: 'DELETE', url: '/v1/webhooks/failed/wf-b-1' });
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result, { deleted: true, id: 'wf-b-1' });
        assert.equal(await notifyQueue.getJob('wf-b-1'), undefined);
    });
});
