'use strict';

// Proves the dispatcher webhook deliveries use performs exactly one HTTP request per delivery
// attempt. The shared dispatcher (httpAgent.retry) retries a POST on a dropped socket or a 429 on
// its own, so a receiver that processed the event before resetting the connection would be handed
// the same event again with an identical X-EE-Wh-Id, invisible to the notify worker's logs,
// metrics and backoff. Retrying a webhook is the notify queue's job, so the webhook dispatcher has
// to leave a failed attempt failed.
//
// Runs under the default link-local egress policy, where loopback is reachable, so the dedicated
// policy-bound dispatcher is the one exercised; test/webhook-egress-dispatcher-test.js covers the
// policy itself under `private`.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');
const { fetch: fetchCmd } = require('undici');

const { httpAgent } = require('../lib/tools');
const registerRedisTeardown = require('./helpers/redis-teardown');

// lib/tools.js pulls in settings and its Redis client, which keeps the process alive
registerRedisTeardown();

// A receiver that drops the first connection mid-request and accepts every request after it: the
// shape of a receiver that processed the event and then reset the socket
async function withDroppingServer(fn) {
    let requests = 0;
    const server = http.createServer((req, res) => {
        requests++;
        if (requests === 1) {
            req.socket.destroy();
            return;
        }
        res.writeHead(202);
        res.end();
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}/hook`;

    try {
        await fn({ url, requestCount: () => requests });
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

test('webhook dispatcher does not retry on its own', async t => {
    await t.test('is a dedicated dispatcher, separate from the retrying one', () => {
        assert.notStrictEqual(httpAgent.webhook, httpAgent.retry);
        assert.notStrictEqual(httpAgent.webhook, httpAgent.fetch);
    });

    await t.test('a dropped socket fails the attempt after a single request', async () => {
        await withDroppingServer(async ({ url, requestCount }) => {
            await assert.rejects(fetchCmd(url, { method: 'post', body: '{}', dispatcher: httpAgent.webhook }));
            assert.strictEqual(requestCount(), 1, 'the event must have reached the receiver exactly once');
        });
    });

    await t.test('control: the shared retrying dispatcher sends the same POST again', async () => {
        await withDroppingServer(async ({ url, requestCount }) => {
            const res = await fetchCmd(url, { method: 'post', body: '{}', dispatcher: httpAgent.retry });
            await res.text();

            assert.strictEqual(res.status, 202);
            assert.strictEqual(requestCount(), 2, 'the retrying dispatcher must have repeated the request');
        });
    });
});
