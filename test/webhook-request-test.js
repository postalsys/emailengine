'use strict';

// Regression test for the webhook delivery socket leak (Commit 5).
//
// The webhook delivery drained the undici response body only on the !res.ok path;
// on a 2xx response the body was never read. With keepAlive a connection is only
// returned to the pool once its body is consumed, so successful (the common case)
// deliveries pinned pooled sockets. sendWebhookRequest() now drains on every path.

const test = require('node:test');
const assert = require('node:assert').strict;

const { sendWebhookRequest } = require('../lib/webhook-request');

function fakeResponse(overrides) {
    let drained = false;
    const res = Object.assign(
        {
            ok: true,
            status: 200,
            statusText: 'OK',
            async text() {
                drained = true;
                return '';
            }
        },
        overrides
    );
    return {
        res,
        wasDrained: () => drained
    };
}

test('sendWebhookRequest drains the body on a successful (2xx) response', async () => {
    const { res, wasDrained } = fakeResponse({ ok: true, status: 200 });
    const fakeFetch = async () => res;

    const status = await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' });

    assert.strictEqual(status, 200);
    assert.strictEqual(wasDrained(), true, 'success path must drain the response body to release the pooled socket');
});

test('sendWebhookRequest drains the body and throws with statusCode on a non-2xx response', async () => {
    const { res, wasDrained } = fakeResponse({ ok: false, status: 503, statusText: 'Service Unavailable' });
    const fakeFetch = async () => res;

    await assert.rejects(
        () => sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' }),
        err => {
            assert.strictEqual(err.statusCode, 503, 'error should carry the HTTP status code');
            return true;
        }
    );

    assert.strictEqual(wasDrained(), true, 'failure path must also drain the response body');
});
