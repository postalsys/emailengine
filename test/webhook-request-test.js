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

// Wall-clock timeout: the notify worker runs with concurrency 1 by default, so a
// hung endpoint with no request timeout used to stall all webhook deliveries.

test('sendWebhookRequest always passes an abort signal to fetch, even without an explicit timeout', async () => {
    const { res } = fakeResponse({});
    let seenOptions;
    const fakeFetch = async (url, options) => {
        seenOptions = options;
        return res;
    };

    await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' });

    assert.ok(seenOptions.signal instanceof AbortSignal, 'fetch must receive an abort signal so a hung request cannot stall the worker');
});

test('sendWebhookRequest strips the timeout option from the fetch options', async () => {
    const { res } = fakeResponse({});
    let seenOptions;
    const fakeFetch = async (url, options) => {
        seenOptions = options;
        return res;
    };

    await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post', timeout: 5000 });

    assert.strictEqual(seenOptions.timeout, undefined, 'timeout is consumed by sendWebhookRequest, not forwarded to fetch');
    assert.strictEqual(seenOptions.method, 'post');
});

test('sendWebhookRequest rejects a hung request with ETIMEDOUT after the timeout', async () => {
    const hungFetch = (url, options) =>
        new Promise((resolve, reject) => {
            options.signal.addEventListener('abort', () => reject(options.signal.reason));
        });

    await assert.rejects(
        () => sendWebhookRequest(hungFetch, 'http://webhook.test/hook', { method: 'post', timeout: 50 }),
        err => {
            assert.strictEqual(err.code, 'ETIMEDOUT', 'timeouts should surface as ETIMEDOUT delivery errors');
            return true;
        }
    );
});

test('sendWebhookRequest rejects a hung response body with ETIMEDOUT instead of swallowing it', async () => {
    const timeoutErr = new Error('body read aborted');
    timeoutErr.name = 'TimeoutError';
    const { res } = fakeResponse({
        text: () => Promise.reject(timeoutErr)
    });
    const fakeFetch = async () => res;

    await assert.rejects(
        () => sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post', timeout: 5000 }),
        err => {
            assert.strictEqual(err.code, 'ETIMEDOUT');
            return true;
        }
    );
});

test('sendWebhookRequest still ignores non-timeout drain errors', async () => {
    const { res } = fakeResponse({
        status: 204,
        statusText: 'No Content',
        text: () => Promise.reject(new Error('read failed'))
    });
    const fakeFetch = async () => res;

    const status = await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' });
    assert.strictEqual(status, 204);
});

// Egress policy plumbing. A validateTarget callback both vets the destination before the request
// and switches redirect handling to manual, because fetch() would otherwise follow a Location
// header to a destination the policy never got to inspect. See lib/egress-filter.js

test('sendWebhookRequest vets the destination before issuing the request', async () => {
    let fetched = false;
    const fakeFetch = async () => {
        fetched = true;
        return fakeResponse().res;
    };

    await assert.rejects(
        sendWebhookRequest(fakeFetch, 'http://169.254.169.254/hook', {
            method: 'post',
            validateTarget: async () => {
                let err = new Error('Refusing to deliver to a blocked address');
                err.code = 'EEGRESSBLOCKED';
                throw err;
            }
        }),
        err => err.code === 'EEGRESSBLOCKED'
    );

    assert.strictEqual(fetched, false, 'a blocked destination must never be contacted');
});

test('sendWebhookRequest switches to manual redirects only when a target validator is set', async () => {
    let seenOptions;
    const fakeFetch = async (url, options) => {
        seenOptions = options;
        return fakeResponse().res;
    };

    await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post', validateTarget: async () => {} });
    assert.strictEqual(seenOptions.redirect, 'manual');
    // The callback itself must not leak into the fetch options
    assert.ok(!('validateTarget' in seenOptions));

    // With the policy off there is nothing to vet, so fetch keeps following redirects as before
    await sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' });
    assert.strictEqual(seenOptions.redirect, undefined);
});

test('sendWebhookRequest reports a redirect instead of following it', async () => {
    // undici returns the 3xx itself under redirect:'manual'
    const { res } = fakeResponse({ ok: false, status: 307, statusText: 'Temporary Redirect' });
    const fakeFetch = async () => res;

    await assert.rejects(
        sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', {
            method: 'post',
            validateTarget: async () => {}
        }),
        err => err.code === 'EREDIRECTNOTFOLLOWED'
    );
});

test('sendWebhookRequest passes a 3xx through as an ordinary failure without a validator', async () => {
    // With the policy off, redirect:'follow' is left in place and a 3xx only reaches here if the
    // caller opted out of manual handling, so it must not be reported as a redirect refusal
    const { res } = fakeResponse({ ok: false, status: 302, statusText: 'Found' });
    const fakeFetch = async () => res;

    await assert.rejects(sendWebhookRequest(fakeFetch, 'http://webhook.test/hook', { method: 'post' }), err => err.statusCode === 302 && !err.code);
});
