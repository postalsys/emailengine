'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Exercise the real provider API retry orchestration instead of a re-implementation: the Gmail
// and Graph request layers (lib/email-client/gmail/gmail-api.js, lib/email-client/outlook/graph-api.js)
// both run on lib/email-client/api-retry.js, and take the client as their first argument, so
// they are driven with a fake context whose oAuth2Client.request we control. A regression in
// the shipping retry/backoff logic now fails this suite.
const apiRetry = require('../lib/email-client/api-retry');
const graphApi = require('../lib/email-client/outlook/graph-api');
const gmailApi = require('../lib/email-client/gmail/gmail-api');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createOAuth2Context } = require('./helpers/oauth-context');
const { withInstantTimers } = require('./helpers/instant-timers');

registerRedisTeardown(redis);

const { MAX_RETRY_ATTEMPTS, RETRY_BASE_DELAY, RETRY_JITTER, MAX_RETRY_DELAY, MAX_TOTAL_RETRY_DELAY } = apiRetry;

// Every wait is the computed delay plus up to RETRY_JITTER of jitter
function assertDelayNear(delay, expected) {
    assert.ok(delay >= expected && delay < expected + RETRY_JITTER, `expected a wait of ${expected}..${expected + RETRY_JITTER} ms, got ${delay}`);
}

// Runs a request through the given transport with the retry waits resolving at once
async function runRetry(transport, requestImpl, { url = '/me', method = 'get', options = {} } = {}) {
    const { context, calls } = createOAuth2Context({ request: requestImpl });
    const { result, error, delays } = await withInstantTimers(() => transport(context, url, method, {}, options));
    return { result, error, calls: calls.requests, delays };
}

const runGraph = (requestImpl, opts) => runRetry(graphApi.requestWithRetry, requestImpl, opts);
const runGmail = (requestImpl, opts) => runRetry(gmailApi.request, requestImpl, { url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages', ...opts });

function statusError(status, retryAfter) {
    const err = new Error(`HTTP ${status}`);
    err.oauthRequest = { status };
    if (retryAfter !== undefined) {
        err.retryAfter = retryAfter;
        err.oauthRequest.retryAfter = retryAfter;
    }
    return err;
}

const rateLimitError = retryAfter => statusError(429, retryAfter);

function networkError(code = 'ECONNRESET') {
    const err = new Error('socket failed');
    err.code = code;
    return err;
}

const { Headers } = require('undici');
const { parseRetryAfter } = require('../lib/tools');

test('parseRetryAfter()', async t => {
    await t.test('reads seconds from a fetch Headers object and from a plain object in any casing', () => {
        assert.strictEqual(parseRetryAfter(new Headers({ 'Retry-After': '17' })), 17);
        assert.strictEqual(parseRetryAfter({ 'Retry-After': '2' }), 2);
        assert.strictEqual(parseRetryAfter({ 'retry-after': ' 0 ' }), 0);
        assert.strictEqual(parseRetryAfter({ 'RETRY-AFTER': '1.5' }), 1.5);
    });

    await t.test('an HTTP-date is the seconds left until it, never negative', () => {
        const soon = parseRetryAfter({ 'retry-after': new Date(Date.now() + 30000).toUTCString() });
        assert.ok(soon >= 29 && soon <= 31, `got ${soon}`);
        assert.strictEqual(parseRetryAfter({ 'retry-after': new Date(Date.now() - 60000).toUTCString() }), 0);
    });

    await t.test('an absent or unreadable header is null', () => {
        assert.strictEqual(parseRetryAfter(null), null);
        assert.strictEqual(parseRetryAfter({}), null);
        assert.strictEqual(parseRetryAfter(new Headers()), null);
        assert.strictEqual(parseRetryAfter({ 'retry-after': 'soon' }), null);
        assert.strictEqual(parseRetryAfter({ 'retry-after': '' }), null);
    });
});

test('api-retry policy', async t => {
    await t.test('constants are defined with expected values', () => {
        assert.strictEqual(MAX_RETRY_ATTEMPTS, 3);
        assert.strictEqual(RETRY_BASE_DELAY, 1000);
        // Waits are capped per retry and per request, so a request finishes (or fails) inside
        // the API worker's 10 s RPC timeout instead of sleeping after the caller gave up
        assert.strictEqual(MAX_RETRY_DELAY, 5000);
        assert.strictEqual(MAX_TOTAL_RETRY_DELAY, 8000);
        assert.ok(MAX_RETRY_DELAY < 10000 && MAX_TOTAL_RETRY_DELAY < 10000);
    });

    await t.test('retryDelay honours err.retryAfter, which is where the transport stores it', () => {
        assertDelayNear(apiRetry.retryDelay({ retryAfter: 3 }, 0), 3000);
    });

    await t.test('retryDelay caps a long Retry-After', () => {
        assert.strictEqual(apiRetry.retryDelay({ retryAfter: 600 }, 0), MAX_RETRY_DELAY);
    });

    await t.test('retryDelay falls back to exponential backoff', () => {
        assertDelayNear(apiRetry.retryDelay({}, 0), 1000);
        assertDelayNear(apiRetry.retryDelay({}, 1), 2000);
        assertDelayNear(apiRetry.retryDelay({}, 2), 4000);
    });

    // A POST that failed on the socket may have been applied: the response was lost, not the
    // request (audit finding API-CLIENT-5). Only a method that is safe to repeat is re-sent
    await t.test('a network error is retried for GET and HEAD only', () => {
        const policy = { options: {}, state: { serverErrorRetries: 0 }, isRateLimited: () => false, serverErrorStatuses: new Set() };
        assert.strictEqual(apiRetry.retryReason(networkError(), { ...policy, method: 'get' }), 'network');
        assert.strictEqual(apiRetry.retryReason(networkError(), { ...policy, method: 'HEAD' }), 'network');
        for (const method of ['post', 'PATCH', 'put', 'delete']) {
            assert.strictEqual(apiRetry.retryReason(networkError(), { ...policy, method }), false, method);
        }
    });
});

test('Outlook Graph API requestWithRetry', async t => {
    await t.test('succeeds on first attempt without retry', async () => {
        const { result, error, calls, delays } = await runGraph(() => ({ ok: true, data: 'test' }));
        assert.ifError(error);
        assert.strictEqual(calls, 1, 'Should only make one attempt');
        assert.strictEqual(delays.length, 0, 'Should not sleep');
        assert.deepStrictEqual(result, { ok: true, data: 'test' });
    });

    await t.test('retries on 429 and succeeds on second attempt', async () => {
        const { result, error, calls, delays } = await runGraph(attempt => {
            if (attempt === 0) {
                throw rateLimitError();
            }
            return { ok: true, attempt };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 2, 'Should make two attempts');
        assert.strictEqual(delays.length, 1);
        assertDelayNear(delays[0], RETRY_BASE_DELAY);
        assert.deepStrictEqual(result, { ok: true, attempt: 1 });
    });

    await t.test('stops once the total wait budget would be exceeded', async () => {
        const { error, calls, delays } = await runGraph(() => {
            throw rateLimitError();
        });
        assert.ok(error, 'Should throw after exhausting the budget');
        assert.strictEqual(error.oauthRequest.status, 429);
        assert.ok(calls >= 2 && calls <= MAX_RETRY_ATTEMPTS + 1);
        assert.ok(
            delays.every(d => d <= MAX_RETRY_DELAY),
            'every wait is capped'
        );
        assert.ok(delays.reduce((a, b) => a + b, 0) <= MAX_TOTAL_RETRY_DELAY, 'the waits stay inside the budget');
    });

    await t.test('throws immediately on non-429 client error (404)', async () => {
        const { error, calls, delays } = await runGraph(() => {
            throw statusError(404);
        });
        assert.ok(error);
        assert.strictEqual(error.oauthRequest.status, 404);
        assert.strictEqual(calls, 1, 'Should not retry');
        assert.strictEqual(delays.length, 0);
    });

    await t.test('throws immediately on 500 server error', async () => {
        const { error, calls } = await runGraph(() => {
            throw statusError(500);
        });
        assert.ok(error);
        assert.strictEqual(error.oauthRequest.status, 500);
        assert.strictEqual(calls, 1, 'Should not retry on 500');
    });

    await t.test('a Retry-After above the cap is capped', async () => {
        const { error, delays } = await runGraph(() => {
            throw rateLimitError(90); // server-requested 90s wait
        });
        assert.ok(error);
        assert.ok(delays.length >= 1);
        assert.ok(delays.every(d => d === MAX_RETRY_DELAY));
    });

    await t.test('a short Retry-After is honoured', async () => {
        const { error, delays } = await runGraph(attempt => {
            if (attempt === 0) {
                throw rateLimitError(2);
            }
            return { ok: true };
        });
        assert.ifError(error);
        assert.strictEqual(delays.length, 1);
        assertDelayNear(delays[0], 2000);
    });

    await t.test('respects custom maxRetries option', async () => {
        const { error, calls } = await runGraph(
            () => {
                throw rateLimitError();
            },
            { options: { maxRetries: 1 } }
        );
        assert.ok(error);
        assert.strictEqual(calls, 2, 'initial attempt + 1 retry');
    });

    await t.test('does not retry errors without a status code', async () => {
        const { error, calls, delays } = await runGraph(() => {
            throw new Error('Unexpected error');
        });
        assert.ok(error);
        assert.strictEqual(error.message, 'Unexpected error');
        assert.strictEqual(calls, 1, 'Should not retry non-HTTP errors');
        assert.strictEqual(delays.length, 0);
    });

    await t.test('retries a transient network error of a read', async () => {
        const { result, error, calls } = await runGraph(attempt => {
            if (attempt < 1) {
                throw networkError();
            }
            return { ok: true, attempt };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 2);
        assert.deepStrictEqual(result, { ok: true, attempt: 1 });
    });

    await t.test('a write that failed on the socket is not sent again', async () => {
        const { error, calls } = await runGraph(
            () => {
                throw networkError('ETIMEDOUT');
            },
            { url: '/me/messages/x/move', method: 'post' }
        );
        assert.strictEqual(error.code, 'ETIMEDOUT');
        assert.strictEqual(calls, 1);
    });

    await t.test('a read that hit a 503 is retried once', async () => {
        const { error, calls } = await runGraph(() => {
            throw statusError(503);
        });
        assert.strictEqual(error.oauthRequest.status, 503);
        assert.strictEqual(calls, 2);
    });

    await t.test('a write that hit a 503 is not retried', async () => {
        const { error, calls } = await runGraph(
            () => {
                throw statusError(503);
            },
            { url: '/me/messages/x/move', method: 'post' }
        );
        assert.strictEqual(error.oauthRequest.status, 503);
        assert.strictEqual(calls, 1);
    });

    await t.test('noRetry sends exactly once', async () => {
        const { error, calls } = await runGraph(
            () => {
                throw rateLimitError();
            },
            { url: '/me/sendMail', method: 'post', options: { noRetry: true } }
        );
        assert.strictEqual(error.oauthRequest.status, 429);
        assert.strictEqual(calls, 1);
    });
});

function gmailRateLimit403() {
    const err = new Error('Rate limited');
    err.oauthRequest = { status: 403, response: { error: { errors: [{ reason: 'userRateLimitExceeded' }] } } };
    return err;
}

test('Gmail API request retries', async t => {
    await t.test('a rate-limit 403 is retried (Gmail throttles with it, not with a 429)', async () => {
        const { result, error, calls } = await runGmail(attempt => {
            if (attempt === 0) {
                throw gmailRateLimit403();
            }
            return { ok: true };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 2);
        assert.deepStrictEqual(result, { ok: true });
    });

    await t.test('a 429 is retried with its Retry-After', async () => {
        const { result, error, calls, delays } = await runGmail(attempt => {
            if (attempt === 0) {
                throw rateLimitError(2);
            }
            return { ok: true };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 2);
        assert.deepStrictEqual(result, { ok: true });
        assertDelayNear(delays[0], 2000);
    });

    await t.test('the total wait stays inside the budget', async () => {
        const { error, delays } = await runGmail(() => {
            const err = gmailRateLimit403();
            err.retryAfter = 4;
            throw err;
        });
        assert.ok(error);
        assert.ok(delays.reduce((a, b) => a + b, 0) <= MAX_TOTAL_RETRY_DELAY);
    });

    await t.test('a read that hit a 500 is retried once (Gmail asks for it)', async () => {
        const { error, calls } = await runGmail(() => {
            throw statusError(500);
        });
        assert.strictEqual(error.oauthRequest.status, 500);
        assert.strictEqual(calls, 2);
    });

    await t.test('a write that hit a 503 is not retried', async () => {
        const { error, calls } = await runGmail(
            () => {
                throw statusError(503);
            },
            { method: 'post' }
        );
        assert.strictEqual(error.oauthRequest.status, 503);
        assert.strictEqual(calls, 1);
    });

    await t.test('a write that failed on the socket is not sent again', async () => {
        const { error, calls } = await runGmail(
            () => {
                throw networkError();
            },
            { method: 'post' }
        );
        assert.strictEqual(error.code, 'ECONNRESET');
        assert.strictEqual(calls, 1);
    });

    await t.test('noRetry sends exactly once, even on a 429', async () => {
        const { error, calls } = await runGmail(
            () => {
                throw rateLimitError();
            },
            { method: 'post', options: { noRetry: true } }
        );
        assert.strictEqual(error.oauthRequest.status, 429);
        assert.strictEqual(calls, 1);
    });

    // The one repeat that is not a retry: a cached token the provider rejects is renewed and the
    // request sent again with the new one
    await t.test('a rejected cached token is renewed and the request repeated once', async () => {
        const { context, calls } = createOAuth2Context({
            cached: true,
            request: attempt =>
                attempt === 0
                    ? (() => {
                          throw statusError(401);
                      })()
                    : { ok: true }
        });
        const result = await gmailApi.request(context, 'https://gmail.googleapis.com/gmail/v1/users/me/labels', 'get', {}, {});
        assert.deepStrictEqual(result, { ok: true });
        assert.strictEqual(calls.requests, 2);
        assert.strictEqual(calls.invalidations, 1);
    });
});
