'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { OUTLOOK_MAX_RETRY_ATTEMPTS, OUTLOOK_RETRY_BASE_DELAY, OUTLOOK_RETRY_MAX_DELAY } = require('../lib/consts');

// Exercise the real Graph API retry orchestration (lib/email-client/outlook/graph-api.js)
// instead of a re-implementation. requestWithRetry(context, ...) takes the client
// as its first argument, so we drive it with a fake context whose oAuth2Client.request
// we control. A regression in the shipping retry/backoff logic now fails this suite.
const graphApi = require('../lib/email-client/outlook/graph-api');
const { redis } = require('../lib/db');

test.after(async () => {
    // graph-api transitively opens a Redis connection via base-client -> lib/db.
    try {
        await redis.quit();
    } catch (err) {
        // ignore - connection may already be closing
    }
});

const noopLogger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

// Build a fake OutlookClient context. requestImpl receives the attempt index
// (0-based) and returns a value to resolve with or throws to simulate failure.
function makeContext(requestImpl) {
    let attempt = 0;
    const context = {
        account: 'test-account',
        logger: noopLogger,
        getToken: async () => 'access-token',
        oAuth2Client: {
            apiBase: 'https://graph.microsoft.com',
            provider: 'outlook',
            request: async () => {
                const current = attempt++;
                return requestImpl(current);
            }
        }
    };
    return {
        context,
        getCalls: () => attempt
    };
}

// Run requestWithRetry while neutralizing the real (30-120s) backoff sleeps.
// We swap global.setTimeout for one that fires immediately but records the
// requested delay. Retry delays are always >= 1000ms (base 30s), so we filter
// out any unrelated sub-second timers that other libraries might schedule.
async function runRetry(requestImpl, options = {}) {
    const { context, getCalls } = makeContext(requestImpl);
    const realSetTimeout = global.setTimeout;
    const rawDelays = [];

    global.setTimeout = (cb, ms, ...args) => {
        rawDelays.push(ms);
        return realSetTimeout(cb, 0, ...args);
    };

    let result;
    let error;
    try {
        result = await graphApi.requestWithRetry(context, '/me', 'get', {}, options);
    } catch (err) {
        error = err;
    } finally {
        global.setTimeout = realSetTimeout;
    }

    const delaysSeconds = rawDelays.filter(ms => ms >= 1000).map(ms => ms / 1000);
    return { result, error, calls: getCalls(), delaysSeconds };
}

function rateLimitError(retryAfter) {
    const err = new Error('Rate limited');
    err.oauthRequest = { status: 429 };
    if (retryAfter !== undefined) {
        err.retryAfter = retryAfter;
    }
    return err;
}

test('Outlook Graph API requestWithRetry', async t => {
    await t.test('constants are defined with expected values', () => {
        assert.strictEqual(OUTLOOK_MAX_RETRY_ATTEMPTS, 3, 'Max retry attempts should be 3');
        assert.strictEqual(OUTLOOK_RETRY_BASE_DELAY, 30, 'Base delay should be 30 seconds');
        assert.strictEqual(OUTLOOK_RETRY_MAX_DELAY, 120, 'Max delay should be 120 seconds');
    });

    await t.test('succeeds on first attempt without retry', async () => {
        const { result, error, calls, delaysSeconds } = await runRetry(() => ({ ok: true, data: 'test' }));
        assert.ifError(error);
        assert.strictEqual(calls, 1, 'Should only make one attempt');
        assert.strictEqual(delaysSeconds.length, 0, 'Should not sleep');
        assert.deepStrictEqual(result, { ok: true, data: 'test' });
    });

    await t.test('retries on 429 and succeeds on second attempt', async () => {
        const { result, error, calls, delaysSeconds } = await runRetry(attempt => {
            if (attempt === 0) {
                throw rateLimitError();
            }
            return { ok: true, attempt };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 2, 'Should make two attempts');
        assert.deepStrictEqual(delaysSeconds, [30], 'First retry delay should be 30s');
        assert.deepStrictEqual(result, { ok: true, attempt: 1 });
    });

    await t.test('retries with exponential backoff (30, 60, 120)', async () => {
        const { result, error, calls, delaysSeconds } = await runRetry(attempt => {
            if (attempt < 3) {
                throw rateLimitError();
            }
            return { ok: true, attempt };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 4, 'Should make 4 attempts (initial + 3 retries)');
        assert.deepStrictEqual(delaysSeconds, [30, 60, 120], 'Delays should follow exponential backoff, capped at 120');
        assert.deepStrictEqual(result, { ok: true, attempt: 3 });
    });

    await t.test('stops retrying after max attempts and throws', async () => {
        const { error, calls, delaysSeconds } = await runRetry(() => {
            throw rateLimitError();
        });
        assert.ok(error, 'Should throw after exhausting retries');
        assert.strictEqual(error.oauthRequest.status, 429);
        assert.strictEqual(calls, 4, 'initial attempt + 3 retries');
        assert.strictEqual(delaysSeconds.length, 3, 'Should sleep 3 times before final failure');
    });

    await t.test('throws immediately on non-429 client error (404)', async () => {
        const { error, calls, delaysSeconds } = await runRetry(() => {
            const err = new Error('Not found');
            err.oauthRequest = { status: 404 };
            throw err;
        });
        assert.ok(error);
        assert.strictEqual(error.oauthRequest.status, 404);
        assert.strictEqual(calls, 1, 'Should not retry');
        assert.strictEqual(delaysSeconds.length, 0);
    });

    await t.test('throws immediately on 500 server error', async () => {
        const { error, calls } = await runRetry(() => {
            const err = new Error('Server error');
            err.oauthRequest = { status: 500 };
            throw err;
        });
        assert.ok(error);
        assert.strictEqual(error.oauthRequest.status, 500);
        assert.strictEqual(calls, 1, 'Should not retry on 500');
    });

    await t.test('uses Retry-After from error when provided', async () => {
        const { error, delaysSeconds } = await runRetry(() => {
            throw rateLimitError(90); // server-requested 90s wait
        });
        assert.ok(error);
        assert.strictEqual(delaysSeconds.length, 3);
        assert.ok(
            delaysSeconds.every(d => d === 90),
            'All delays should be 90s from Retry-After'
        );
    });

    await t.test('respects custom maxRetries option', async () => {
        const { error, calls } = await runRetry(
            () => {
                throw rateLimitError();
            },
            { maxRetries: 1 }
        );
        assert.ok(error);
        assert.strictEqual(calls, 2, 'initial attempt + 1 retry');
    });

    await t.test('does not retry errors without a status code', async () => {
        const { error, calls, delaysSeconds } = await runRetry(() => {
            throw new Error('Unexpected error');
        });
        assert.ok(error);
        assert.strictEqual(error.message, 'Unexpected error');
        assert.strictEqual(calls, 1, 'Should not retry non-HTTP errors');
        assert.strictEqual(delaysSeconds.length, 0);
    });

    // The transient-network-retry branch (graph-api.js retries ENOTFOUND/
    // ETIMEDOUT/ECONNRESET/... before the 429 check) was previously untested.
    await t.test('retries transient network errors then succeeds', async () => {
        const { result, error, calls, delaysSeconds } = await runRetry(attempt => {
            if (attempt < 2) {
                const err = new Error('socket hang up');
                err.code = 'ECONNRESET';
                throw err;
            }
            return { ok: true, attempt };
        });
        assert.ifError(error);
        assert.strictEqual(calls, 3, 'initial attempt + 2 retries');
        assert.deepStrictEqual(delaysSeconds, [30, 60], 'Transient retries use exponential backoff');
        assert.deepStrictEqual(result, { ok: true, attempt: 2 });
    });

    await t.test('transient network error exhausts retries and throws', async () => {
        const { error, calls, delaysSeconds } = await runRetry(() => {
            const err = new Error('timeout');
            err.code = 'ETIMEDOUT';
            throw err;
        });
        assert.ok(error);
        assert.strictEqual(error.code, 'ETIMEDOUT');
        assert.strictEqual(calls, 4, 'initial attempt + 3 retries');
        assert.strictEqual(delaysSeconds.length, 3);
    });
});
