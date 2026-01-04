'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    OUTLOOK_MAX_RETRY_ATTEMPTS,
    OUTLOOK_RETRY_BASE_DELAY,
    OUTLOOK_RETRY_MAX_DELAY
} = require('../lib/consts');

/**
 * Calculate exponential backoff delay (mirrors implementation in outlook-client.js)
 * @param {number} attempt - Current attempt number (0-indexed)
 * @param {number} [retryAfter] - Optional Retry-After header value
 * @returns {number} Delay in seconds
 */
function calculateBackoffDelay(attempt, retryAfter) {
    return retryAfter || Math.min(OUTLOOK_RETRY_BASE_DELAY * Math.pow(2, attempt), OUTLOOK_RETRY_MAX_DELAY);
}

/**
 * Simulates requestWithRetry behavior for testing
 * @param {Function} requestFn - Mock request function that may throw
 * @param {object} options - Options including maxRetries
 * @returns {Promise<object>} Result or throws after max retries
 */
async function simulateRequestWithRetry(requestFn, options = {}) {
    const maxRetries = options.maxRetries ?? OUTLOOK_MAX_RETRY_ATTEMPTS;
    const delays = [];
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            return await requestFn(attempt);
        } catch (err) {
            // Only retry on 429 (rate limit) errors
            if (err.oauthRequest?.status !== 429 || attempt === maxRetries) {
                throw err;
            }

            lastError = err;
            const retryAfter = calculateBackoffDelay(attempt, err.retryAfter);
            delays.push(retryAfter);

            // In tests, we don't actually wait - just record the delay
            if (options.recordDelays) {
                options.recordDelays.push(retryAfter);
            }
        }
    }

    throw lastError;
}

test('Retry logic tests', async t => {
    await t.test('constants are defined with expected values', async () => {
        assert.strictEqual(OUTLOOK_MAX_RETRY_ATTEMPTS, 3, 'Max retry attempts should be 3');
        assert.strictEqual(OUTLOOK_RETRY_BASE_DELAY, 30, 'Base delay should be 30 seconds');
        assert.strictEqual(OUTLOOK_RETRY_MAX_DELAY, 120, 'Max delay should be 120 seconds');
    });

    await t.test('calculates correct exponential backoff delays', async () => {
        // attempt 0: min(30 * 2^0, 120) = min(30, 120) = 30
        assert.strictEqual(calculateBackoffDelay(0), 30, 'Attempt 0 should have 30s delay');

        // attempt 1: min(30 * 2^1, 120) = min(60, 120) = 60
        assert.strictEqual(calculateBackoffDelay(1), 60, 'Attempt 1 should have 60s delay');

        // attempt 2: min(30 * 2^2, 120) = min(120, 120) = 120
        assert.strictEqual(calculateBackoffDelay(2), 120, 'Attempt 2 should have 120s delay');

        // attempt 3: min(30 * 2^3, 120) = min(240, 120) = 120 (capped)
        assert.strictEqual(calculateBackoffDelay(3), 120, 'Attempt 3 should be capped at 120s');

        // attempt 4: min(30 * 2^4, 120) = min(480, 120) = 120 (capped)
        assert.strictEqual(calculateBackoffDelay(4), 120, 'Attempt 4 should be capped at 120s');
    });

    await t.test('respects Retry-After header when present', async () => {
        // When Retry-After is provided, it takes precedence
        assert.strictEqual(calculateBackoffDelay(0, 45), 45, 'Should use Retry-After value of 45');
        assert.strictEqual(calculateBackoffDelay(1, 10), 10, 'Should use Retry-After value of 10');
        assert.strictEqual(calculateBackoffDelay(2, 200), 200, 'Should use Retry-After even if > max');
    });

    await t.test('succeeds on first attempt without retry', async () => {
        const delays = [];
        let attemptCount = 0;

        const result = await simulateRequestWithRetry(
            async attempt => {
                attemptCount++;
                return { success: true, data: 'test' };
            },
            { recordDelays: delays }
        );

        assert.strictEqual(attemptCount, 1, 'Should only make one attempt');
        assert.strictEqual(delays.length, 0, 'Should not record any delays');
        assert.deepStrictEqual(result, { success: true, data: 'test' });
    });

    await t.test('retries on 429 and succeeds on second attempt', async () => {
        const delays = [];
        let attemptCount = 0;

        const result = await simulateRequestWithRetry(
            async attempt => {
                attemptCount++;
                if (attempt === 0) {
                    const err = new Error('Rate limited');
                    err.oauthRequest = { status: 429 };
                    throw err;
                }
                return { success: true, attempt };
            },
            { recordDelays: delays }
        );

        assert.strictEqual(attemptCount, 2, 'Should make two attempts');
        assert.strictEqual(delays.length, 1, 'Should record one delay');
        assert.strictEqual(delays[0], 30, 'First retry delay should be 30s');
        assert.deepStrictEqual(result, { success: true, attempt: 1 });
    });

    await t.test('retries with exponential backoff delays', async () => {
        const delays = [];
        let attemptCount = 0;

        const result = await simulateRequestWithRetry(
            async attempt => {
                attemptCount++;
                if (attempt < 3) {
                    const err = new Error('Rate limited');
                    err.oauthRequest = { status: 429 };
                    throw err;
                }
                return { success: true, attempt };
            },
            { recordDelays: delays }
        );

        assert.strictEqual(attemptCount, 4, 'Should make 4 attempts (initial + 3 retries)');
        assert.strictEqual(delays.length, 3, 'Should record 3 delays');
        assert.deepStrictEqual(delays, [30, 60, 120], 'Delays should follow exponential backoff');
        assert.deepStrictEqual(result, { success: true, attempt: 3 });
    });

    await t.test('stops retrying after max attempts and throws', async () => {
        const delays = [];
        let attemptCount = 0;

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(
                    async () => {
                        attemptCount++;
                        const err = new Error('Rate limited');
                        err.oauthRequest = { status: 429 };
                        throw err;
                    },
                    { recordDelays: delays }
                );
            },
            err => {
                assert.strictEqual(err.message, 'Rate limited');
                assert.strictEqual(err.oauthRequest.status, 429);
                return true;
            }
        );

        // initial attempt + 3 retries = 4 total attempts
        assert.strictEqual(attemptCount, 4, 'Should make 4 attempts total');
        assert.strictEqual(delays.length, 3, 'Should record 3 delays before final failure');
    });

    await t.test('throws immediately on non-429 errors', async () => {
        const delays = [];
        let attemptCount = 0;

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(
                    async () => {
                        attemptCount++;
                        const err = new Error('Not found');
                        err.oauthRequest = { status: 404 };
                        throw err;
                    },
                    { recordDelays: delays }
                );
            },
            err => {
                assert.strictEqual(err.message, 'Not found');
                assert.strictEqual(err.oauthRequest.status, 404);
                return true;
            }
        );

        assert.strictEqual(attemptCount, 1, 'Should only make one attempt');
        assert.strictEqual(delays.length, 0, 'Should not record any delays');
    });

    await t.test('throws immediately on 500 errors', async () => {
        let attemptCount = 0;

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(async () => {
                    attemptCount++;
                    const err = new Error('Server error');
                    err.oauthRequest = { status: 500 };
                    throw err;
                });
            },
            err => {
                assert.strictEqual(err.oauthRequest.status, 500);
                return true;
            }
        );

        assert.strictEqual(attemptCount, 1, 'Should not retry on 500');
    });

    await t.test('uses Retry-After from error when provided', async () => {
        const delays = [];

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(
                    async () => {
                        const err = new Error('Rate limited');
                        err.oauthRequest = { status: 429 };
                        err.retryAfter = 90; // Server requested 90 second wait
                        throw err;
                    },
                    { recordDelays: delays }
                );
            },
            () => true
        );

        // All delays should use the Retry-After value
        assert.strictEqual(delays.length, 3);
        assert.ok(delays.every(d => d === 90), 'All delays should be 90s from Retry-After');
    });

    await t.test('respects custom maxRetries option', async () => {
        let attemptCount = 0;

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(
                    async () => {
                        attemptCount++;
                        const err = new Error('Rate limited');
                        err.oauthRequest = { status: 429 };
                        throw err;
                    },
                    { maxRetries: 1 }
                );
            },
            () => true
        );

        // initial attempt + 1 retry = 2 total
        assert.strictEqual(attemptCount, 2, 'Should only make 2 attempts with maxRetries=1');
    });

    await t.test('handles errors without oauthRequest property', async () => {
        let attemptCount = 0;

        await assert.rejects(
            async () => {
                await simulateRequestWithRetry(async () => {
                    attemptCount++;
                    throw new Error('Network error');
                });
            },
            err => {
                assert.strictEqual(err.message, 'Network error');
                return true;
            }
        );

        assert.strictEqual(attemptCount, 1, 'Should not retry errors without status');
    });
});
