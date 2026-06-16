'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Exercise the real submit-worker discard predicate (lib/delivery-error.js),
// the exact code path workers/submit.js uses to decide whether a failed
// delivery job should be discarded (permanent failure) or left for BullMQ to
// retry. Previously this test re-implemented the predicate inline and never
// covered the NON_RETRYABLE_CODES (EAUTH/EOAUTH2/...) branch at all.
const { shouldDiscardJob, isPermanentDeliveryError, NON_RETRYABLE_CODES } = require('../lib/delivery-error');

test('submit worker delivery-error classification', async t => {
    await t.test('does not discard jobs with 503 status code', () => {
        let err503 = new Error('No active handler');
        err503.statusCode = 503;

        let err500 = new Error('Internal server error');
        err500.statusCode = 500;

        let err502 = new Error('Bad gateway');
        err502.statusCode = 502;

        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscardJob(err503, job), false, '503 errors should NOT be discarded (allows BullMQ retry)');
        assert.strictEqual(shouldDiscardJob(err500, job), true, '500 errors should be discarded');
        assert.strictEqual(shouldDiscardJob(err502, job), true, '502 errors should be discarded');
    });

    await t.test('still discards 5xx errors other than 503', () => {
        let statusCodes = [500, 501, 502, 504, 505];
        let job = { attemptsMade: 0, opts: { attempts: 5 } };

        for (let code of statusCodes) {
            let err = new Error(`Error ${code}`);
            err.statusCode = code;
            assert.strictEqual(shouldDiscardJob(err, job), true, `${code} errors should still be discarded`);
        }
    });

    await t.test('does not discard transient codes below 500', () => {
        let job = { attemptsMade: 0, opts: { attempts: 5 } };

        for (let code of [421, 450, 451, 452]) {
            let err = new Error(`Error ${code}`);
            err.statusCode = code;
            assert.strictEqual(shouldDiscardJob(err, job), false, `${code} errors should be retried`);
        }
    });

    await t.test('does not discard when all attempts are exhausted', () => {
        let err500 = new Error('Internal server error');
        err500.statusCode = 500;

        let job = { attemptsMade: 10, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscardJob(err500, job), false, 'Should not discard when attempts are exhausted');
    });

    await t.test('discards non-retryable error codes regardless of status', () => {
        // This branch (NON_RETRYABLE_CODES) was previously untested entirely.
        let job = { attemptsMade: 0, opts: { attempts: 10 } };

        for (let code of NON_RETRYABLE_CODES) {
            let err = new Error(`Permanent failure: ${code}`);
            err.code = code;
            // No statusCode at all - must still be permanent because of the code.
            assert.strictEqual(isPermanentDeliveryError(err), true, `${code} should be a permanent error`);
            assert.strictEqual(shouldDiscardJob(err, job), true, `${code} jobs should be discarded`);
        }
    });

    await t.test('non-retryable code is discarded even with a transient status code', () => {
        // A permanent code wins over a transient (sub-500 or 503) status code.
        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        let err = new Error('Auth failed mid-handshake');
        err.code = 'EAUTH';
        err.statusCode = 503; // transient on its own

        assert.strictEqual(isPermanentDeliveryError(err), true);
        assert.strictEqual(shouldDiscardJob(err, job), true);
    });

    await t.test('does not discard unknown/transient errors with no status or code', () => {
        let job = { attemptsMade: 0, opts: { attempts: 10 } };

        let err = new Error('ETIMEDOUT'); // network timeout, retryable
        err.code = 'ETIMEDOUT';

        assert.strictEqual(isPermanentDeliveryError(err), false);
        assert.strictEqual(shouldDiscardJob(err, job), false);
    });

    await t.test('isPermanentDeliveryError tolerates a missing error object', () => {
        assert.strictEqual(isPermanentDeliveryError(null), false);
        assert.strictEqual(isPermanentDeliveryError(undefined), false);
    });
});
