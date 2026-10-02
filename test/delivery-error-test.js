'use strict';

// The `nextAttempt` figure reported by GET /v1/outbox and carried into a submission's job info is
// derived from BullMQ's exponential backoff, and the two call sites read a job in different phases:
// the submit worker holds a job whose attemptsMade is not yet incremented for the attempt it is
// running, while the outbox listing reads a job whose attemptsMade already counts the attempt that
// failed. That made the exponents at the two sites differ by one and look like a bug - two reviews
// reached opposite conclusions about which was wrong. Both were right, and the tests below pin it
// against BullMQ's own implementation so an upgrade that changes the formula fails here.

const test = require('node:test');
const assert = require('node:assert').strict;

const { Backoffs } = require('bullmq');
const { retryDelayAfterAttempt, nextAttemptWhileProcessing, nextAttemptOfStoredJob } = require('../lib/delivery-error');

const BACKOFF = { type: 'exponential', delay: 5000 };

// BullMQ asks Backoffs.calculate() for the delay with attemptsMade + 1, where attemptsMade is the
// pre-increment value held inside Job#shouldRetryJob(). So for the attempt numbered k (1-based) that
// has just failed, the argument is k.
const bullmqDelayAfterAttempt = attemptNumber => Backoffs.calculate(BACKOFF, attemptNumber);

const job = (attemptsMade, { attempts = 10, processedOn = 1000000, timestamp = 900000, delay = 0 } = {}) => ({
    attemptsMade,
    processedOn,
    timestamp,
    opts: { attempts, backoff: BACKOFF, delay }
});

test('retryDelayAfterAttempt() matches the BullMQ exponential strategy', async t => {
    await t.test('the delay after attempt k is what BullMQ computes for it', () => {
        for (const attemptNumber of [1, 2, 3, 4, 5]) {
            assert.equal(
                retryDelayAfterAttempt(attemptNumber, job(0)),
                bullmqDelayAfterAttempt(attemptNumber),
                `attempt ${attemptNumber} waits as long as BullMQ waits`
            );
        }
    });

    await t.test('the first retry waits one base delay, not two', () => {
        assert.equal(retryDelayAfterAttempt(1, job(0)), 5000);
    });

    await t.test('a job with no exponential backoff waits not at all', () => {
        assert.equal(retryDelayAfterAttempt(3, { opts: { attempts: 10 } }), 0);
    });
});

test('nextAttemptWhileProcessing() reads a job the submit worker is holding', async t => {
    // attemptsMade is still the count of attempts that have FAILED, so the running attempt is the
    // next one up and the wait after it fails is keyed on attemptsMade + 1.
    await t.test('the first attempt waits one base delay before the second', () => {
        assert.equal(nextAttemptWhileProcessing(job(0)), 1000000 + bullmqDelayAfterAttempt(1));
    });

    await t.test('the third attempt waits four base delays before the fourth', () => {
        assert.equal(nextAttemptWhileProcessing(job(2)), 1000000 + bullmqDelayAfterAttempt(3));
    });

    await t.test('the last attempt has no retry', () => {
        assert.equal(nextAttemptWhileProcessing(job(2, { attempts: 3 })), false);
        assert.equal(nextAttemptWhileProcessing(job(0, { attempts: 1 })), false);
    });
});

test('nextAttemptOfStoredJob() reads a job as it is stored', async t => {
    // attemptsMade already counts the attempt that failed, so the wait is keyed on attemptsMade
    // itself. The same wall-clock answer as the worker reported for that same attempt.
    await t.test('a job whose first attempt failed is due one base delay after it ran', () => {
        assert.equal(nextAttemptOfStoredJob(job(1), 900000), 1000000 + bullmqDelayAfterAttempt(1));
    });

    await t.test('the two call sites agree about the same attempt', () => {
        // The worker is running attempt 3 (attemptsMade 2); once it fails the stored job reads 3
        assert.equal(nextAttemptWhileProcessing(job(2)), nextAttemptOfStoredJob(job(3), 900000));
    });

    await t.test('a job that has not run yet is due at its scheduled time', () => {
        assert.equal(nextAttemptOfStoredJob(job(0, { timestamp: 900000, delay: 60000 }), 960000), 960000);
    });

    await t.test('a job that has used up every attempt has no next one', () => {
        assert.equal(nextAttemptOfStoredJob(job(3, { attempts: 3 }), 900000), false);
        assert.equal(nextAttemptOfStoredJob(job(4, { attempts: 3 }), 900000), false);
        // An unset attempts count means BullMQ runs the job once, so a failure ends it
        assert.equal(nextAttemptOfStoredJob({ attemptsMade: 1, processedOn: 1000000, opts: { backoff: BACKOFF } }, 900000), false);
    });
});
