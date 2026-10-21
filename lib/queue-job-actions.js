'use strict';

// The actions the queue browser and the outbox API take on a BullMQ job, written once: a retry
// resets the attempt count, a promote needs a delayed job, a removal refuses a job a worker is
// running. The submit queue's own rules (the message content that lives beside the job) are
// layered on top of these by lib/outbox.js; the webhook queue uses them as they are.
//
// Dependency-free apart from the error shape, so lib/outbox.js can use it without a cycle
// through the queue browser.

const { statusError } = require('./utils/status-error');

/**
 * Puts a failed job back into the queue with a fresh set of attempts.
 *
 * Reset, not resumed: a job that used all its attempts would otherwise get one more and fail for
 * good again on the first transient error. The stored progress still describes the failure, so it
 * is replaced by the "queued" marker the submit worker writes for a new job; the worker overwrites
 * it once it picks the job up.
 *
 * @param {Object} job - BullMQ job, already loaded and known to be in the failed state
 * @param {string} noun - What the job is, for the refusal message ("message", "webhook delivery")
 * @throws {Error} With `statusCode` 409 and `code` NotFailed when BullMQ refuses (the job left the
 *   failed set meanwhile, or a worker holds its lock)
 */
async function retryFailedJob(job, noun) {
    try {
        await job.retry('failed', { resetAttemptsMade: true, resetAttemptsStarted: true });
    } catch (err) {
        throw statusError(`The ${noun} could not be retried: ${err.message}`, 'NotFailed', 409);
    }

    try {
        await job.updateProgress({ status: 'queued' });
    } catch (err) {
        // best effort, like every other progress write
    }
}

/**
 * Runs a delayed job at the next opportunity instead of at its time.
 *
 * @param {Object} job - BullMQ job, already loaded and known to be in the delayed state
 * @param {string} noun - What the job is, for the refusal message
 * @throws {Error} With `statusCode` 409 and `code` NotDelayed when BullMQ refuses
 */
async function promoteDelayedJob(job, noun) {
    try {
        await job.promote();
    } catch (err) {
        throw statusError(`The ${noun} could not be promoted: ${err.message}`, 'NotDelayed', 409);
    }
}

/**
 * Asserts the state an action needs, in the words the pages and the API show.
 *
 * @param {Object} job - BullMQ job
 * @param {string} state - The state the action applies to
 * @param {string} noun - What the job is
 * @param {string} verb - What the caller wants to do ("retried", "sent now")
 * @throws {Error} With `statusCode` 409 and a code naming the state the job is not in
 */
async function assertJobState(job, state, noun, verb) {
    if ((await job.getState()) !== state) {
        const code = state === 'failed' ? 'NotFailed' : state === 'delayed' ? 'NotDelayed' : 'WrongState';
        const sentence =
            state === 'failed'
                ? `Only a ${noun} whose delivery has failed can be ${verb}`
                : `Only a ${noun} waiting for its scheduled time or for its next attempt can be ${verb}`;
        throw statusError(sentence, code, 409);
    }
}

/**
 * Loads a job, but only when it belongs to the given account. What keeps a credential bound to
 * one account away from another account's jobs on the account-scoped routes, so it is written once
 * for every queue those routes reach
 * @param {Object} queue - BullMQ queue
 * @param {string} id - Job ID
 * @param {string} [account] - When set, a job of any other account is answered as missing
 * @returns {Promise<Object|null>} The job, or null
 */
async function getAccountJob(queue, id, account) {
    const job = id ? await queue.getJob(id) : null;
    if (!job || (account && (!job.data || job.data.account !== account))) {
        return null;
    }
    return job;
}

module.exports = { retryFailedJob, promoteDelayedJob, assertJobState, getAccountJob };
