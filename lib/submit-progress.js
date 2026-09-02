'use strict';

// Progress states a submit job reaches only once the message has been accepted. The email client
// writes 'smtp-completed' right after the MTA's 250 (or the provider API's accept), and the submit
// worker writes 'submitted' once the post-send bookkeeping is through as well. Everything a job
// does after either state is bookkeeping (Sent-folder copy, draft cleanup, flag updates, gateway
// stats), so a job that is running again in one of these states must not send the message again.
//
// Split out of workers/submit.js because the worker boots a BullMQ consumer on require, which
// keeps the decision itself out of reach of a unit test.
const SENT_PROGRESS_STATES = new Set(['smtp-completed', 'submitted']);

/**
 * Tells whether a submit job's stored progress says the message was already accepted.
 *
 * BullMQ hands a re-run job the progress its previous run stored, so this is what a stalled job
 * (heartbeat kill, crash, a shutdown drain that could not cover a long SMTP transaction) looks
 * like when it comes back. A retry after a real delivery failure never carries one of these states:
 * the failure path writes 'error' before it throws, and a run cut short before the 250 leaves
 * 'processing' or 'smtp-starting' behind.
 *
 * @param {*} progress - job.progress as BullMQ hydrates it (an object, or 0 when never set)
 * @returns {boolean} True when the message was already sent
 */
function isAlreadySent(progress) {
    return !!(progress && typeof progress === 'object' && SENT_PROGRESS_STATES.has(progress.status));
}

module.exports = { isAlreadySent, SENT_PROGRESS_STATES };
