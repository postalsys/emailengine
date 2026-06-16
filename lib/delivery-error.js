'use strict';

// Classification of outbound delivery errors for the submit worker.
//
// This logic lives in its own module so it can be unit tested without booting
// the BullMQ submit worker (workers/submit.js connects to Redis and expects a
// worker-thread parentPort at require time).

// Nodemailer/SMTP error codes that represent permanent failures. A message that
// fails with one of these will fail again on every retry, so the job is
// discarded instead of being retried.
const NON_RETRYABLE_CODES = new Set([
    'EAUTH', // authentication failed
    'ENOAUTH', // no credentials provided
    'EOAUTH2', // OAuth2 token failure
    'ETLS', // TLS handshake failed
    'EENVELOPE', // invalid sender/recipients
    'EMESSAGE', // message content error
    'EPROTOCOL' // SMTP protocol mismatch
]);

/**
 * Determines whether a delivery error is permanent (must not be retried).
 *
 * An error is permanent when either:
 *   - the SMTP status code is a 5xx other than 503 (503 is treated as a
 *     transient "try again later" response), or
 *   - the error carries one of the NON_RETRYABLE_CODES.
 *
 * @param {Object} err - Error thrown during submission
 * @param {Number} [err.statusCode] - SMTP/HTTP status code
 * @param {String} [err.code] - Nodemailer error code
 * @returns {Boolean} True if the error should never be retried
 */
function isPermanentDeliveryError(err) {
    if (!err) {
        return false;
    }
    const isPermanentSmtp = err.statusCode >= 500 && err.statusCode !== 503;
    const isPermanentCode = NON_RETRYABLE_CODES.has(err.code);
    return isPermanentSmtp || isPermanentCode;
}

/**
 * Determines whether the submit worker should discard a job (stop retrying).
 *
 * A job is discarded only when the error is permanent AND there are still
 * attempts remaining. When attempts are already exhausted, BullMQ will fail the
 * job naturally, so there is nothing to discard.
 *
 * @param {Object} err - Error thrown during submission
 * @param {Object} job - BullMQ job
 * @param {Number} job.attemptsMade - Attempts already made
 * @param {Object} job.opts - Job options
 * @param {Number} job.opts.attempts - Configured max attempts
 * @returns {Boolean} True if the job should be discarded
 */
function shouldDiscardJob(err, job) {
    return isPermanentDeliveryError(err) && job.attemptsMade < job.opts.attempts;
}

module.exports = { NON_RETRYABLE_CODES, isPermanentDeliveryError, shouldDiscardJob };
