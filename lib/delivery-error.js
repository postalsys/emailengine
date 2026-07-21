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
 * The 5xx rule is keyed on nodemailer's `responseCode`, NOT on `statusCode`. Only a real SMTP reply
 * puts a code in `responseCode` (base-client.js copies it into `statusCode` for the API and webhook
 * payloads, which is why the two look interchangeable and are not). Across the rest of the codebase
 * a 5xx `statusCode` overwhelmingly means the opposite of a rejected message: 503 "no active
 * handler", 504 inter-thread RPC timeouts, 500 Redis lock failures, and every API transport's
 * passthrough of the provider's HTTP status. Reading that field as an SMTP verdict silently
 * discarded queued mail that nothing was wrong with.
 *
 * Keying on provenance rather than maintaining an allowlist of transient codes is what makes this
 * hold for transports that do not exist yet: an error is only a delivery rejection if it came back
 * from a mail server. The one case that is genuinely permanent without being an SMTP reply -
 * Outlook rejecting a malformed message - says so explicitly via `permanentDeliveryError`.
 *
 * @param {Object} err - Error thrown during submission
 * @param {Number} [err.responseCode] - SMTP reply code, set by nodemailer on real SMTP failures
 * @param {Boolean} [err.permanentDeliveryError] - Explicit "never retry" marker for non-SMTP paths
 * @param {String} [err.code] - Nodemailer error code
 * @returns {Boolean} True if the error should never be retried
 */
function isPermanentDeliveryError(err) {
    if (!err) {
        return false;
    }

    if (err.permanentDeliveryError) {
        return true;
    }

    if (NON_RETRYABLE_CODES.has(err.code)) {
        return true;
    }

    // 503 is a transient "try again later" response, so it is not a permanent rejection
    const smtpResponseCode = Number(err.responseCode);
    return smtpResponseCode >= 500 && smtpResponseCode !== 503;
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
