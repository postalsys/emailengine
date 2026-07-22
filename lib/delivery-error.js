'use strict';

// Classification of outbound delivery errors for the submit worker.
//
// This logic lives in its own module so it can be unit tested without booting
// the BullMQ submit worker (workers/submit.js connects to Redis and expects a
// worker-thread parentPort at require time).

// Nodemailer/SMTP error codes that represent permanent failures when the error does NOT also carry a
// transient (4xx) SMTP reply code. nodemailer stamps these on hard failures (bad credentials, a
// malformed envelope the server never even replied to, TLS/protocol mismatch) that recur on every
// retry, so the job is discarded instead of retried. Note that nodemailer also stamps
// EAUTH/EENVELOPE/EMESSAGE on *transient* 4xx replies (e.g. a "450 greylisted" RCPT TO), which is
// why isPermanentDeliveryError() consults the SMTP reply code BEFORE this set.
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
 * The SMTP-reply rule is keyed on nodemailer's `responseCode`, NOT on `statusCode`. Only a real SMTP
 * reply puts a code in `responseCode` (base-client.js copies it into `statusCode` for the API and
 * webhook payloads, which is why the two look interchangeable and are not). Across the rest of the
 * codebase a 5xx `statusCode` overwhelmingly means the opposite of a rejected message: 503 "no active
 * handler", 504 inter-thread RPC timeouts, 500 Redis lock failures, and every API transport's
 * passthrough of the provider's HTTP status. Reading that field as an SMTP verdict silently discarded
 * queued mail that nothing was wrong with. `responseCode` is forwarded across the worker-thread RPC
 * hop explicitly (see lib/worker-rpc-error.js) so this branch actually fires in production.
 *
 * When a real SMTP reply is present it decides on its own: per RFC 5321 a 4yz reply is a TRANSIENT
 * negative completion ("try again later", e.g. greylisting) and only 5yz is permanent. nodemailer
 * tags envelope/message/auth rejections with EENVELOPE/EMESSAGE/EAUTH regardless of the reply class,
 * so the reply code has to be consulted BEFORE the code allowlist - otherwise a soft 4xx (or a 503)
 * would be discarded as if it were a hard rejection. The code allowlist is the fallback for failures
 * that carry no server reply at all (missing credentials, TLS/protocol mismatch).
 *
 * @param {Object} err - Error thrown during submission
 * @param {Number} [err.responseCode] - SMTP reply code, set by nodemailer on real SMTP failures
 * @param {String} [err.code] - Nodemailer error code
 * @returns {Boolean} True if the error should never be retried
 */
function isPermanentDeliveryError(err) {
    if (!err) {
        return false;
    }

    const smtpResponseCode = Number(err.responseCode);
    if (smtpResponseCode) {
        // A real SMTP reply decides on its own: 5xx is permanent, everything else (transient 4xx, or
        // an unexpected 2xx/3xx) is retryable. 503 is carved out and left retryable on purpose -
        // discarding a message the server might still accept loses mail, while retrying a genuinely
        // permanent 503 only wastes a bounded number of attempts.
        return smtpResponseCode >= 500 && smtpResponseCode !== 503;
    }

    // No SMTP reply at all: fall back to the nodemailer error code.
    return NON_RETRYABLE_CODES.has(err.code);
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
