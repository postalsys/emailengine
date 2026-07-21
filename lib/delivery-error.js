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

// Codes that force a retry, overriding the status-code rule below.
//
// The rule below reads `statusCode` as an SMTP reply code, but only the SMTP path actually puts one
// there (base-client.js handleSubmitError, from nodemailer's `responseCode`). The API transports and
// the inter-thread RPC stamp the same field with an HTTP status, so a 5xx that has nothing to do
// with the message used to be read as a permanent rejection and silently discard queued mail.
//
// Listing the transient codes here rather than tagging every throw site with its provenance is
// deliberate: it mirrors NON_RETRYABLE_CODES, keeps both directions visible from one place, and
// touches none of the ~90 sites that assign statusCode. A code that is genuinely permanent must
// simply stay out of this set - Outlook's "Invalid message format" deliberately forges a 500 for
// exactly that reason (outlook-client.js), and a malformed message really will fail every retry.
const RETRYABLE_CODES = new Set([
    // An OAuth2 token refresh failure carries the *token endpoint's* HTTP status, so a provider
    // returning 502 while renewing a token used to be read as a permanent 5xx SMTP rejection and
    // silently discarded a queued message that nothing was wrong with. The queue's own attempt
    // budget bounds the retries, and a provider outage is by nature temporary.
    'ETokenRefresh',

    // Gmail INTERNAL -> 500 (gmail/gmail-api.js GMAIL_ERROR_MAP). A Google-side server error during
    // send, which is exactly what a retry is for - but 500 matched the SMTP rule and dropped the
    // message instead.
    'InternalError',

    // Gmail UNAVAILABLE -> 503. Already retried by the 503 exemption below; listed so the set is the
    // authoritative statement of what is transient even if that mapping ever changes.
    'ServiceUnavailable',

    // RPC timeout waiting for the IMAP worker to answer (workers/submit.js call(), statusCode 504).
    // The message never reached a mail server at all - the worker was busy or restarting - yet 504
    // matched the SMTP rule, so a loaded instance discarded queued mail. Note 503 is already the
    // codebase's convention for the sibling "no active handler" case (imap-client.js).
    'Timeout'
]);

/**
 * Determines whether a delivery error is permanent (must not be retried).
 *
 * An error is permanent when either:
 *   - the SMTP status code is a 5xx other than 503 (503 is treated as a
 *     transient "try again later" response), or
 *   - the error carries one of the NON_RETRYABLE_CODES,
 * unless it carries one of the RETRYABLE_CODES, which wins over both.
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

    if (RETRYABLE_CODES.has(err.code)) {
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

module.exports = { NON_RETRYABLE_CODES, RETRYABLE_CODES, isPermanentDeliveryError, shouldDiscardJob };
