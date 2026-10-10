'use strict';

// How a failed outbound HTTP request is told apart from a refused or broken one. undici raises
// every connection failure as a generic TypeError ("fetch failed", "terminated") with the real
// DNS/socket/timeout error on err.cause, so a check of err.code alone misses all of them.
//
// Dependency-free apart from consts, so lib/logger.js can use it without a require cycle.

const { TRANSIENT_NETWORK_CODES } = require('./consts');

// How far down a cause chain the transient check looks. A chain is not guaranteed to be finite - an
// error may cite itself - so the walk is bounded rather than trusting it to end.
const MAX_CAUSE_DEPTH = 5;

/**
 * Failing to reach a remote endpoint is a connection problem, not a rejected credential or a bug.
 *
 * The whole cause chain is searched, not one level: a caller that wraps an undici failure in an
 * error of its own pushes the code one level deeper (lib/oauth/external-account-signer.js does
 * exactly that for its Workload Identity Federation requests).
 *
 * @param {Error} err - The error to check
 * @returns {boolean} True if the error, or anything it was caused by, is a transient network failure
 */
function isTransientNetworkError(err) {
    for (let cause = err, depth = 0; cause && typeof cause === 'object' && depth < MAX_CAUSE_DEPTH; cause = cause.cause, depth++) {
        if (TRANSIENT_NETWORK_CODES.has(cause.code)) {
            return true;
        }
    }

    return false;
}

/**
 * Copies the code of an undici failure from err.cause onto the error itself, so callers that read
 * err.code (and the webhook and log payloads built from it) see ECONNRESET or UND_ERR_BODY_TIMEOUT
 * rather than nothing. Leaves an error that already carries a code alone.
 *
 * @param {Error} err - The error thrown by fetch()
 * @returns {Error} The same error
 */
function promoteCauseCode(err) {
    if (err && !err.code && err.cause && err.cause.code) {
        err.code = err.cause.code;
    }
    return err;
}

module.exports = { isTransientNetworkError, promoteCauseCode };
