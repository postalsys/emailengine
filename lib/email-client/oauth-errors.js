'use strict';

// Shared classification of OAuth2 failures on the connection path. These decide whether a failure
// means "the credentials are bad" (park the account) or "the provider is having a moment" (retry),
// which is the difference between an account recovering on its own and one sitting in
// authenticationError until someone re-authorizes it.

// Socket and DNS failures that undici surfaces while talking to a token endpoint. None of them say
// anything about the credentials. Shared with the rest of the codebase so that adding a code in one
// place cannot leave this path parking healthy accounts on it.
const { TRANSIENT_NETWORK_CODES } = require('../consts');

/**
 * Decides whether a failed OAuth2 token refresh reflects bad credentials or a transient condition.
 *
 * 429 and 5xx mean rate limited or broken. A 4xx other than 429 - notably invalid_grant, a revoked
 * refresh token - is a real credential problem and must keep parking the account.
 *
 * @param {Error} err - Error thrown by renewAccessToken()
 * @returns {boolean} True when the failure should be treated as a connection error, not an auth error
 */
function isTransientTokenRefreshError(err) {
    if (!err) {
        return false;
    }

    if (TRANSIENT_NETWORK_CODES.has(err.code)) {
        return true;
    }

    if (err.code !== 'ETokenRefresh') {
        return false;
    }

    return err.statusCode === 429 || (err.statusCode >= 500 && err.statusCode <= 599);
}

/**
 * Decides whether a SASL error payload should cause the cached access token to be dropped.
 *
 * @param {Object} [oauthError] - The `oauthError` payload attached by ImapFlow, if any
 * @returns {boolean} True when the cached access token should be invalidated
 */
function shouldInvalidateAccessToken(oauthError) {
    // Per RFC 6750 `invalid_token` is the status that actually means expired, revoked or malformed,
    // and it was previously not handled at all. `invalid_request` means the SASL request itself was
    // malformed, so a fresh token cannot fix it - kept because providers do send it for stale
    // credentials in practice, but it is not a reliable staleness signal.
    let status = oauthError && oauthError.status;
    return status === 'invalid_token' || status === 'invalid_request';
}

module.exports = { isTransientTokenRefreshError, shouldInvalidateAccessToken };
