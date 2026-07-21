'use strict';

// Shared classification of OAuth2 failures on the connection path.

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
    //
    // NB: this only matches the OAUTHBEARER (RFC 7628) shape, where `status` carries a symbolic
    // code. XOAUTH2 servers put a numeric HTTP status there instead ("401"), so neither branch
    // fires for them and their stale tokens are still never proactively cleared.
    let status = oauthError && oauthError.status;
    return status === 'invalid_token' || status === 'invalid_request';
}

module.exports = { shouldInvalidateAccessToken };
