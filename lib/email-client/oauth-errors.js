'use strict';

// Shared classification of OAuth2 failures on the connection path.

/**
 * Decides whether a SASL error payload should cause the cached access token to be dropped.
 *
 * @param {Object} [oauthError] - The `oauthError` payload attached by ImapFlow, if any
 * @returns {boolean} True when the cached access token should be invalidated
 */
function shouldInvalidateAccessToken(oauthError) {
    let status = oauthError && oauthError.status;
    if (!status) {
        return false;
    }

    // OAUTHBEARER (RFC 7628) carries a symbolic code. Per RFC 6750 `invalid_token` is the one that
    // actually means expired, revoked or malformed. `invalid_request` means the SASL request itself
    // was malformed, so a fresh token cannot fix it - kept because providers do send it for stale
    // credentials in practice, but it is not a reliable staleness signal.
    if (status === 'invalid_token' || status === 'invalid_request') {
        return true;
    }

    // XOAUTH2 puts a numeric HTTP status here instead of a symbolic code, and it is what Gmail and
    // Exchange Online actually negotiate - ImapFlow only sends OAUTHBEARER when the server
    // advertises AUTH=OAUTHBEARER. Matching the symbolic codes alone therefore never fired for the
    // two providers that dominate OAuth2-IMAP, so a revoked-but-cached token was re-presented until
    // it expired naturally. 401 is the only status that means "this token was rejected"; a 4xx like
    // 400 is a malformed request and a 5xx is the server's own problem, neither of which a fresh
    // token fixes.
    return Number(status) === 401;
}

module.exports = { shouldInvalidateAccessToken };
