'use strict';

// Shared token validation for the SMTP and IMAP-proxy submission servers. Both
// servers accept a 64-char hex API token as the password and apply the same
// checks (account binding, scope, IP allowlist). The logic lives here so the two
// auth handlers (lib/smtp-auth.js, lib/imap-proxy-auth.js) cannot drift apart -
// a token security-policy change is made once and applies to both surfaces.

const logger = require('./logger');
const tokens = require('./tokens');
const { matchIp } = require('./utils/network');

// Reason-specific denial messages, shared verbatim by both auth handlers. The
// generic "failed to authenticate" fallback and any protocol-specific error
// decoration are left to each caller.
const REASON_MESSAGES = {
    username: 'Access denied, invalid username',
    scope: 'Access denied, invalid scope',
    ip: 'Access denied, traffic not accepted from this IP'
};

/**
 * Validates a 64-char hex API token supplied as a server password.
 *
 * Performs the token lookup plus the account-binding, scope and IP-allowlist
 * checks. Does NOT throw - the caller maps the returned reason to its own
 * protocol-specific error (SMTP and IMAP use different response shapes).
 *
 * @param {Object} opts
 * @param {String} opts.password - supplied password (candidate token)
 * @param {String} opts.account - username the client authenticated as
 * @param {String} opts.requiredScope - scope the token must hold ('smtp' | 'imap-proxy')
 * @param {String} opts.remoteAddress - client IP, checked against token restrictions
 * @returns {Promise<{authenticated: Boolean, reason: (null|'username'|'scope'|'ip')}>}
 */
async function validateAuthToken({ password, account, requiredScope, remoteAddress }) {
    if (!/^[0-9a-f]{64}$/i.test(password)) {
        return { authenticated: false, reason: null };
    }

    let tokenData;
    try {
        tokenData = await tokens.get(password, false, { log: true, remoteAddress });
    } catch (err) {
        logger.error({ msg: 'Failed to fetch token', err });
    }

    if (!tokenData) {
        return { authenticated: false, reason: null };
    }

    if (tokenData.account && tokenData.account !== account) {
        return { authenticated: false, reason: 'username' };
    }

    if (tokenData.scopes && !tokenData.scopes.includes(requiredScope) && !tokenData.scopes.includes('*')) {
        logger.error({
            msg: 'Trying to use invalid scope for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            requestedScope: requiredScope,
            scopes: tokenData.scopes
        });
        return { authenticated: false, reason: 'scope' };
    }

    if (tokenData.restrictions && tokenData.restrictions.addresses && !matchIp(remoteAddress, tokenData.restrictions.addresses)) {
        logger.error({
            msg: 'Trying to use invalid IP for a token',
            tokenAccount: tokenData.account,
            tokenId: tokenData.id,
            account,
            remoteAddress,
            addressAllowlist: tokenData.restrictions.addresses
        });
        return { authenticated: false, reason: 'ip' };
    }

    return { authenticated: true, reason: null };
}

module.exports = { validateAuthToken, REASON_MESSAGES };
