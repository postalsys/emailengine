'use strict';

// Exchange Online ties an IMAP session to the lifetime of the OAuth2 access token it logged in
// with. Once that token expires, the next command on the session (typically the DONE that ends
// IDLE so an API request can run) is answered with `* BYE Session invalidated -
// AccessTokenExpired`, and whatever request was in flight fails with it. Renewing the stored token
// does nothing for a session that is already open: IMAP has no way to authenticate again inside an
// authenticated session, so the session has to be replaced before its token runs out.
//
// ImapFlow does the replacing (its `sessionExpires` option, from 2.11.0): from `sessionExpiryLead`
// before the expiry it closes the connection the first time nothing runs on it, and shortly before
// the expiry it closes it regardless. The close handlers reconnect a primary connection or a
// subconnection, and a command connection is opened again for the next request. What stays here is
// deciding which sessions that applies to and making sure each login starts with a token that has
// enough life left, only for the providers listed below (a Gmail session outlives its token, and
// reconnecting those every hour would only cost a resync).

const { OAUTH_TOKEN_MIN_VALIDITY } = require('../../consts');

// Providers whose IMAP sessions end when the access token used to log in expires
const TOKEN_BOUND_SESSION_PROVIDERS = new Set(['outlook']);

// How long before the token expires the connection starts looking for a moment to close
const REAUTH_LEAD = 5 * 60 * 1000;

// Up to this much is added to the lead at random. Accounts that logged in together (a worker
// restart) renew together and would otherwise all reconnect in the same few seconds one token
// lifetime later, and every lifetime after that
const REAUTH_JITTER = 2 * 60 * 1000;

// A session that would have to be replaced sooner than this after logging in gets no deadline. Only
// a provider handing out short tokens gets there, and replacing such a session on every login would
// turn into a reconnect loop; it ends the way it did before, with the server's BYE. Longer than
// STABLE_CONNECTION_TIME, so the close handler reconnects the replaced primary at once instead of
// throttling it as a connection that died young
const REAUTH_MIN_DELAY = 6 * 60 * 1000;

// How much lifetime a token must have left to be used for a login on such a provider. Above the
// longest lead plus REAUTH_MIN_DELAY with a minute to spare, so a session that logs in with a token
// it got this way always gets a deadline. Kept close to that sum, because command connections and
// subconnections log in too, and every renewal they cause moves the next replacement of the primary
// connection earlier
const LOGIN_MIN_VALIDITY = 15 * 60 * 1000;

/**
 * How much lifetime a stored access token needs to be used as is
 * @param {string} provider - OAuth2 app provider (`outlook`, `gmail`, ...)
 * @param {string} target - What the token is for (`imap`, `smtp`, `api`)
 * @returns {number} Milliseconds
 */
function minTokenValidity(provider, target) {
    return target === 'imap' && TOKEN_BOUND_SESSION_PROVIDERS.has(provider) ? LOGIN_MIN_VALIDITY : OAUTH_TOKEN_MIN_VALIDITY;
}

/**
 * The ImapFlow options that close a session before the token it logs in with expires, or null when
 * the session does not end with its token (or the token is too short-lived to bother)
 * @param {string} provider - OAuth2 app provider
 * @param {Date|string|number} expires - Expiry of the token the session logs in with
 * @param {number} now - Current epoch milliseconds
 * @param {Function} [random=Math.random] - Source of the jitter, for tests
 * @returns {{sessionExpires: number, sessionExpiryLead: number}|null}
 */
function sessionExpiryOptions(provider, expires, now, random = Math.random) {
    if (!TOKEN_BOUND_SESSION_PROVIDERS.has(provider) || !expires) {
        return null;
    }
    const sessionExpires = new Date(expires).getTime();
    const sessionExpiryLead = REAUTH_LEAD + Math.round(random() * REAUTH_JITTER);
    if (!Number.isFinite(sessionExpires) || sessionExpires - sessionExpiryLead - now < REAUTH_MIN_DELAY) {
        return null;
    }
    return { sessionExpires, sessionExpiryLead };
}

module.exports = {
    LOGIN_MIN_VALIDITY,
    REAUTH_LEAD,
    REAUTH_JITTER,
    REAUTH_MIN_DELAY,
    minTokenValidity,
    sessionExpiryOptions
};
