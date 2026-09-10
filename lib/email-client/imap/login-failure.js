'use strict';

// What an IMAP server's answer to a login means. ImapFlow flags every failed AUTHENTICATE or LOGIN
// as `authenticationFailed`, which is the fact of what happened; whether the credential was refused
// or the server could not serve the login right now is decided here, the way
// lib/email-client/credential-errors.js decides it for a token endpoint. Reporting a backend outage
// as `authenticationError` puts the account in an error state that re-authorizing cannot clear, and
// the login that follows the outage then contradicts it with `authenticationSuccess`.
//
// Dependency-free on purpose: subconnection.js consults it, and the pure subconnection tests would
// otherwise inherit the Redis connections lib/tools.js opens at load and never exit.

// The RFC 5530 codes a server puts on a NO when the failure is its own and temporary: a subsystem
// the login depends on is down, the server tripped over itself, or a limit was hit.
// AUTHENTICATIONFAILED, AUTHORIZATIONFAILED, EXPIRED and PRIVACYREQUIRED are the verdicts on the
// credential
const TRANSIENT_RESPONSE_CODES = new Set(['UNAVAILABLE', 'SERVERBUG', 'INUSE', 'LIMIT']);

// The same meaning carried by text alone. Exchange Online sends no response code, and "User is
// authenticated but not connected." is its front end saying the token was accepted but the
// mailbox's backend could not be reached - a failover, a mailbox move, a throttled backend. It says
// the same thing permanently when IMAP is disabled for the mailbox, which is why a match is
// reported as a connection failure carrying the text rather than dropped
const TRANSIENT_RESPONSE_TEXT = /user is authenticated but not connected/i;

/**
 * The readable text of a failed IMAP command. ImapFlow rewrites err.response into the response line
 * for a login failure and leaves the parsed response object there for any other command, so the
 * text field is the fallback - a stored error state or webhook payload built off the object would
 * render as "[object Object]"
 * @param {Error} err - The error ImapFlow threw
 * @returns {string|undefined} The response line or its text, when there is one
 */
function imapResponseText(err) {
    return (typeof err?.response === 'string' && err.response) || err?.responseText;
}

/**
 * Whether a failed IMAP login is the server refusing the credential, as opposed to being unable to
 * serve the login right now
 * @param {Error} err - The error a login attempt threw
 * @returns {boolean} True when the server rejected the credential
 */
function isRefusedImapLogin(err) {
    if (!err || !err.authenticationFailed || TRANSIENT_RESPONSE_CODES.has(err.serverResponseCode)) {
        return false;
    }

    return !TRANSIENT_RESPONSE_TEXT.test(imapResponseText(err) || '');
}

module.exports = { imapResponseText, isRefusedImapLogin };
