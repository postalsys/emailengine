'use strict';

// How the IMAP proxy tells a failure it may answer the client with from an internal fault.
// Dependency-free on purpose: lib/imapproxy/proxy-handoff.js needs these, and lib/imap-proxy-auth.js,
// which used to define them, opens the Redis connection at require time. That module re-exports
// them for the callers that always took them from there.

/**
 * Whether an error already names the IMAP response to answer the client with, as opposed to being
 * an internal proxy fault. Both a refusal and a temporary failure carry one.
 *
 * @param {Error} err - The error to check
 * @returns {boolean} True when the error carries an IMAP response
 */
function isImapResponseError(err) {
    return !!err && (!!err.authenticationFailed || err.serverResponseCode === 'AUTHENTICATIONFAILED' || err.serverResponseCode === 'UNAVAILABLE');
}

/**
 * Renders a tagged failure as the error the IMAP server answers the client with. imap-core reads
 * the status off `response`, and an error that carries none is answered BAD, which counts against
 * the connection's bad-command budget instead of telling the client what happened.
 *
 * @param {Error} err - The tagged failure
 * @returns {Error} A new error carrying the response line to send
 */
function toImapResponseError(err) {
    let error = new Error(`${err.serverResponseCode ? `[${err.serverResponseCode}] ` : ''}${err.responseText || err.message || 'Authentication failed'}`);
    error.response = err.responseStatus || 'NO';
    return error;
}

module.exports = { isImapResponseError, toImapResponseError };
