'use strict';

// The failures the IMAP client raises on its own behalf, rather than passing on something a server
// said. Each was written out by hand at every site that needed it - ten copies of the first alone,
// across imap-client.js, mailbox.js and sync-operations.js - which is how one of them ended up
// carrying a different code from the rest.
//
// The first two are in CONNECTION_CLOSING_CODES, so every existing handler already treats them as
// "the connection is gone, retry after the reconnect" rather than as a command failure.
// `IMAPUnavailable` is deliberately NOT in that set: it says the account has no usable connection
// to serve a request with, which is a 503 for the caller and not something a sync retries past.
// All of them are 503, which is what an API path reports.

const { ImapFlowErrorCode } = require('imapflow');
const { CONNECTION_CLOSING_CODES } = require('../../consts');

/**
 * There is no connection to run this on: the client was torn down and not replaced yet.
 * @returns {Error} A connection-closing error
 */
function connectionNotAvailableError() {
    const err = new Error('IMAP connection not available');
    err.code = 'IMAPConnectionClosing';
    err.statusCode = 503;
    return err;
}

/**
 * The connection went away in the middle of a sync. The original failure is kept as `cause`,
 * because on this path it is the only record of why the server dropped the connection
 * (NO [OVERQUOTA], * BYE Too many connections, [SERVERBUG]).
 * @param {Error} [cause] - What the server or socket reported
 * @returns {Error} A connection-closing error
 */
function connectionClosedError(cause) {
    const err = new Error('IMAP connection closed during sync', { cause });
    err.code = 'IMAPConnectionClosing';
    err.statusCode = 503;
    return err;
}

/**
 * The account has no usable connection to serve this request with. Unlike the two above, this is
 * the answer to a caller rather than a signal to a sync loop, so its code stays outside
 * CONNECTION_CLOSING_CODES and nothing retries past it.
 * @returns {Error} A 503 for the caller
 */
function connectionUnavailableError() {
    const err = new Error('IMAP connection is currently not available for requested account');
    err.code = 'IMAPUnavailable';
    err.statusCode = 503;
    return err;
}

/**
 * Whether a failed FETCH in a sync loop ends the pass instead of being retried: the connection is
 * no longer usable, or the folder the loop locked is no longer the one selected. ImapFlow used to
 * answer a FETCH with no mailbox selected by returning no rows, which a full sync took for an empty
 * folder; since 2.6.0 it throws NoMailboxSelected, and retrying would only throw it again
 * @param {Object} imapClient - The connection the loop fetches on
 * @param {Error} err - The FETCH failure
 * @returns {boolean}
 */
function syncInterrupted(imapClient, err) {
    return !imapClient.usable || err?.code === 'NoMailboxSelected';
}

/**
 * Gives a failed command's error the HTTP status the API should answer with, when the error came
 * from ImapFlow with a code but no status of its own. Called by the IMAP worker before the error is
 * sent back to the caller, so every surface (REST, MCP, admin UI) answers the same.
 *
 * - Throttled after every retry: 429, the caller should back off, the same answer a throttled
 *   Gmail or Graph request gets.
 * - The connection went away under the command (ImapFlow's NoConnection after a server BYE, such as
 *   Exchange Online ending a session whose access token expired): 503. The account reconnects on
 *   its own, so the request can be retried; it used to be a 500, which reads as a fault.
 *
 * @param {Error} err - The command failure, changed in place
 * @returns {Error} The same error
 */
function assignRelayStatus(err) {
    if (!err || typeof err !== 'object' || err.statusCode) {
        return err;
    }
    if (err.code === ImapFlowErrorCode.ETHROTTLE) {
        err.statusCode = 429;
    } else if (CONNECTION_CLOSING_CODES.has(err.code)) {
        err.statusCode = 503;
    }
    return err;
}

module.exports = { connectionNotAvailableError, connectionClosedError, connectionUnavailableError, syncInterrupted, assignRelayStatus };
