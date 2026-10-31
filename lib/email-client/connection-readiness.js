'use strict';

// Whether an account connection that was just assigned is still starting up, and waiting for it.
//
// When an account moves between EmailEngine instances (lib/cluster/), a request can reach the new
// owner a moment after it took the account over. Run at once, it fails with whatever the half-built
// connection has to say: a folder or message that is "not found" because the mailbox listing has
// not been loaded, or no connection at all. The same happens on a single instance right after a
// restart. A command waits for the connection to get that far, for a bounded time, and then runs
// whatever the state is, as before.
//
// Only the start of a connection is waited for: an IMAP connection is usable once its mailbox
// listing is loaded, well before its first full sync ends, and waiting for the sync would hold
// every read on a large mailbox for its whole duration.

const STARTING_STATES = new Set(['init', 'connecting']);

/**
 * @param {Object} connection - An email client (lib/email-client/*-client.js)
 * @returns {boolean}
 */
function isStartingUp(connection) {
    if (!connection) {
        return false;
    }
    if (STARTING_STATES.has(connection.state)) {
        return true;
    }
    // An IMAP connection in its initial sync, before the folder listing is registered
    return connection.state === 'syncing' && connection.mailboxes instanceof Map && connection.mailboxes.size === 0;
}

/**
 * Waits while the connection is starting up, at most `timeout` milliseconds
 * @param {Function} getConnection - Returns the account's connection now (it can be replaced meanwhile)
 * @param {number} timeout
 * @param {number} [interval]
 * @returns {Promise<boolean>} true when it waited at all
 */
async function waitUntilStarted(getConnection, timeout, interval = 50) {
    if (!isStartingUp(getConnection())) {
        return false;
    }
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline && isStartingUp(getConnection())) {
        await new Promise(resolve => setTimeout(resolve, interval));
    }
    return true;
}

module.exports = { isStartingUp, waitUntilStarted };
