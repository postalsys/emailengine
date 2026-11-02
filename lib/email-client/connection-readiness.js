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
 * Whether a connection has started, once, and a wait for that. Every email client holds one and
 * notes each state change (BaseClient's `state` setter); the IMAP client also notes when its folder
 * listing is registered. A connection that started stays started: one that dropped and keeps
 * reconnecting is not waited for, and a command for it fails at once as it always has
 * @returns {{started: boolean, note: Function, release: Function, wait: Function}}
 */
function createStartSignal() {
    let started = false;
    const waiters = new Set();
    const settle = () => {
        for (const done of [...waiters]) {
            done();
        }
    };
    return {
        get started() {
            return started;
        },
        /** Marks the connection started once it is no longer starting up */
        note(connection) {
            if (!started && !isStartingUp(connection)) {
                started = true;
                settle();
            }
        },
        /** Ends every wait: the connection is closing, whatever it got to */
        release: settle,
        /**
         * Marks the connection started whatever its state: it came up as far as it will for now (a
         * failed init that is retried later), and a command for it fails at once as it always has
         */
        give() {
            started = true;
            settle();
        },
        /**
         * @param {number} timeout
         * @returns {Promise<boolean>} true when it waited at all
         */
        wait(timeout) {
            if (started) {
                return Promise.resolve(false);
            }
            return new Promise(resolve => {
                const done = () => {
                    clearTimeout(timer);
                    waiters.delete(done);
                    resolve(true);
                };
                const timer = setTimeout(done, timeout);
                waiters.add(done);
            });
        }
    };
}

module.exports = { isStartingUp, createStartSignal };
