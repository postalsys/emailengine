'use strict';

/**
 * Decisions for the stale view check of the main mailbox (EENGINE_IMAP_STALE_CHECK_INTERVAL).
 *
 * Some servers keep a long-lived session healthy on the wire - IDLE, NOOP, LIST and STATUS of
 * other folders all answer OK - while the session's view of the selected mailbox stops moving.
 * No EXISTS arrives, and a FETCH or SEARCH on that connection answers from the frozen view, so
 * nothing the primary connection can do reveals it. A new session sees the messages, which is
 * why the check asks a second connection and why the only remedy is reconnecting.
 *
 * Kept free of connection and Redis code so the rules can be tested on their own.
 */

// A probe that finds the server ahead has to be confirmed by the next one before the primary
// connection is dropped. A message that landed just before the probe is normally still on its
// way through EXISTS and the partial sync it triggers, and the next probe no longer sees it
const STALE_CONFIRMATIONS = 2;

/**
 * Decides whether this resync pass should look at the main mailbox over a second connection.
 * Only a connection that has stored nothing new for a whole interval is probed, so an account
 * that keeps receiving mail never pays for the extra login
 * @param {Object|null} state - State returned by the previous call on this connection, or null
 * @param {Number|false} storedUidNext - uidNext the sync state machine last stored for the main mailbox
 * @param {Number} now - Current time in milliseconds
 * @param {Number} interval - Quiet period before probing, in milliseconds. Falsy disables the check
 * @returns {{ probe: Boolean, state: Object|null }} Whether to probe, and the state to keep
 */
function planStaleViewProbe(state, storedUidNext, now, interval) {
    if (!interval || typeof storedUidNext !== 'number' || !storedUidNext) {
        // Disabled, or a server that reports no UIDNEXT - there is nothing to compare against
        return { probe: false, state: null };
    }

    if (!state || state.uidNext !== storedUidNext) {
        // First pass on this connection, or the connection stored something since the last
        // look. Either way it is not stale, and the quiet period starts over
        return { probe: false, state: { checkedAt: now, uidNext: storedUidNext, confirmations: 0 } };
    }

    if (now - state.checkedAt < interval) {
        return { probe: false, state };
    }

    // The clock restarts as the probe is decided, not when it answers: a probe that fails (the
    // second login refused, another folder open on the primary) must wait out a whole interval
    // like any other, not log in again on the next resync pass
    return { probe: true, state: Object.assign({}, state, { checkedAt: now }) };
}

/**
 * Compares the STATUS answer of a second connection with what the primary connection knows.
 *
 * The primary knows the higher of the stored UIDNEXT and the one its session reports. The stored
 * value alone is not enough: a message delivered and expunged before the primary fetched it
 * leaves the server's UIDNEXT ahead of the stored one, and on a CONDSTORE server whose
 * HIGHESTMODSEQ did not move the open handler stores nothing after a reconnect, so the gap - and
 * the reconnect - would repeat forever. A fresh session's SELECT closes it. A stale session
 * does not, its UIDNEXT is as frozen as the rest of its view
 * @param {Object} state - State returned by planStaleViewProbe() for the pass that probed
 * @param {Object} storedStatus - Stored status of the main mailbox, read after the probe answered
 * @param {Number|false} sessionUidNext - UIDNEXT the primary connection's session reports for the main mailbox
 * @param {Object|null} serverStatus - STATUS answer (uidNext, uidValidity) from the second connection
 * @param {Number} now - Current time in milliseconds
 * @returns {{ stale: Boolean, ahead: Boolean, state: Object|null }} Whether to drop the primary
 *     connection, whether this probe found the server ahead, and the state to keep
 */
function evaluateStaleViewProbe(state, storedStatus, sessionUidNext, serverStatus, now) {
    const storedUidNext = storedStatus && storedStatus.uidNext;

    if (typeof storedUidNext !== 'number' || !storedUidNext) {
        return { stale: false, ahead: false, state: null };
    }

    if (!state || state.uidNext !== storedUidNext) {
        // The primary connection stored an arrival while the probe was running - it is alive
        return { stale: false, ahead: false, state: { checkedAt: now, uidNext: storedUidNext, confirmations: 0 } };
    }

    const knownUidNext = typeof sessionUidNext === 'number' ? Math.max(storedUidNext, sessionUidNext) : storedUidNext;

    const ahead =
        !!serverStatus &&
        typeof serverStatus.uidNext === 'number' &&
        serverStatus.uidNext > knownUidNext &&
        // A different UIDVALIDITY is another folder incarnation, which the open handler deals
        // with - UIDs of two incarnations say nothing about each other
        !!storedStatus.uidValidity &&
        storedStatus.uidValidity === serverStatus.uidValidity;

    const confirmations = ahead ? state.confirmations + 1 : 0;
    const stale = confirmations >= STALE_CONFIRMATIONS;

    return {
        stale,
        ahead,
        state: { checkedAt: now, uidNext: storedUidNext, confirmations: stale ? 0 : confirmations }
    };
}

module.exports = { planStaleViewProbe, evaluateStaleViewProbe, STALE_CONFIRMATIONS };
