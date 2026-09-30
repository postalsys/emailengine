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
 * What the primary connection knows of the main mailbox's UIDNEXT: the higher of the stored value
 * and the one its session reports. Neither is enough alone. A partial sync stores the snapshot it
 * took before fetching, while ImapFlow moves the session's UIDNEXT once a FETCH returns a newer
 * UID, so the stored value trails a healthy session by one fetch. And a message delivered and
 * expunged before the primary fetched it leaves the stored value behind the server's for good on
 * a CONDSTORE server whose HIGHESTMODSEQ did not move, while the SELECT of the next session reports
 * the server's value. A frozen session's UIDNEXT is as frozen as the rest of its view
 * @param {Number|false} storedUidNext - uidNext the sync state machine last stored
 * @param {Number|false} sessionUidNext - UIDNEXT the primary connection's session reports
 * @returns {Number|false} The known UIDNEXT, false when neither is available
 */
function knownUidNext(storedUidNext, sessionUidNext) {
    const values = [storedUidNext, sessionUidNext].filter(value => typeof value === 'number' && value > 0);
    return values.length ? Math.max(...values) : false;
}

// Fresh state: the quiet period starts at `now` from this UIDNEXT
const baseline = (now, uidNext) => ({ checkedAt: now, uidNext, confirmations: 0 });

/**
 * Decides whether this resync pass should look at the main mailbox over a second connection.
 * Only a connection whose known UIDNEXT has not moved for a whole interval is probed, so an
 * account that keeps receiving mail never pays for the extra login
 * @param {Object|null} state - State returned by the previous call on this connection, or null
 * @param {Number|false} uidNext - Known UIDNEXT of the main mailbox, see knownUidNext()
 * @param {Number} now - Current time in milliseconds
 * @param {Number} interval - Quiet period before probing, in milliseconds. Falsy disables the check
 * @returns {{ probe: Boolean, state: Object|null }} Whether to probe, and the state to keep
 */
function planStaleViewProbe(state, uidNext, now, interval) {
    if (!interval || !uidNext) {
        // Disabled, or a server that reports no UIDNEXT - there is nothing to compare against
        return { probe: false, state: null };
    }

    if (!state || state.uidNext !== uidNext) {
        // First pass on this connection, or something arrived since the last look. Either way
        // it is not stale, and the quiet period starts over
        return { probe: false, state: baseline(now, uidNext) };
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
 * Compares the STATUS answer of a second connection with what the primary connection knows
 * @param {Object} state - State returned by planStaleViewProbe() for the pass that probed
 * @param {Object} known - { uidNext, uidValidity } the primary knows, read after the probe answered
 * @param {Object|null} serverStatus - STATUS answer (uidNext, uidValidity) from the second connection
 * @param {Number} now - Current time in milliseconds
 * @returns {{ stale: Boolean, ahead: Boolean, state: Object|null }} Whether to drop the primary
 *     connection, whether this probe found the server ahead, and the state to keep
 */
function evaluateStaleViewProbe(state, known, serverStatus, now) {
    if (!known.uidNext) {
        return { stale: false, ahead: false, state: null };
    }

    if (!state || state.uidNext !== known.uidNext) {
        // Something arrived on the primary connection while the probe was running - it is alive
        return { stale: false, ahead: false, state: baseline(now, known.uidNext) };
    }

    const ahead =
        typeof serverStatus?.uidNext === 'number' &&
        serverStatus.uidNext > known.uidNext &&
        // A different UIDVALIDITY is another folder incarnation, which the open handler deals
        // with - UIDs of two incarnations say nothing about each other
        !!known.uidValidity &&
        known.uidValidity === serverStatus.uidValidity;

    const confirmations = ahead ? state.confirmations + 1 : 0;
    const stale = confirmations >= STALE_CONFIRMATIONS;

    return {
        stale,
        ahead,
        state: { checkedAt: now, uidNext: known.uidNext, confirmations: stale ? 0 : confirmations }
    };
}

module.exports = { knownUidNext, planStaleViewProbe, evaluateStaleViewProbe, STALE_CONFIRMATIONS };
