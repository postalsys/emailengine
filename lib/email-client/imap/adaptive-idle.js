'use strict';

// Learns how often to restart IDLE for a server that drops idle sessions without saying so.
//
// Some servers, or a proxy in front of them, close a session that has been quiet for a while with
// no BYE: TransIP cuts one 30 seconds after the client last wrote, far below the 30 minutes RFC 9051
// asks for. Restarting IDLE before that point is a write, which keeps the session alive, and an
// operator can set the interval per account (imap.maxIdleTime) once they have found the number by
// hand. This finds it from the drops themselves, per server host, so every account on the host
// benefits from what one of them saw.
//
// The signal is a primary connection that closed while it was idling, after a quiet time (since
// the client last wrote) that is well short of what a server may legitimately allow. Two such drops
// with a similar quiet time set the interval to a fraction of it, and lowering a learned interval
// takes three. A session cap is the other way a server ends sessions: Vimexx ends every one after
// about six minutes however often the client writes. Shortening the interval does not help there,
// which shows as sessions (two of them) still ending at the same age as before the interval was
// learned, and the host then goes back to the default and is left alone for a day. Only a
// connection that ran the learned interval can show that: one opened before it was learned, or by an
// account with its own interval, ends at the old age because it never restarted IDLE any sooner. A
// learned interval relaxes again after a run of long stable sessions, and a relaxed interval the
// server cuts goes back to the one it relaxed from, which is then as far as relaxing goes.
//
// Pure: the state is a plain object the caller stores, so every rule is testable on its own.

const { IMAP_MAX_IDLE_TIME_MIN } = require('../../consts');

// Fraction of the observed quiet time to restart IDLE at, leaving room for timers and latency
const LEARN_RATIO = 0.6;
// A drop after this much quiet is within what a server may do (RFC 9051 allows 30 minutes)
const LEARN_CEILING = 25 * 60 * 1000;
// Drops with a similar quiet time needed before an interval is learned, and before a learned one is
// lowered. Lowering asks for more: a connection running an interval is never quiet for longer than
// it, so a network blip on it always looks like a shorter timer, and two blips can happen to agree
const CONFIRM_DROPS = 2;
const LOWER_CONFIRM_DROPS = 3;
// A run of similar drops, or of cap or revert evidence, older than this confirms nothing: a timer
// that cuts sessions does so on every session, not once a week
const PENDING_WINDOW = 60 * 60 * 1000;
// How close two quiet times or two session ages must be to count as the same. Drops that would lower
// a learned interval have to agree more closely: a timer that got shorter cuts at the same quiet time
// every time, while blips land anywhere up to the interval
const SIMILAR = 0.25;
const LOWER_SIMILAR = 0.1;
// A session this long is evidence the interval works
const STABLE_SESSION = 30 * 60 * 1000;
// Stable sessions in a row before the interval relaxes, and by how much
const RELAX_AFTER = 3;
const RELAX_FACTOR = 1.5;
// How long a host that turned out to cap sessions is left alone
const CAP_COOLDOWN = 24 * 3600 * 1000;
// Drops closer together than this are one event (a proxy restart, a network blip) seen by several
// accounts on the host, and can not confirm each other
const SAME_EVENT_WINDOW = 10 * 1000;

const similar = (a, b, ratio = SIMILAR) => a > 0 && b > 0 && Math.abs(a - b) <= ratio * Math.max(a, b);

/**
 * The state of a host nothing has been learned for
 * @returns {Object}
 */
function initialState() {
    return {
        interval: null,
        pendingQuiet: null,
        pendingAt: 0,
        drops: 0,
        stable: 0,
        ageWhenLearned: null,
        cappedUntil: 0,
        // the interval the last relaxing step started from, and a relaxed interval the server cut
        relaxedFrom: null,
        relaxLimit: null,
        // sessions on the learned interval that look like a session cap, or (after a relaxing step,
        // which clears the learning age, so never both) that the server cut on the relaxed interval,
        // and when the last one was seen; CONFIRM_DROPS of them are acted on
        evidenceDrops: 0,
        evidenceAt: 0
    };
}

/**
 * One relaxing step after a run of stable sessions, in place: half as long again, unless that
 * reaches an interval the server already cut (`relaxLimit`), and back to the default once near what
 * a server may allow. Clears the age the interval was learned at, since sessions this long are not
 * capped
 * @param {Object} state
 */
function relax(state) {
    state.stable = 0;
    const relaxed = Math.round(state.interval * RELAX_FACTOR);
    if (state.relaxLimit && relaxed >= state.relaxLimit) {
        return;
    }
    state.ageWhenLearned = null;
    if (relaxed >= LEARN_CEILING) {
        Object.assign(state, initialState());
        return;
    }
    state.relaxedFrom = state.interval;
    state.interval = relaxed;
}

/**
 * Applies one observation to a host's state
 * @param {Object|null} state - Stored state, or null for a host with none
 * @param {Object} observation - `{ type: 'drop', quietMs, ageMs, idling, ranInterval }` for a
 *     connection that closed unexpectedly (`ranInterval` is the IDLE restart interval it ran with,
 *     null for none), `{ type: 'stable', ageMs, ranInterval }` for one that lived long and closed
 * @param {number} now - Epoch ms
 * @returns {Object} The new state (a new object, the input is left alone)
 */
function observe(state, observation, now) {
    const next = Object.assign(initialState(), state || {});
    if (next.cappedUntil && now >= next.cappedUntil) {
        // a cooldown that is over is nothing to keep, and leaves the host free to learn again
        next.cappedUntil = 0;
    }
    if (next.pendingAt && now - next.pendingAt >= PENDING_WINDOW) {
        clearPending(next);
    }
    if (next.evidenceAt && now - next.evidenceAt >= PENDING_WINDOW) {
        clearEvidence(next);
    }

    if (observation.type === 'stable') {
        return observeStable(next, observation);
    }

    if (observation.type !== 'drop' || !observation.idling || now < next.cappedUntil) {
        return next;
    }
    const { quietMs, ageMs, ranInterval } = observation;
    if (!(quietMs > 0) || quietMs >= LEARN_CEILING) {
        return next;
    }

    next.stable = 0;
    // whether this connection restarted IDLE at least as often as the learned interval asks
    const ranLearned = !!(next.interval && ranInterval > 0 && ranInterval <= next.interval);

    // Whether the session restarted IDLE on its interval before the cut: its last write came more
    // than one interval into the session. A cut before the first restart is a quiet timer shorter
    // than the interval; one after it is not about the interval at all (a blip, a session cap)
    const restarted = ageMs - quietMs > ranInterval;

    // A relaxed interval the server cuts before the first restart: back to the one that held, and no
    // further. A session that did restart on it says nothing against it
    if (next.relaxedFrom && ranInterval === next.interval && !restarted) {
        if (countEvidence(next, now)) {
            next.relaxLimit = next.interval;
            next.interval = next.relaxedFrom;
            next.relaxedFrom = null;
            clearPending(next);
        }
        return next;
    }

    // Sessions that ran the learned interval, restarted IDLE on it and still end at the age they ended
    // at before: a cap on the session, not on its quiet time, which no interval can get under. A cut
    // before the first restart is a quiet timer shorter than the interval, left to the lowering below
    if (ranLearned && restarted && next.ageWhenLearned && similar(ageMs, next.ageWhenLearned)) {
        return countEvidence(next, now) ? Object.assign(initialState(), { cappedUntil: now + CAP_COOLDOWN }) : next;
    }

    if (next.pendingAt && now - next.pendingAt < SAME_EVENT_WINDOW) {
        // the same event, seen through another account of the host
        return next;
    }

    const confirming = next.pendingQuiet && similar(quietMs, next.pendingQuiet, next.interval ? LOWER_SIMILAR : SIMILAR);
    next.drops = confirming ? next.drops + 1 : 1;
    // the shortest quiet time of the run of similar drops: the timer is at most that long
    next.pendingQuiet = confirming ? Math.min(quietMs, next.pendingQuiet) : quietMs;
    next.pendingAt = now;

    if (next.drops >= (next.interval ? LOWER_CONFIRM_DROPS : CONFIRM_DROPS)) {
        const candidate = Math.max(IMAP_MAX_IDLE_TIME_MIN, Math.floor(next.pendingQuiet * LEARN_RATIO));
        if (!next.interval || candidate < next.interval) {
            if (!next.interval) {
                next.ageWhenLearned = ageMs;
            }
            next.interval = candidate;
            // a relaxing step this undercuts is no longer the one to go back to
            next.relaxedFrom = null;
        }
        clearPending(next);
    }

    return next;
}

/**
 * A long session closing: evidence the interval works. Counts towards relaxing, and a session that
 * ran a relaxed interval proves it, so later drops are no longer a reason to go back
 * @param {Object} next - State, changed in place
 * @param {Object} observation - `{ type: 'stable', ageMs, ranInterval }`
 * @returns {Object} next
 */
function observeStable(next, observation) {
    if (!(observation.ageMs >= STABLE_SESSION)) {
        return next;
    }
    clearPending(next);
    clearEvidence(next);
    if (next.interval) {
        if (next.relaxedFrom && observation.ranInterval === next.interval) {
            next.relaxedFrom = null;
        }
        next.stable++;
        if (next.stable >= RELAX_AFTER) {
            relax(next);
        }
    }
    return next;
}

/**
 * Counts one session of evidence for the cap or the relax-revert rule, sessions closer together
 * than SAME_EVENT_WINDOW counting once
 * @param {Object} next - State, changed in place
 * @param {number} now
 * @returns {boolean} Whether there is now enough to act on (the count is then reset)
 */
function countEvidence(next, now) {
    if (!(next.evidenceAt && now - next.evidenceAt < SAME_EVENT_WINDOW)) {
        next.evidenceDrops++;
        next.evidenceAt = now;
    }
    if (next.evidenceDrops < CONFIRM_DROPS) {
        return false;
    }
    clearEvidence(next);
    return true;
}

function clearEvidence(next) {
    next.evidenceDrops = 0;
    next.evidenceAt = 0;
}

function clearPending(next) {
    next.drops = 0;
    next.pendingQuiet = null;
    next.pendingAt = 0;
}

/**
 * The observation a closed primary connection makes, or null when its close says nothing about the
 * server's timers (a close EmailEngine asked for, which ImapFlow reports as closedByClient, a
 * connection that never got a socket)
 * @param {Object} imapClient - The closed ImapFlow client
 * @param {number} now - Epoch ms
 * @returns {Object|null}
 */
function observationFor(imapClient, now) {
    if (!imapClient || imapClient.closedByClient || imapClient.context?.disabled || !imapClient.connectedAt) {
        return null;
    }
    const ageMs = now - imapClient.connectedAt;
    // ImapFlow's IDLE restart interval for this connection (ImapFlow keeps false for none)
    const ranInterval = imapClient.maxIdleTime > 0 ? imapClient.maxIdleTime : null;
    if (ageMs >= STABLE_SESSION) {
        return { type: 'stable', ageMs, ranInterval };
    }
    if (!imapClient.lastClientWrite) {
        return null;
    }
    return {
        type: 'drop',
        quietMs: now - imapClient.lastClientWrite,
        ageMs,
        idling: !!imapClient.idlingAtClose,
        ranInterval
    };
}

module.exports = { observe, observationFor, initialState, LEARN_CEILING, STABLE_SESSION, RELAX_AFTER, CAP_COOLDOWN, SAME_EVENT_WINDOW, PENDING_WINDOW };
