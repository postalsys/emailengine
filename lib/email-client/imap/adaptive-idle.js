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
// with a similar quiet time set the interval to a fraction of it. A session cap is the other way a
// server ends sessions: Vimexx ends every one after about six minutes however often the client
// writes. Shortening the interval does not help there, which shows as sessions still ending at the
// same age as before the interval was learned, and the host then goes back to the default and is
// left alone for a day. A learned interval relaxes again after a run of long stable sessions.
//
// Pure: the state is a plain object the caller stores, so every rule is testable on its own.

const { IMAP_MAX_IDLE_TIME_MIN } = require('../../consts');

// Fraction of the observed quiet time to restart IDLE at, leaving room for timers and latency
const LEARN_RATIO = 0.6;
// A drop after this much quiet is within what a server may do (RFC 9051 allows 30 minutes)
const LEARN_CEILING = 25 * 60 * 1000;
// Drops with a similar quiet time needed before an interval is learned or lowered
const CONFIRM_DROPS = 2;
// How close two quiet times or two session ages must be to count as the same
const SIMILAR = 0.25;
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

const similar = (a, b) => a > 0 && b > 0 && Math.abs(a - b) <= SIMILAR * Math.max(a, b);

/**
 * The state of a host nothing has been learned for
 * @returns {Object}
 */
function initialState() {
    return { interval: null, pendingQuiet: null, pendingAt: 0, drops: 0, stable: 0, ageWhenLearned: null, cappedUntil: 0 };
}

/**
 * Applies one observation to a host's state
 * @param {Object|null} state - Stored state, or null for a host with none
 * @param {Object} observation - `{ type: 'drop', quietMs, ageMs, idling }` for a connection that
 *     closed unexpectedly, `{ type: 'stable', ageMs }` for one that lived long and closed
 * @param {number} now - Epoch ms
 * @returns {Object} The new state (a new object, the input is left alone)
 */
function observe(state, observation, now) {
    const next = Object.assign(initialState(), state || {});

    if (observation.type === 'stable') {
        if (!(observation.ageMs >= STABLE_SESSION)) {
            return next;
        }
        next.drops = 0;
        next.pendingQuiet = null;
        next.pendingAt = 0;
        if (next.interval) {
            next.stable++;
            if (next.stable >= RELAX_AFTER) {
                const relaxed = Math.round(next.interval * RELAX_FACTOR);
                next.interval = relaxed >= LEARN_CEILING ? null : relaxed;
                next.ageWhenLearned = next.interval ? next.ageWhenLearned : null;
                next.stable = 0;
            }
        }
        return next;
    }

    if (observation.type !== 'drop' || !observation.idling || now < next.cappedUntil) {
        return next;
    }
    const { quietMs, ageMs } = observation;
    if (!(quietMs > 0) || quietMs >= LEARN_CEILING) {
        return next;
    }

    next.stable = 0;

    // Learned, and sessions still end at the age they ended at before: a cap on the session, not on
    // its quiet time, which no interval can get under
    if (next.interval && next.ageWhenLearned && similar(ageMs, next.ageWhenLearned)) {
        return Object.assign(initialState(), { cappedUntil: now + CAP_COOLDOWN });
    }

    if (next.pendingAt && now - next.pendingAt < SAME_EVENT_WINDOW) {
        // the same event, seen through another account of the host
        return next;
    }

    const confirming = next.pendingQuiet && similar(quietMs, next.pendingQuiet);
    next.drops = confirming ? next.drops + 1 : 1;
    // the shortest quiet time of the run of similar drops: the timer is at most that long
    next.pendingQuiet = confirming ? Math.min(quietMs, next.pendingQuiet) : quietMs;
    next.pendingAt = now;

    if (next.drops >= CONFIRM_DROPS) {
        const candidate = Math.max(IMAP_MAX_IDLE_TIME_MIN, Math.floor(next.pendingQuiet * LEARN_RATIO));
        if (!next.interval || candidate < next.interval) {
            if (!next.interval) {
                next.ageWhenLearned = ageMs;
            }
            next.interval = candidate;
        }
        next.drops = 0;
        next.pendingQuiet = null;
        next.pendingAt = 0;
    }

    return next;
}

/**
 * The observation a closed primary connection makes, or null when its close says nothing about the
 * server's timers (a close EmailEngine asked for, a connection that never got a socket)
 * @param {Object} imapClient - The closed ImapFlow client
 * @param {number} now - Epoch ms
 * @returns {Object|null}
 */
function observationFor(imapClient, now) {
    if (!imapClient || imapClient.context?.disabled || !imapClient.connectedAt) {
        return null;
    }
    const ageMs = now - imapClient.connectedAt;
    if (ageMs >= STABLE_SESSION) {
        return { type: 'stable', ageMs };
    }
    if (!imapClient.lastClientWrite) {
        return null;
    }
    return { type: 'drop', quietMs: now - imapClient.lastClientWrite, ageMs, idling: !!imapClient.idlingAtClose };
}

module.exports = { observe, observationFor, initialState, LEARN_CEILING, STABLE_SESSION, RELAX_AFTER, CAP_COOLDOWN, SAME_EVENT_WINDOW };
