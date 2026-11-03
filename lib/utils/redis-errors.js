'use strict';

// Which Redis reply errors say "not now" rather than "never". Dependency-free, so pure modules and
// their tests can ask.
//
// A cut connection never reaches the code as an error (ioredis runs with maxRetriesPerRequest null
// and sends the command again once it has reconnected), so these replies are how a Redis problem
// does reach it: OOM for every write and script while used memory is over maxmemory, LOADING while a
// restarted Redis loads its dataset, BUSY while a script runs past its time limit, READONLY and
// MASTERDOWN around a failover, MISCONF while snapshots fail, the cluster ones while slots move. All
// of them clear up without anything changing on our side, so a caller that holds work durably (a
// queued arrival, a retried job) keeps it rather than drop it.

const TRANSIENT_REPLY = /^(OOM|LOADING|BUSY|READONLY|MASTERDOWN|MISCONF|TRYAGAIN|CLUSTERDOWN|NOREPLICAS)\b/;

/**
 * Whether an error is a Redis reply that a later attempt can get past. EXECABORT counts when every
 * command that failed inside the transaction did so for such a reason (ioredis collects them in
 * `previousErrors`); a transaction refused for a syntax error fails the same way every time. An
 * error that wraps one (its `cause`) counts as well
 * @param {Error} err
 * @returns {boolean}
 */
function isTransientRedisError(err, depth = 0) {
    if (!err || depth > 5) {
        return false;
    }
    if (err.name !== 'ReplyError' || typeof err.message !== 'string') {
        return isTransientRedisError(err.cause, depth + 1);
    }
    if (TRANSIENT_REPLY.test(err.message)) {
        return true;
    }
    return (
        /^EXECABORT\b/.test(err.message) &&
        Array.isArray(err.previousErrors) &&
        err.previousErrors.length > 0 &&
        // An explicit callback: every() would hand in the index as the depth, so the seventh
        // failed command of a transaction read as past the depth limit, a permanent error
        err.previousErrors.every(previous => isTransientRedisError(previous, depth + 1))
    );
}

module.exports = { isTransientRedisError };
