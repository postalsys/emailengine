'use strict';

// ioredis calls `reconnectOnError` for every error REPLY, not for connection errors: a refused
// write under `maxmemory` (OOM), a WRONGTYPE, a NOSCRIPT before the script is loaded again, and an
// error raised by a BullMQ Lua script all pass through it. Answering true to all of them dropped the
// connection on each one, and the IMAP worker exits on every Redis reconnect (workers/imap.js), so a
// full Redis turned into a loop of worker restarts and account resyncs, each writing more to a
// database that was already refusing writes.
//
// The only reply a reconnect fixes is READONLY: the client is still connected to a node that was
// demoted in a failover, and reconnecting reaches the new primary. Returning 2 makes ioredis resend
// the command once it has.

const RESEND_AFTER_RECONNECT = 2;

/**
 * Decides whether an error reply means the connection should be re-established
 * @param {Error} err - The error reply ioredis received
 * @returns {number|boolean} 2 to reconnect and resend the command, false to just reject it
 */
function reconnectOnErrorReply(err) {
    let message = (err && typeof err.message === 'string' && err.message) || '';
    if (/^READONLY\b/.test(message)) {
        return RESEND_AFTER_RECONNECT;
    }
    return false;
}

module.exports = { reconnectOnErrorReply, RESEND_AFTER_RECONNECT };
