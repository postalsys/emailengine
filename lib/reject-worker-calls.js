'use strict';

/**
 * Reject every pending cross-thread call routed to a worker thread that has
 * terminated. Without this, a call placed against a worker that then crashes or
 * is force-restarted keeps waiting until its own timeout fires - which can be
 * minutes (the submitMessage floor) or hours (a large X-EE-Timeout). Rejecting
 * here lets the caller fail fast with a retryable error the instant the worker
 * is known to be gone.
 *
 * The stored `reject` wrapper clears the entry's timeout, so we only need to
 * drop the entry from the queue and invoke it.
 *
 * @param {Map} callQueue - mid -> { resolve, reject, timer, worker }
 * @param {Worker} worker - The terminated worker thread
 * @param {Error} err - Rejection reason. May be a shared instance reused across
 *   concurrent rejections, so callers must not attach per-call fields to it.
 * @returns {number} Number of pending calls that were rejected
 */
function rejectWorkerCalls(callQueue, worker, err) {
    let rejected = 0;

    // Deleting the current entry while iterating a Map is safe in JS.
    for (let [mid, entry] of callQueue) {
        if (entry.worker !== worker) {
            continue;
        }

        callQueue.delete(mid);
        try {
            entry.reject(err);
        } catch (rejectErr) {
            // A consumer that throws synchronously from its rejection path must
            // not stop us from cleaning up the remaining pending calls.
        }
        rejected++;
    }

    return rejected;
}

module.exports = { rejectWorkerCalls };
