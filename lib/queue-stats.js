'use strict';

/**
 * Job counts for the BullMQ queues, read through BullMQ's own API.
 *
 * Both the /v1/stats payload and the GET /v1/settings/queue/{queue} route used to count queues by
 * issuing raw llen/zcard/hget against BullMQ's internal key layout (`bull:<queue>:active`, `:wait`,
 * `:delayed`, `:meta`). That layout is private and it moved under us in the 5.x -> 6.x bump, which
 * removed the `<queue>:paused` list - and because `llen` on a missing key returns 0 rather than an
 * error, both surfaces would have gone on silently reporting zeroes instead of failing. The public
 * getter also subtracts the deprecated `0:` wait-list marker that a queue carried over from a 5.x
 * install still holds, which a raw `llen` counts as if it were a job.
 */

// Counted states, chosen to match the two payloads this backs rather than BullMQ's full set:
// completed and failed jobs are retained separately (see EENGINE_QUEUE_KEEP_FAILED) and are not
// pending work. `prioritized` is not counted either - nothing in EmailEngine queues with a
// priority, and adding it would add a key to two published payloads.
const COUNTED_STATES = ['active', 'delayed', 'waiting'];

/**
 * Counts the pending jobs of a queue and reports whether the queue is paused.
 *
 * @param {Object} queueObj - BullMQ Queue instance
 * @returns {Promise<Object>} `active`, `delayed` and `waiting` counts plus their `total`, the
 *   `isPaused` flag, and a `paused` count that is always 0 - BullMQ 6 no longer parks jobs in a
 *   separate paused list, so a paused queue holds them in `waiting` and they are counted there.
 *   The key is kept because it is part of both published payloads.
 */
async function queueStats(queueObj) {
    const [counts, isPaused] = await Promise.all([queueObj.getJobCounts(...COUNTED_STATES), queueObj.isPaused()]);

    const stats = {
        paused: 0,
        isPaused: !!isPaused
    };

    let total = 0;
    for (const state of COUNTED_STATES) {
        const count = Number(counts[state]) || 0;
        stats[state] = count;
        total += count;
    }
    stats.total = total;

    return stats;
}

module.exports = { queueStats, COUNTED_STATES };
