'use strict';

// Retention policies for BullMQ job entries.
//
// This module is deliberately dependency-free (no Redis, no settings) so it can be unit tested
// directly. Four call sites used to build these policies inline from the `queueKeep` setting and
// had already drifted apart: three read the setting with `?? true` and one with `|| true`, which
// silently turned an explicit `queueKeep = 0` into "keep everything".

// How long a completed entry is kept when the operator asked for a bounded count. Completed jobs
// are purely for debugging, so a day is plenty.
const COMPLETED_JOB_RETENTION_AGE = 24 * 3600;

// Failed entries are the only record that a delivery was given up on, so they outlive completed
// ones. Bounded on both axes because webhook payloads can carry up to `notifyTextSize` (2MB by
// default) of message text and an endpoint that is down fails every event it is sent.
// Both are overridable because the right bound depends on payload size: a `messageNew` webhook
// carries up to `notifyTextSize` (2MB by default) of message text, and a receiver that is down
// turns every event into a retained entry.
const FAILED_JOB_RETENTION_AGE = Number(process.env.EENGINE_QUEUE_KEEP_FAILED_AGE) || 7 * 24 * 3600;
const FAILED_JOB_RETENTION_COUNT = Number(process.env.EENGINE_QUEUE_KEEP_FAILED) || 500;

/**
 * Builds the `removeOnComplete` / `removeOnFail` pair for a queue job.
 *
 * A job reaches the failed set only after every retry is exhausted, which for a webhook means the
 * event is gone. `queueKeep` defaults to 0, so applying it to failures too (the previous behavior)
 * deleted that record the moment it was written and left nothing but a log line behind. Failures
 * therefore get their own floor: at least `FAILED_JOB_RETENTION_COUNT` entries for
 * `FAILED_JOB_RETENTION_AGE` seconds, regardless of how few completed entries are wanted.
 *
 * BullMQ reads these values as "when to remove", not "how much to keep": `true` removes the entry
 * immediately, `false` keeps it forever, a number keeps the last N, and `{age, count}` keeps
 * entries younger than `age` up to `count` of them.
 *
 * @param {boolean|number} queueKeep - The `queueKeep` setting: entries to retain, or a boolean
 * @returns {{removeOnComplete: boolean|Object, removeOnFail: boolean|Object}} BullMQ job options
 */
function buildRetentionPolicy(queueKeep) {
    const removeOnComplete = typeof queueKeep === 'number' ? { age: COMPLETED_JOB_RETENTION_AGE, count: queueKeep } : queueKeep;

    // Always bounded, and widened when the operator asked to keep more entries than the floor
    const removeOnFail = {
        age: FAILED_JOB_RETENTION_AGE,
        count: typeof queueKeep === 'number' ? Math.max(queueKeep, FAILED_JOB_RETENTION_COUNT) : FAILED_JOB_RETENTION_COUNT
    };

    return { removeOnComplete, removeOnFail };
}

module.exports = {
    buildRetentionPolicy,
    COMPLETED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_COUNT
};
