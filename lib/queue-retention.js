'use strict';

// Retention policies for BullMQ job entries.
//
// This module is deliberately dependency-free (no Redis, no settings, no environment) so it can be unit tested
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
//
// Both are settings (queueKeepFailedAge, queueKeepFailed) and environment variables, which
// lib/env-setting-overrides.js resolves, the environment winning; the values below are only the
// defaults. Every caller passes the resolved bounds in, so there is one parser for the variables.
const FAILED_JOB_RETENTION_AGE_DEFAULT = 7 * 24 * 3600;
const FAILED_JOB_RETENTION_COUNT_DEFAULT = 500;

/**
 * @param {{age: number, count: number}} failedRetention
 * @returns {{age: number, count: number}} The same bounds, checked
 */
function requireFailedRetention(failedRetention) {
    const age = Number(failedRetention?.age);
    const count = Number(failedRetention?.count);
    if (!(age > 0) || !(count > 0)) {
        // the bounds come from getFailedJobRetention(); a default here would ignore the setting
        throw new TypeError('The failed-job retention bounds are required, see getFailedJobRetention()');
    }
    return { age, count };
}

/**
 * Builds the `removeOnComplete` / `removeOnFail` pair for a queue job.
 *
 * A job reaches the failed set only after every retry is exhausted, which for a webhook means the
 * event is gone. `queueKeep` defaults to 0, so applying it to failures too (the previous behavior)
 * deleted that record the moment it was written and left nothing but a log line behind. Failures
 * therefore get their own floor: at least `failedRetention.count` entries for `failedRetention.age`
 * seconds, regardless of how few completed entries are wanted.
 *
 * BullMQ reads these values as "when to remove", not "how much to keep": `true` removes the entry
 * immediately, `false` keeps it forever, a number keeps the last N, and `{age, count}` keeps
 * entries younger than `age` up to `count` of them.
 *
 * @param {boolean|number} queueKeep - The `queueKeep` setting: entries to retain, or a boolean
 * @param {{age: number, count: number}} failedRetention - The failed-job bounds in effect (age in
 *     seconds), as getFailedJobRetention() resolves them
 * @returns {{removeOnComplete: boolean|Object, removeOnFail: boolean|Object}} BullMQ job options
 */
function buildRetentionPolicy(queueKeep, failedRetention) {
    const { age: failedAge, count: failedCount } = requireFailedRetention(failedRetention);

    const removeOnComplete = typeof queueKeep === 'number' ? { age: COMPLETED_JOB_RETENTION_AGE, count: queueKeep } : queueKeep;

    // Always bounded, and widened when the operator asked to keep more entries than the floor
    const removeOnFail = {
        age: failedAge,
        count: typeof queueKeep === 'number' ? Math.max(queueKeep, failedCount) : failedCount
    };

    return { removeOnComplete, removeOnFail };
}

// The raw content of a message whose delivery failed for good is kept so the message can be
// retried from the queue browser or through POST /v1/outbox/{queueId}/retry. The job's own
// retention (above) only bounds the job record, which is a few hundred bytes of metadata; the
// content it points at is the whole message, up to EENGINE_MAX_SMTP_MESSAGE_SIZE, so it gets a
// bound of its own on both the count and the total size. Both defaults are deliberately well
// below the failed-job bounds: the record of a failure should outlive the ability to retry it.
const DEFAULT_FAILED_CONTENT_RETENTION_COUNT = 100;
const DEFAULT_FAILED_CONTENT_RETENTION_SIZE = 100 * 1024 * 1024;

/**
 * Picks the retained failed-message contents that have to go to stay within the limits.
 *
 * Pure, so the three bounds can be tested without Redis. Entries are considered newest first:
 * the most recent failures are the ones an operator is looking at, so when something has to be
 * dropped it is the oldest. An entry is dropped when it is older than `maxAge`, when it is past
 * the `maxCount` newest, or when the sizes of it and every newer entry add up to more than
 * `maxBytes`. A single message larger than `maxBytes` on its own is therefore never retained,
 * which is the point of a size bound.
 *
 * @param {Array<{account: string, queueId: string, size: number, finishedOn: number}>} entries - Retained contents, any order
 * @param {Object} limits - Bounds to apply
 * @param {number} limits.maxCount - How many contents to keep at most
 * @param {number} limits.maxBytes - Total size of the kept contents, in bytes
 * @param {number} limits.maxAge - How long a content is kept after the failure, in seconds
 * @param {number} [limits.now] - The current time, for tests (defaults to Date.now())
 * @returns {Array<Object>} The entries to drop, oldest first
 */
function selectFailedContentToDrop(entries, limits) {
    const now = limits.now || Date.now();
    const cutoff = now - limits.maxAge * 1000;

    const newestFirst = entries.slice().sort((a, b) => b.finishedOn - a.finishedOn);

    const drop = [];
    let kept = 0;
    let keptBytes = 0;
    for (const entry of newestFirst) {
        const size = Number(entry.size) || 0;
        if (entry.finishedOn < cutoff || kept >= limits.maxCount || keptBytes + size > limits.maxBytes) {
            drop.push(entry);
            continue;
        }
        kept++;
        keptBytes += size;
    }

    return drop.reverse();
}

/**
 * Ages for the periodic queue clean in server.js, in milliseconds as BullMQ's clean() takes them
 * (the retention ages above are seconds, as removeOnComplete/removeOnFail take them). The clean used
 * hardcoded 24 hours and 7 days, so a longer failed-job retention kept failed jobs no longer than a
 * week anyway
 * @param {{age: number, count: number}} failedRetention - As getFailedJobRetention() resolves it
 * @returns {{ completed: number, failed: number }}
 */
function queueCleanAges(failedRetention) {
    return {
        completed: COMPLETED_JOB_RETENTION_AGE * 1000,
        failed: requireFailedRetention(failedRetention).age * 1000
    };
}

module.exports = {
    buildRetentionPolicy,
    queueCleanAges,
    selectFailedContentToDrop,
    COMPLETED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_AGE_DEFAULT,
    FAILED_JOB_RETENTION_COUNT_DEFAULT,
    DEFAULT_FAILED_CONTENT_RETENTION_COUNT,
    DEFAULT_FAILED_CONTENT_RETENTION_SIZE
};
