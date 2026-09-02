'use strict';

const { submitQueue, redis } = require('./db');
const { REDIS_PREFIX } = require('../lib/consts');

// Job reads and removals are issued in bounded batches. ioredis writes each command as it is
// issued, so a batch costs one round trip rather than one per job, while the bound keeps an account
// with a huge outbox from putting an unlimited number of Lua scripts in flight at once.
const BATCH_SIZE = 100;

// The states an outbox entry can be in, in the order they concatenate into the listing. 'waiting',
// not 'wait': getRanges() accepts either, but getJobCounts() keys its result only by 'waiting', so
// 'wait' read back undefined and left total/pages at 0. There is no 'paused' either - BullMQ 6
// dropped it as a job state and reports the jobs of a paused queue as waiting.
const JOB_STATES = ['delayed', 'waiting', 'active', 'failed'];

function outboxKey(account) {
    return `${REDIS_PREFIX}iaq:${account}`;
}

function formatQueueEntry(job) {
    let scheduled = job.timestamp + (Number(job.opts.delay) || 0);

    let backoffDelay = Number(job.opts.backoff && job.opts.backoff.delay) || 0;
    // attemptsMade already includes the failed attempt, so the retry delay is 2^(attemptsMade-1) * base
    let nextAttempt = job.attemptsMade ? Math.round(job.processedOn + Math.pow(2, job.attemptsMade - 1) * backoffDelay) : scheduled;

    if (job.opts.attempts <= job.attemptsMade) {
        nextAttempt = false;
    }

    return Object.assign(job.data, {
        created: new Date(Number(job.data.created || job.timestamp)).toISOString(),
        //status: job.name,
        progress: job.progress,
        attemptsMade: job.attemptsMade,
        attempts: job.opts.attempts,
        scheduled: new Date(scheduled).toISOString(),
        nextAttempt: nextAttempt ? new Date(nextAttempt).toISOString() : false
    });
}

/**
 * Maps a page of the outbox onto a sub-range of each job state.
 *
 * The outbox is the concatenation of the submit queue's per-state lists, in the order given, and
 * the job counts already say how long each one is - which is enough to work out how much of the
 * requested window falls in which state. Asking getRanges() for [start, end] across all the states
 * at once instead (what this used to do) applies that range to every state separately, so a page
 * came back holding up to pageSize entries PER state, and page 1 skipped the first pageSize entries
 * of each state rather than the first pageSize entries overall.
 *
 * @param {String[]} jobStates - Job states, in the order they concatenate into the outbox
 * @param {Object} jobCounts - Job count per state, as returned by Queue#getJobCounts()
 * @param {Number} start - Index of the first entry of the page, within the concatenated list
 * @param {Number} pageSize - How many entries the page holds at most
 * @returns {Object[]} `{ state, start, end }` ranges, inclusive, totalling at most pageSize entries
 */
function selectPageRanges(jobStates, jobCounts, start, pageSize) {
    let ranges = [];
    let remaining = pageSize;
    // How many entries the states already walked hold between them
    let precedingEntries = 0;

    for (let state of jobStates) {
        if (remaining <= 0) {
            break;
        }

        let stateLength = Number(jobCounts[state]) || 0;
        // Clamped to 0 once the page has started in an earlier state, in which case this one is
        // read from its first entry
        let from = Math.max(start - precedingEntries, 0);
        precedingEntries += stateLength;

        // Also covers a page that begins past the end of this state, where from >= stateLength
        let take = Math.min(stateLength - from, remaining);
        if (take > 0) {
            ranges.push({ state, start: from, end: from + take - 1 });
            remaining -= take;
        }
    }

    return ranges;
}

async function list(options) {
    options = options || {};
    let page = Number(options.page) || 0;
    let pageSize = Number(options.pageSize) || 20;
    let logger = options.logger;

    let jobCounts = await submitQueue.getJobCounts(...JOB_STATES);

    let totalJobs = JOB_STATES.map(state => Number(jobCounts[state]) || 0).reduce((previousValue, currentValue) => previousValue + currentValue);

    // The counts above and the ranges below are separate reads, so a job that changes state in
    // between can be listed twice or missed. That is inherent to paging a live queue without
    // locking it, and the next request reflects the queue as it then stands.
    let ranges = selectPageRanges(JOB_STATES, jobCounts, page * pageSize, pageSize);

    let idsPerRange = await Promise.all(ranges.map(range => submitQueue.getRanges([range.state], range.start, range.end, true)));
    let jobIds = idsPerRange.flat();

    // Queue#getJobs() is this same id-fetch-plus-getJob, but with an unbounded Promise.all and no
    // per-entry error handling: one unreadable job would reject the whole page. Batched here
    // instead, the same shape as removeJobs() below, because pageSize goes up to 1000.
    let messages = [];
    for (let i = 0; i < jobIds.length; i += BATCH_SIZE) {
        let batch = await Promise.all(
            jobIds.slice(i, i + BATCH_SIZE).map(async jobId => {
                try {
                    return await submitQueue.getJob(jobId);
                } catch (err) {
                    logger.error({ msg: 'Failed to retrieve message info from outbox', jobId, err });
                    return null;
                }
            })
        );

        for (let job of batch) {
            if (job) {
                messages.push(formatQueueEntry(job));
            }
        }
    }

    return {
        total: totalJobs,
        page,
        pages: Math.ceil(totalJobs / pageSize),
        messages
    };
}

// Resolves to { deleted } - with `locked: true` when the message could not be removed because a
// submit worker is delivering it right now. That is the one refusal a caller can act on (retry
// once the attempt is over), so it is reported rather than folded into a plain false; a failure to
// remove for any other reason is thrown.
async function del(options) {
    options = options || {};

    let logger = options.logger;

    if (!options.queueId) {
        return { deleted: false };
    }

    let job = await submitQueue.getJob(options.queueId);
    if (!job) {
        return { deleted: false };
    }

    // BullMQ refuses to remove a job a worker holds the lock on, and for the submit queue that is
    // a message in the middle of a delivery attempt. Checked before touching the content: the
    // attempt in flight still needs it, and removing it here would not stop the attempt anyway.
    if (await job.isActive()) {
        logger.info({
            msg: 'Queued message is being delivered, not removed',
            account: job.data.account,
            queueId: job.data.queueId,
            messageId: job.data.messageId
        });
        return { deleted: false, locked: true };
    }

    // Delete message content
    try {
        let res = await redis.hdel(outboxKey(job.data.account), job.data.queueId);
        logger.info({ msg: 'Removed queued message', res, account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId });
    } catch (err) {
        logger.error({ msg: 'Failed to remove queued message', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
    }

    // Delete job entry
    try {
        await job.remove();
    } catch (err) {
        logger.error({ msg: 'Failed to remove queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
        throw err;
    }

    logger.info({ msg: 'Removed queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId });
    return { deleted: true };
}

async function get(options) {
    options = options || {};

    let logger = options.logger;

    if (!options.queueId) {
        return false;
    }

    let job = await submitQueue.getJob(options.queueId);
    if (!job) {
        return false;
    }

    try {
        let queueEntryBuf = await redis.hgetBuffer(outboxKey(job.data.account), job.data.queueId);
        if (!queueEntryBuf) {
            return false;
        }
    } catch (err) {
        logger.error({ msg: 'Failed to retrieve queued message', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
        throw err;
    }

    return formatQueueEntry(job);
}

/**
 * Removes the submit queue jobs of messages that were queued for an account that no longer exists.
 *
 * Deleting an account removes the message content, but the queue job pointing at it is a separate
 * structure that the deletion does not touch, and its job data still carries the envelope, the
 * subject and the message ID. A job that is merely waiting cleans itself up the moment it runs,
 * because the worker finds no content and returns, but a *delayed* job does not run until its
 * `sendAt`, which the API caller chooses and which can be arbitrarily far in the future. Without
 * this, a message scheduled for next year would keep its recipient addresses and subject line in
 * Redis for that long after the account was erased.
 *
 * The `notify` queue is deliberately not handled the same way. Webhook entries for a deleted
 * account are never delivered, as the notify worker checks that the account still exists before
 * doing anything, and the entries that do not clean themselves up - deliveries that already failed
 * permanently - are bounded by EENGINE_QUEUE_KEEP_FAILED_AGE. They are inert and self-expiring,
 * whereas finding them would mean matching on job payloads that BullMQ reads inside a blocking Lua
 * script. Submit jobs that already reached the failed set are bounded the same way, and are left
 * alone for the same reason.
 *
 * @param {String[]} queueIds - Queue IDs, which are also the submit queue job IDs
 * @param {Object} options - Options
 * @param {String} options.account - Account ID, for logging
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Number>} Number of jobs removed. A job a worker holds the lock on is left
 *   behind, which is harmless: the worker finds no content for it and completes without sending.
 */
async function removeJobs(queueIds, options) {
    const { account, logger } = options;

    let removed = 0;

    for (let i = 0; i < queueIds.length; i += BATCH_SIZE) {
        let batch = queueIds.slice(i, i + BATCH_SIZE);

        let results = await Promise.all(
            batch.map(async queueId => {
                try {
                    // Removes by ID without loading the job payload, and returns 0 instead of
                    // throwing when a worker holds the job lock. Submit jobs are never flow nodes,
                    // so skipping the child lookups saves five Redis calls per job.
                    return await submitQueue.remove(queueId, { removeChildren: false });
                } catch (err) {
                    logger.error({ msg: 'Failed to remove queued message job', account, queueId, err });
                    return 0;
                }
            })
        );

        removed += results.filter(code => code === 1).length;
    }

    return removed;
}

// selectPageRanges is exported for its own tests: it is the pagination arithmetic, and exercising it
// through list() alone would need a queue populated across all four states to cover the cases.
// selectPageRanges and JOB_STATES are exported for the pagination tests: exercising the arithmetic
// through list() alone would need a queue populated across all four states to cover the cases.
module.exports = { list, del, get, removeJobs, selectPageRanges, JOB_STATES };
