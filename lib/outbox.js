'use strict';

const { submitQueue, redis } = require('./db');
const { REDIS_PREFIX } = require('../lib/consts');

// Job removals are issued in bounded batches. ioredis writes each command as it is issued, so a
// batch costs one round trip rather than one per job, while the bound keeps an account with a huge
// outbox from putting an unlimited number of Lua scripts in flight at once.
const REMOVE_BATCH_SIZE = 100;

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

async function list(options) {
    options = options || {};
    let page = Number(options.page) || 0;
    let pageSize = Number(options.pageSize) || 20;
    let logger = options.logger;

    let jobCounts = await submitQueue.getJobCounts();

    let jobStates = ['delayed', 'paused', 'wait', 'active', 'failed'];

    let totalJobs = jobStates.map(state => Number(jobCounts[state]) || 0).reduce((previousValue, currentValue) => previousValue + currentValue);

    let jobIds = await submitQueue.getRanges(jobStates, page * pageSize, page * pageSize + pageSize - 1, true);

    let messages = [];

    for (let jobId of jobIds) {
        try {
            let job = await submitQueue.getJob(jobId);
            if (job) {
                messages.push(formatQueueEntry(job));
            }
        } catch (err) {
            logger.error({ msg: 'Failed to retrieve message info from outbox', jobId, err });
        }
    }

    return {
        total: totalJobs,
        page,
        pages: Math.ceil(totalJobs / pageSize),
        messages
    };
}

async function del(options) {
    options = options || {};

    let logger = options.logger;

    if (!options.queueId) {
        return false;
    }

    let job = await submitQueue.getJob(options.queueId);
    if (!job) {
        return false;
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
        logger.info({ msg: 'Remove queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId });
        return true;
    } catch (err) {
        logger.error({ msg: 'Failed to remove queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
    }

    return false;
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

    for (let i = 0; i < queueIds.length; i += REMOVE_BATCH_SIZE) {
        let batch = queueIds.slice(i, i + REMOVE_BATCH_SIZE);

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

module.exports = { list, del, get, removeJobs };
