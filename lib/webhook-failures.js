'use strict';

// The webhook deliveries that failed for good, for the REST API: list them, put one back into the
// queue, or remove it. The admin queue browser (lib/queue-browser) offers the same over the whole
// notify queue; this is the failed set only, in the shape an integrator replaying the events a
// receiver outage cost it needs, and optionally held to one account so a token bound to that
// account reaches only its own deliveries.
//
// A listing carries what a delivery was about (event, account, folder, message, the route that
// sent it and why it failed), never the event payload itself, which can hold up to notifyTextSize
// of message text.

const { notifyQueue } = require('./db');
const { QUEUES_BY_NAME, listJobs } = require('./queue-browser');
const { retryFailedJob, assertJobState } = require('./queue-job-actions');
const { statusError } = require('./utils/status-error');

const NOTIFY_QUEUE = QUEUES_BY_NAME.get('notify');

/**
 * The API form of a failed delivery, from the queue browser's formatted entry
 * @param {Object} entry - Entry from listJobs()
 * @returns {Object}
 */
function formatFailedDelivery(entry) {
    return {
        id: entry.id,
        event: entry.event,
        eventId: entry.eventId,
        account: entry.account,
        path: entry.path,
        messageId: entry.messageId,
        route: entry.routeId ? { id: entry.routeId, name: entry.routeName || null } : null,
        created: entry.created,
        failed: entry.finishedOn,
        attemptsMade: entry.attemptsMade,
        attempts: entry.attempts,
        error: entry.failure
            ? {
                  message: entry.failure.reason,
                  code: entry.failure.code,
                  statusCode: entry.failure.statusCode,
                  permanent: entry.failure.permanent
              }
            : null
    };
}

/**
 * One page of failed deliveries, most recent first. With an account the failed set is scanned from
 * its head for that account's deliveries, as far as the queue browser scans a filtered listing, and
 * the result says when the scan stopped short of the end.
 *
 * @param {Object} options
 * @param {string} [options.account] - Only deliveries of this account
 * @param {number} [options.page] - Zero-based page
 * @param {number} [options.pageSize] - Entries per page
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} `{ total, page, pages, scanLimited, deliveries }`
 */
async function list(options) {
    const result = await listJobs({
        queue: NOTIFY_QUEUE,
        state: 'failed',
        page: options.page,
        pageSize: options.pageSize,
        account: options.account,
        logger: options.logger
    });

    return {
        total: result.total,
        page: result.page,
        pages: result.total ? result.pages : 0,
        scanLimited: result.scanLimited,
        deliveries: result.entries.map(formatFailedDelivery)
    };
}

/**
 * The job of a failed delivery, or null when there is none, or when `account` is given and the
 * delivery belongs to another account
 * @param {string} id - Job ID
 * @param {string} [account] - Account the delivery has to belong to
 * @returns {Promise<Object|null>} BullMQ job
 */
async function getOwnJob(id, account) {
    const job = id ? await notifyQueue.getJob(id) : null;
    if (!job || (account && (!job.data || job.data.account !== account))) {
        return null;
    }
    return job;
}

/**
 * Puts a failed delivery back into the queue with a fresh set of attempts.
 *
 * @param {Object} options
 * @param {string} options.id - Job ID
 * @param {string} [options.account] - Account the delivery has to belong to
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|false>} `{ retried: true, id }`, or false when there is no such delivery
 * @throws {Error} 409 NotFailed when the delivery is not in the failed state
 */
async function retry(options) {
    const job = await getOwnJob(options.id, options.account);
    if (!job) {
        return false;
    }

    await assertJobState(job, 'failed', NOTIFY_QUEUE.noun, 'retried');
    await retryFailedJob(job, NOTIFY_QUEUE.noun);

    options.logger.info({ msg: 'Retrying failed webhook delivery', job: job.id, event: job.name, account: job.data && job.data.account });
    return { retried: true, id: String(job.id) };
}

/**
 * Removes a failed delivery from the queue.
 *
 * @param {Object} options
 * @param {string} options.id - Job ID
 * @param {string} [options.account] - Account the delivery has to belong to
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|false>} `{ deleted: true, id }`, or false when there is no such delivery
 * @throws {Error} 409 NotFailed when the delivery is not in the failed state
 */
async function del(options) {
    const job = await getOwnJob(options.id, options.account);
    if (!job) {
        return false;
    }

    await assertJobState(job, 'failed', NOTIFY_QUEUE.noun, 'removed');

    try {
        await job.remove();
    } catch (err) {
        // retried and picked up by a worker between the check and the removal
        throw statusError('The webhook delivery is being processed and cannot be removed', 'Locked', 409);
    }

    options.logger.info({ msg: 'Removed failed webhook delivery', job: job.id, event: job.name, account: job.data && job.data.account });
    return { deleted: true, id: String(job.id) };
}

module.exports = { list, retry, del, formatFailedDelivery };
