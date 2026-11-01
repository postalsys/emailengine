'use strict';

// Sends a queued message under a lock, so a retry never runs next to a send that is still in
// progress. The submit worker retries when its call fails, and a call can fail while the send goes
// on: a timeout, or a call forwarded to another instance whose connection was cut. Before the lock,
// a retry five seconds later started a second SMTP transaction for the same message.

const { runLocked } = require('./lock-run');
const { statusError } = require('./utils/status-error');
const { REDIS_PREFIX } = require('./consts');

// How long the lock lives without being extended. It is extended while the send runs, so this
// only has to outlast a stalled process
const SUBMIT_LOCK_TTL = 60 * 1000;

// How long a sent message is remembered: longer than a queued message can be retried for
const SENT_MARKER_TTL = 7 * 24 * 3600;

const sentKey = (account, queueId) => `${REDIS_PREFIX}submit:sent:${account}:${queueId}`;

/**
 * @param {Object} opts
 * @param {Object} opts.lock - ioredfour Lock (getSharedLock())
 * @param {Object} opts.redis - ioredis client
 * @param {string} opts.account
 * @param {Object} opts.data - The queued submission (queueId)
 * @param {Function} opts.send - () => the send itself
 * @returns {Promise<*>} What send resolves with
 */
async function sendQueuedOnce({ lock, redis, account, data, send }) {
    if (!data || !data.queueId) {
        return await send();
    }
    return await runLocked(
        lock,
        `submit:${account}:${data.queueId}`,
        { ttl: SUBMIT_LOCK_TTL, wait: false, extend: true },
        async () => {
            // The attempt that held the lock before may have sent it. Its own record, not the job
            // progress: a retry writes 'processing' over that before it gets here
            if (await redis.exists(sentKey(account, data.queueId))) {
                // The submit worker counts the job as sent
                throw statusError('An earlier attempt already sent this message', 'AlreadySent', 409);
            }
            const result = await send();
            // A send that resolved went out: the email clients swallow failures after the accept
            await redis.set(sentKey(account, data.queueId), '1', 'EX', SENT_MARKER_TTL);
            return result;
        },
        err => {
            // Retried by the queue like any transient failure
            const busy = statusError('An earlier attempt is still sending this message', 'SubmitInProgress', 409);
            busy.cause = err;
            throw busy;
        }
    );
}

module.exports = { sendQueuedOnce, SUBMIT_LOCK_TTL, sentKey };
