'use strict';

// The submit queue's job processor, moved out of workers/submit.js so a test can run the real thing
// against real BullMQ jobs: the worker cannot be loaded from a test (it starts consuming on
// require), and what has to be pinned here is the order of events around a crash, which only the
// real processor and a real queue show.
//
// What this does NOT do is forget that a message was sent. The marker sendQueuedOnce() writes
// (lib/submit-lock.js) is the only record that a retry must not send again, and it is needed until
// BullMQ has recorded the job as completed: a worker that dies after the send and before that
// record leaves a job that runs again. Clearing it here, before the processor returned, let that
// run send the message a second time. completeSubmission() clears it from the worker's
// 'completed' event, which BullMQ emits only once the completion is stored; a job that never
// completes keeps its marker until the marker expires.

const { UnrecoverableError } = require('bullmq');
const { delayWhilePenalised } = require('./queue-job-actions');
const { submitPenaltyKey } = require('./submit-penalty');

const { decodeQueueEntry, outboxKey } = require('./outbox');
const { shouldDiscardJob, willBeFinalAttempt, nextAttemptWhileProcessing } = require('./delivery-error');
const { isAlreadySent } = require('./submit-progress');
const { clearSent } = require('./submit-lock');

/**
 * Jobs queued by old versions carry the queue entry id as `qId`
 * @param {Object} job - BullMQ job, its data updated in place
 */
function normalizeQueueId(job) {
    if (!job.data.queueId && job.data.qId) {
        job.data.queueId = job.data.qId;
    }
}

/**
 * Builds the submit queue processor
 * @param {Object} deps
 * @param {Object} deps.redis - ioredis client
 * @param {Object} deps.logger
 * @param {Object} deps.submitQueue - the BullMQ queue the jobs belong to, read back for a job's stored progress
 * @param {Function} deps.getAccount - async (accountId) => object with submitMessage(queueEntry)
 * @returns {Function} async (job, token) => processes one queued message
 */
function createSubmitProcessor({ redis, logger, submitQueue, getAccount }) {
    return async (job, token) => {
        normalizeQueueId(job);

        // A job re-run after a stall (heartbeat kill, crash, a shutdown drain that could not cover
        // a long SMTP transaction plus the Sent-folder upload) comes back with the progress its
        // previous run stored. Once that says the MTA accepted the message, sending again would
        // deliver a duplicate under the same queueId: the message is done, only the bookkeeping
        // after the 250 was cut short. The catch below covers the same state for a run that got
        // as far as throwing; this covers the run that never got to throw anything.
        if (isAlreadySent(job.progress)) {
            logger.info({
                msg: 'Skipping re-run of an already sent message',
                action: 'submit',
                queue: job.queue.name,
                code: 'result_success',
                job: job.id,
                event: job.name,
                account: job.data.account,
                queueId: job.data.queueId,
                messageId: job.data.messageId,
                progress: job.progress.status,
                attemptsMade: job.attemptsMade
            });
            return;
        }

        let queueEntryBuf = await redis.hgetBuffer(outboxKey(job.data.account), job.data.queueId);
        if (!queueEntryBuf) {
            // nothing to do here
            try {
                await redis.hdel(outboxKey(job.data.account), job.data.queueId);
            } catch (err) {
                // ignore
            }
            return;
        }

        let queueEntry;
        try {
            // Rejects a value that decodes to something other than a map as well, otherwise the
            // job metadata assignment below throws a TypeError against it and the entry is retried
            // as a failed delivery instead of being dropped as the corrupt entry it is
            queueEntry = decodeQueueEntry(queueEntryBuf);
        } catch (err) {
            logger.error({ msg: 'Failed to parse queued email entry', job: job.id, account: job.data.account, queueId: job.data.queueId, err });
            try {
                await redis.hdel(outboxKey(job.data.account), job.data.queueId);
            } catch (err) {
                // ignore
            }
            return;
        }

        // An account whose last delivery ran into the deadline waits, so its server does not hold
        // the queue every other account shares; see lib/submit-penalty.js
        await delayWhilePenalised(job, token, redis, submitPenaltyKey(job.data.account), delay =>
            logger.info({ msg: 'Account is penalised for a stalled delivery, delaying message', account: job.data.account, job: job.id, delay })
        );

        let accountObject = await getAccount(job.data.account);

        logger.trace({
            msg: 'Processing message',
            action: 'submit',
            queue: job.queue.name,
            code: 'processing',
            job: job.id,
            event: job.name,
            data: job.data,
            account: job.data.account
        });

        try {
            try {
                // try to update
                await job.updateProgress({
                    status: 'processing'
                });
            } catch (err) {
                // ignore
            }

            let nextAttempt = nextAttemptWhileProcessing(job);

            queueEntry.job = {
                id: job.id,
                attemptsMade: job.attemptsMade,
                attempts: job.opts.attempts,
                nextAttempt: nextAttempt ? new Date(nextAttempt).toISOString() : false
            };

            let res = await accountObject.submitMessage(queueEntry);

            logger.trace({
                msg: 'Submitted queued message for delivery',
                action: 'submit',
                queue: job.queue.name,
                code: 'result_success',
                job: job.id,
                event: job.name,
                data: job.data,
                account: job.data.account
            });

            try {
                // try to update
                await job.updateProgress({
                    status: 'submitted',
                    response: res.response
                });
            } catch (err) {
                // ignore
            }
        } catch (err) {
            // The message went out even though this run failed: an earlier attempt sent it and its
            // call failed after the fact (AlreadySent, lib/submit-lock.js), or this run failed after
            // the accept
            let alreadySent = err.code === 'AlreadySent';
            if (!alreadySent) {
                try {
                    const submitJobEntry = await submitQueue.getJob(job.id);
                    alreadySent = !!submitJobEntry && isAlreadySent(submitJobEntry.progress);
                } catch (err) {
                    logger.error({
                        msg: 'Failed to fetch job status',
                        job: job.id,
                        account: job.data.account,
                        err
                    });
                }
            }
            if (alreadySent) {
                logger.info({
                    msg: 'Message was already sent, counting the job as sent',
                    action: 'submit',
                    queue: job.queue.name,
                    code: 'result_success',
                    job: job.id,
                    event: job.name,
                    account: job.data.account,
                    queueId: job.data.queueId,
                    err
                });
                try {
                    // The retry wrote 'processing' over the sent state
                    await job.updateProgress({ status: 'submitted' });
                } catch (err) {
                    // ignore
                }
                return;
            }

            const discardJob = shouldDiscardJob(err, job);
            const isFinalAttempt = discardJob || willBeFinalAttempt(job);

            logger[isFinalAttempt ? 'error' : 'warn']({
                msg: 'Message submission failed',
                action: 'submit',
                queue: job.queue.name,
                code: 'result_fail',
                job: job.id,
                event: job.name,
                data: job.data,
                account: job.data.account,
                err
            });

            try {
                // try to update
                await job.updateProgress({
                    status: 'error',
                    error: {
                        message: err.message,
                        code: err.code,
                        statusCode: err.statusCode,
                        // the SMTP reply code, when there was a reply: what decides whether the
                        // failure is permanent (lib/delivery-error.js), kept so the queue browser
                        // can say so without a rule of its own
                        responseCode: err.responseCode
                    },
                    networkRouting: err.info?.networkRouting
                });
            } catch (err) {
                // ignore
            }

            if (discardJob) {
                // Do not retry after a permanent rejection (5xx except 503, which is transient).
                // BullMQ 6 removed Job#discard(), so the way to end a job before its attempts are
                // spent is to throw UnrecoverableError. The stack is carried over because the
                // 'failed' handler reports job.stacktrace[0] as the error in the failure webhook -
                // constructing a bare UnrecoverableError would replace the SMTP reason with
                // "UnrecoverableError" there.
                let unrecoverableErr = new UnrecoverableError(err.message);
                unrecoverableErr.stack = err.stack;
                unrecoverableErr.code = err.code;
                unrecoverableErr.responseCode = err.responseCode;
                unrecoverableErr.statusCode = err.statusCode;

                logger.info({
                    msg: 'Job discarded',
                    job: job.id,
                    account: queueEntry.account,
                    queueId: job.data.queueId,
                    messageId: job.data.messageId,
                    errorCode: err.code,
                    responseCode: err.responseCode
                });

                throw unrecoverableErr;
            }

            throw err;
        }
    };
}

/**
 * The bookkeeping of a job BullMQ has recorded as completed: the stored message content and the
 * sent marker both go. Called from the worker's 'completed' event, never from the processor
 * @param {Object} job - the completed BullMQ job
 * @param {Object} deps
 * @param {Object} deps.redis - ioredis client
 * @param {Object} deps.logger
 */
async function completeSubmission(job, { redis, logger }) {
    normalizeQueueId(job);

    if (!job.data.account || !job.data.queueId) {
        return;
    }

    // Independent writes, sent together: a failure of one must not keep the other from running
    const { account, queueId } = job.data;
    await Promise.all([
        redis.hdel(outboxKey(account), queueId).catch(err => {
            logger.error({ msg: 'Failed to remove queue entry', account, queueId, messageId: job.data.messageId, err });
        }),
        // A marker that could not be cleared expires on its own, and until then it only stops a job
        // that is already done from running again
        clearSent(redis, account, queueId).catch(err => {
            logger.warn({ msg: 'Failed to clear the sent marker of a completed message', job: job.id, account, err });
        })
    ]);
}

module.exports = { createSubmitProcessor, completeSubmission, normalizeQueueId };
