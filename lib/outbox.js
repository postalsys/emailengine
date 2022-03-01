'use strict';

const { submitQueue } = require('./db');

async function list(options) {
    options = options || {};
    let page = Number(options.page) || 0;
    let pageSize = Number(options.pageSize) || 20;
    let logger = options.logger;

    let jobCounts = await submitQueue.getJobCounts();

    let jobStates = ['delayed', 'paused', 'wait', 'active'];

    let totalJobs = jobStates.map(state => Number(jobCounts[state]) || 0).reduce((previousValue, currentValue) => previousValue + currentValue);

    let jobIds = await submitQueue.getRanges(jobStates, page * pageSize, page * pageSize + pageSize - 1, true);

    let messages = [];

    for (let jobId of jobIds) {
        try {
            let job = await submitQueue.getJob(jobId);
            if (job) {
                let scheduled = job.timestamp + (Number(job.opts.delay) || 0);

                let backoffDelay = Number(job.opts.backoff && job.opts.backoff.delay) || 0;
                let nextAttempt = job.attemptsMade ? Math.round(job.processedOn + Math.pow(2, job.attemptsMade) * backoffDelay) : scheduled;

                if (job.opts.attempts <= job.attemptsMade) {
                    nextAttempt = false;
                }

                messages.push(
                    Object.assign(job.data, {
                        created: new Date(Number(job.created || job.timestamp)).toISOString(),
                        //status: job.name,
                        progress: job.progress,
                        attemptsMade: job.attemptsMade,
                        attempts: job.opts.attempts,
                        scheduled: new Date(scheduled).toISOString(),
                        nextAttempt: nextAttempt ? new Date(nextAttempt).toISOString() : false
                    })
                );
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

module.exports = { list };
