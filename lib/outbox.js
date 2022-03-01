'use strict';

const { date } = require('joi');
const { submitQueue } = require('./db');

async function list(options) {
    options = options || {};
    let page = Number(options.page) || 0;
    let pageSize = Number(options.pageSize) || 20;
    let account = options.account;
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
                console.log(JSON.stringify(job, false, 2));

                let scheduled = job.timestamp + (Number(job.opts.delay) || 0);

                let backoffDelay = Number(job.opts.backoff && job.opts.backoff.delay) || 0;
                let nextAttempt = job.attemptsMade ? Math.round(job.processedOn + Math.pow(2, job.attemptsMade) * backoffDelay) : scheduled;

                messages.push(
                    Object.assign(job.data, {
                        created: new Date(Number(job.created || job.timestamp)).toISOString(),
                        status: job.name,
                        progress: job.progress,
                        attemptsMade: job.attemptsMade,
                        scheduled: new Date(scheduled).toISOString(),
                        nextAttempt: new Date(nextAttempt).toISOString()
                    })
                );
            }
        } catch (err) {
            logger.error({ msg: 'Failed to retrieve message info from outbox', account, jobId, err });
        }
    }

    let data = {
        total: totalJobs,
        page,
        pages: Math.ceil(totalJobs / pageSize),
        messages
    };

    console.log(JSON.stringify(data, false, 2));
}

list({});
