'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');

const { getDuration, readEnvValue, threadStats } = require('../lib/tools');
const { webhooks: Webhooks } = require('../lib/webhooks');
const settings = require('../lib/settings');

const { initSentry } = require('../lib/sentry');
initSentry('submit');

const util = require('util');
const { redis, queueConf, submitQueue, logBullErrors } = require('../lib/db');
const { Worker } = require('bullmq');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { retainFailedContent } = require('../lib/outbox');

const { EMAIL_FAILED_NOTIFY } = require('../lib/consts');

config.smtp = config.smtp || {
    port: 2525,
    host: '127.0.0.1'
};

config.queues = config.queues || {
    submit: 1
};

config.service = config.service || {};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const SUBMIT_QC = (readEnvValue('EENGINE_SUBMIT_QC') && Number(readEnvValue('EENGINE_SUBMIT_QC'))) || config.queues.submit || 1;

const SUBMIT_DELAY = getDuration(readEnvValue('EENGINE_SUBMIT_DELAY') || config.submitDelay) || null;

const { isFinalFailedAttempt } = require('../lib/delivery-error');
const { createSubmitProcessor, completeSubmission, normalizeQueueId } = require('../lib/submit-processor');

const { createRpcClient, respond, isCall } = require('../lib/worker-rpc');
const rpc = createRpcClient({ port: parentPort, defaultTimeout: EENGINE_TIMEOUT, timeoutTag: 'T5' });
const call = rpc.call;

async function metrics(logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

async function notify(account, event, data) {
    metrics(logger, 'events', 'inc', {
        event
    });

    let serviceUrl = (await settings.get('serviceUrl')) || null;

    let payload = {
        serviceUrl,
        account,
        date: new Date().toISOString()
    };

    if (event) {
        payload.event = event;
    }

    if (data) {
        payload.data = data;
    }

    await Webhooks.enqueue(event, payload);
}

const smtpLogger = {};
for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
    smtpLogger[level] = (data, message, ...args) => {
        if (args && args.length) {
            message = util.format(message, ...args);
        }
        data.msg = message;
        data.sub = 'smtp-server';
        if (typeof logger[level] === 'function') {
            logger[level](data);
        } else {
            logger.debug(data);
        }
    };
}

const submitWorker = new Worker(
    'submit',
    createSubmitProcessor({
        redis,
        logger,
        submitQueue,
        getAccount: async account => new Account({ account, redis, call, secret: await getSecret() })
    }),
    Object.assign(
        {
            concurrency: SUBMIT_QC,

            // Lock duration must exceed SMTP socket timeout (2 min) to prevent
            // jobs from being marked stalled during normal email delivery
            lockDuration: 3 * 60 * 1000, // 3 minutes

            // Check for stalled jobs every 60 seconds
            stalledInterval: 60 * 1000,

            // Allow jobs to recover from stalled state up to 3 times before failing
            // This handles transient Redis latency or connection issues
            maxStalledCount: 3,

            limiter: SUBMIT_DELAY
                ? {
                      max: 1,
                      duration: SUBMIT_DELAY
                  }
                : null
        },
        queueConf
    )
);

logBullErrors(submitWorker, 'worker:submit');

submitWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'submit',
        status: 'completed'
    });

    // BullMQ emits this only once the completion is stored, which is what lets the sent marker go
    await completeSubmission(job, { redis, logger });

    logger.info({
        msg: 'Submission queue entry completed',
        action: 'submit',
        queue: job.queue.name,
        code: 'completed',
        job: job.id,
        account: job.data.account
    });
});

submitWorker.on('failed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'submit',
        status: 'failed'
    });

    // BullMQ sets finishedOn only when the job is done for good, which covers both exhausting its
    // attempts and being ended early by the UnrecoverableError thrown for a permanent rejection.
    if (job.finishedOn) {
        // this was the final attempt
        normalizeQueueId(job);
        if (job.data && job.data.account && job.data.queueId) {
            // The content stays stored, within the failed-content bounds, so the message can be
            // retried from the queue browser or the outbox API. It used to be deleted here, which
            // left a failed job that a retry could put back into the queue but that then found
            // nothing to send.
            try {
                await retainFailedContent({ account: job.data.account, queueId: job.data.queueId, finishedOn: job.finishedOn, logger });
            } catch (err) {
                logger.error({
                    msg: 'Failed to retain the content of a failed message',
                    account: job.data.account,
                    queueId: job.data.queueId,
                    messageId: job.data.messageId,
                    err
                });
            }
            // report as failed
            try {
                await notify(job.data.account, EMAIL_FAILED_NOTIFY, {
                    messageId: job.data.messageId,
                    queueId: job.data.queueId,
                    error: job.stacktrace && job.stacktrace[0] && job.stacktrace[0].split('\n').shift(),
                    networkRouting: job.progress?.networkRouting
                });
            } catch (notifyErr) {
                // A failed webhook notification must not bubble out of this BullMQ
                // event listener as an unhandled rejection and take down the worker.
                logger.error({
                    msg: 'Failed to deliver submission failure notification',
                    account: job.data.account,
                    queueId: job.data.queueId,
                    messageId: job.data.messageId,
                    err: notifyErr
                });
            }
        }
    }

    let isFinal = isFinalFailedAttempt(job);

    logger[isFinal ? 'error' : 'debug']({
        msg: 'Submission queue entry failed',
        action: 'submit',
        queue: job.queue.name,
        code: 'failed',
        job: job.id,
        account: job.data.account,

        failedReason: job.failedReason,
        stacktrace: job.stacktrace,
        attemptsMade: job.attemptsMade
    });
});

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();

        // Shutdown drain. Signals reach the main thread only, so server.js forwards them here.
        // This matters more than for the other queues: the `iaq:` entry is cleared in the
        // 'completed' handler, so a thread terminated mid-delivery leaves the job to be recovered
        // as stalled and re-run - re-sending a message the MTA had already accepted. A graceful
        // close stops fetching new jobs immediately and waits for the in-flight one.
        case 'close':
            await submitWorker.close();
            return true;

        default:
            logger.debug({ msg: 'Unhandled command', command });
            return 999;
    }
}

// Start sending heartbeats to main thread
setInterval(() => {
    try {
        parentPort.postMessage({ cmd: 'heartbeat' });
    } catch (err) {
        // Ignore errors, parent might be shutting down
    }
}, 10 * 1000).unref();

// Send initial ready signal
parentPort.postMessage({ cmd: 'ready' });

parentPort.on('message', message => {
    if (rpc.handleResponse(message)) {
        return;
    }

    if (isCall(message)) {
        return respond(parentPort, message, onCommand, { logger });
    }
});

logger.info({ msg: 'Started SMTP submission worker thread', version: packageData.version });
