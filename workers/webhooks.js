'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');
const { webhooks: Webhooks } = require('../lib/webhooks');

const { GooglePubSub } = require('../lib/oauth/pubsub/google');

const { readEnvValue, threadStats, getDuration, httpAgent, getServiceSecret } = require('../lib/tools');
const { isFinalFailedAttempt } = require('../lib/delivery-error');
const { validateWebhookTarget } = require('../lib/webhook-egress');
const { createWebhookProcessor } = require('../lib/webhook-delivery');

const { initSentry } = require('../lib/sentry');
initSentry('webhooks');

const { redis, queueConf, logBullErrors } = require('../lib/db');
const { Worker } = require('bullmq');
const settings = require('../lib/settings');
const { decryptField } = require('../lib/encrypt');
const getSecret = require('../lib/get-secret');

const { fetch: fetchCmd } = require('undici');

config.queues = config.queues || {
    notify: 1
};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const NOTIFY_QC = (readEnvValue('EENGINE_NOTIFY_QC') && Number(readEnvValue('EENGINE_NOTIFY_QC'))) || config.queues.notify || 1;

// Wall-clock cap for a single webhook delivery attempt; falls back to the
// DEFAULT_WEBHOOK_REQUEST_TIMEOUT baked into sendWebhookRequest when unset
const WEBHOOK_TIMEOUT = getDuration(readEnvValue('EENGINE_WEBHOOK_TIMEOUT')) || false;

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T6]');
            err.statusCode = 504;
            err.code = 'Timeout';
            err.ttl = ttl;
            callQueue.delete(mid);
            reject(err);
        }, ttl);

        callQueue.set(mid, { resolve, reject, timer });

        try {
            parentPort.postMessage(
                {
                    cmd: 'call',
                    mid,
                    message
                },
                transferList
            );
        } catch (err) {
            clearTimeout(timer);
            callQueue.delete(mid);
            return reject(err);
        }
    });
}

const googlePubSub = new GooglePubSub({
    call
});

// The account `webhooks` and `webhooksCustomHeaders` fields are encrypted at rest (see
// ENCRYPTED_ACCOUNT_FIELDS in lib/account.js); a value stored before that is cleartext, which
// decrypt() passes through. One that no longer decrypts reads as unset, as it does for the account.
async function openAccountField(field, value, account) {
    return decryptField(value, await getSecret(), err =>
        logger.error({ msg: 'Failed to decrypt account webhook setting', action: 'webhook', account, field, err })
    );
}

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

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
        case 'googlePubSub':
            await googlePubSub.update(command.app);
            return true;
        case 'googlePubSubRemove':
            googlePubSub.remove(command.app);
            return true;
        case 'close':
            clearTimeout(startRetryTimer);
            googlePubSub.stopAll();
            // Not forced: a forced close abandons the delivery in flight, which BullMQ then
            // re-runs as stalled after the lock expires, so the receiver got the event twice
            // with the same X-EE-Wh-Id. The main thread bounds this wait with its own drain timeout.
            await notifyWorker.close();
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

// Clean up Pub/Sub instances when parent port closes
parentPort.on('close', () => {
    clearTimeout(startRetryTimer);
    googlePubSub.stopAll();
    // notifyWorker.close() may throw synchronously if not yet initialized
    try {
        notifyWorker.close(true).catch(() => {});
    } catch {
        // ignore
    }
});

// Send initial ready signal
parentPort.postMessage({ cmd: 'ready' });

parentPort.on('message', message => {
    if (message && message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
        let { resolve, reject, timer } = callQueue.get(message.mid);
        clearTimeout(timer);
        callQueue.delete(message.mid);
        if (message.error) {
            let err = new Error(message.error);
            if (message.code) {
                err.code = message.code;
            }
            if (message.statusCode) {
                err.statusCode = message.statusCode;
            }
            if (message.info) {
                err.info = message.info;
            }
            return reject(err);
        } else {
            return resolve(message.response);
        }
    }

    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

const notifyWorker = new Worker(
    'notify',
    // the processor lives in lib/webhook-delivery.js so it can be tested; everything it touches is passed in here
    createWebhookProcessor({
        redis,
        settings,
        webhooks: Webhooks,
        logger,
        metrics: (key, method, ...args) => metrics(logger, key, method, ...args),
        openAccountField,
        getServiceSecret,
        fetch: fetchCmd,
        dispatcher: httpAgent.webhook,
        timeout: WEBHOOK_TIMEOUT,
        validateTarget: validateWebhookTarget
    }),
    Object.assign(
        {
            concurrency: Number(NOTIFY_QC) || 1,

            // Each webhook HTTP attempt is capped at EENGINE_WEBHOOK_TIMEOUT (default 30s);
            // keep this lock comfortably above that cap so an in-flight attempt cannot outlive
            // the lock and let BullMQ mark the job stalled (which would re-deliver the webhook).
            lockDuration: 3 * 60 * 1000, // 3 minutes

            // Check for stalled jobs every 60 seconds
            stalledInterval: 60 * 1000,

            // Allow jobs to recover from stalled state up to 3 times
            maxStalledCount: 3
        },
        queueConf || {}
    )
);

logBullErrors(notifyWorker, 'worker:webhooks');

notifyWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'notify',
        status: 'completed'
    });

    logger.debug({
        msg: 'Notification queue entry completed',
        action: 'webhook',
        queue: job.queue.name,
        code: 'completed',
        job: job.id,
        event: job.name,
        account: job.data.account,
        // a completed job always ran the processor, which stashes this before any early return
        route: job.__routeId
    });
});

notifyWorker.on('failed', async (job, err) => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'notify',
        status: 'failed'
    });

    let isFinal = isFinalFailedAttempt(job);

    logger[isFinal ? 'error' : 'debug']({
        msg: 'Notification queue entry failed',
        action: 'webhook',
        queue: job.queue.name,
        code: 'failed',
        job: job.id,
        event: job.name,
        account: job.data.account,
        // the fallback covers jobs that stalled out before this worker instance ever processed
        // them, where the stash was never set and _route is still in the payload
        route: job.__routeId || (job.data._route && job.data._route.id),
        webhooks: job.__redactedTargetUrl,
        err,

        failedReason: job.failedReason,
        stacktrace: job.stacktrace,
        attemptsMade: job.attemptsMade
    });
});

let startRetryTimer = null;

(function startGooglePubSub(attempt) {
    googlePubSub
        .start()
        .then(() => {
            logger.info({ msg: 'Started processing Google pub/sub' });
        })
        .catch(err => {
            let maxNormalAttempts = 20;
            let delay;
            if (attempt < maxNormalAttempts) {
                delay = Math.min(5000 * Math.pow(2, Math.min(attempt, 10)), 60000);
                logger.warn({ msg: 'Failed to start processing Google pub/sub', err, attempt: attempt + 1, retryMs: delay });
            } else {
                delay = 5 * 60 * 1000;
                logger.error({ msg: 'Failed to start processing Google pub/sub (reduced frequency)', err, attempt: attempt + 1, retryMs: delay });
            }
            startRetryTimer = setTimeout(() => startGooglePubSub(attempt + 1), delay);
        });
})(0);

logger.info({ msg: 'Started Webhooks worker thread', version: packageData.version });
