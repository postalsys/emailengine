'use strict';

const { parentPort } = require('worker_threads');
const config = require('wild-config');
const logger = require('../lib/logger');
const util = require('util');
const { redis, submitQueue, notifyQueue } = require('../lib/db');
const { Account } = require('../lib/account');
const { getDuration } = require('../lib/tools');
const getSecret = require('../lib/get-secret');
const packageData = require('../package.json');
const msgpack = require('msgpack5')();

const { EMAIL_FAILED_NOTIFY, QUEUE_REMOVE_AFTER } = require('../lib/consts');

config.smtp = config.smtp || {
    port: 2525,
    host: '127.0.0.1'
};

config.queues = config.queues || {
    submit: 1
};

config.service = config.service || {};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(process.env.EENGINE_TIMEOUT || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const SUBMIT_QC = (process.env.EENGINE_SUBMIT_QC && Number(process.env.EENGINE_SUBMIT_QC)) || config.queues.submit || 1;

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T5]');
            err.statusCode = 504;
            err.code = 'Timeout';
            reject(err);
        }, message.timeout || EENGINE_TIMEOUT);

        callQueue.set(mid, { resolve, reject, timer });

        parentPort.postMessage(
            {
                cmd: 'call',
                mid,
                message
            },
            transferList
        );
    });
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

async function notify(account, event, data) {
    metrics(logger, 'events', 'inc', {
        event
    });

    let payload = {
        account,
        date: new Date().toISOString()
    };

    if (event) {
        payload.event = event;
    }

    if (data) {
        payload.data = data;
    }

    await notifyQueue.add(event, payload, {
        removeOnComplete: QUEUE_REMOVE_AFTER,
        removeOnFail: QUEUE_REMOVE_AFTER,
        attempts: 10,
        backoff: {
            type: 'exponential',
            delay: 5000
        }
    });
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

submitQueue.process('*', SUBMIT_QC, async job => {
    let queueEntryBuf = await redis.hgetBuffer(`iaq:${job.data.account}`, job.data.qId);
    if (!queueEntryBuf) {
        // nothing to do here
        try {
            await redis.hdel(`iaq:${job.data.account}`, job.data.qId);
        } catch (err) {
            // ignore
        }
        return;
    }

    let queueEntry;
    try {
        queueEntry = msgpack.decode(queueEntryBuf);
    } catch (err) {
        logger.error({ msg: 'Failed to parse queued email entry', job: job.data, err });
        try {
            await redis.hdel(`iaq:${job.data.account}`, job.data.qId);
        } catch (err) {
            // ignore
        }
        return;
    }

    if (!queueEntry) {
        //could be expired?
        return false;
    }

    let accountObject = new Account({ account: job.data.account, redis, call, secret: await getSecret() });

    let res = await accountObject.submitMessage(queueEntry);

    logger.info({ msg: 'Submitted queued message for delivery', account: queueEntry.account, queueId: job.data.qId, messageId: job.data.messageId, res });
});

submitQueue.on('completed', async job => {
    if (job.data && job.data.account && job.data.qId) {
        try {
            await redis.hdel(`iaq:${job.data.account}`, job.data.qId);
        } catch (err) {
            logger.error({ msg: 'Failed to remove queue entry', account: job.data.account, queueId: job.data.qId, messageId: job.data.messageId, err });
        }
    }
});

submitQueue.on('failed', async job => {
    if (job.finishedOn) {
        // this was final attempt, remove it
        if (job.data && job.data.account && job.data.qId) {
            try {
                await redis.hdel(`iaq:${job.data.account}`, job.data.qId);
            } catch (err) {
                logger.error({ msg: 'Failed to remove queue entry', account: job.data.account, queueId: job.data.qId, messageId: job.data.messageId, err });
            }
            // report as failed
            await notify(job.data.account, EMAIL_FAILED_NOTIFY, {
                messageId: job.data.messageId,
                queueId: job.data.qId,
                error: job.stacktrace && job.stacktrace[0] && job.stacktrace[0].split('\n').shift()
            });
        }
    }
});

async function onCommand(command) {
    logger.debug({ msg: 'Unhandled command', command });
}

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

logger.info({ msg: 'Started SMTP submission worker thread', version: packageData.version });
