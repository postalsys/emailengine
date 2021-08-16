'use strict';

const { parentPort } = require('worker_threads');
const config = require('wild-config');
const logger = require('../lib/logger');
const { SMTPServer } = require('smtp-server');
const util = require('util');
const { redis, submitQueue, notifyQueue } = require('../lib/db');
const { Account } = require('../lib/account');
const { getDuration } = require('../lib/tools');
const getSecret = require('../lib/get-secret');
const packageData = require('../package.json');
const msgpack = require('msgpack5')();

const { EMAIL_FAILED_NOTIFY } = require('../lib/consts');

config.smtp = config.smtp || {
    port: 2525,
    host: '127.0.0.1'
};

config.service = config.service || {};

const MAX_SIZE = 20 * 1024 * 1024;
const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(process.env.EENGINE_TIMEOUT || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const SMTP_PORT = (process.env.EENGINE_SMTP_PORT && Number(process.env.EENGINE_SMTP_PORT)) || config.smtp.port || 2525;
const SMTP_HOST = process.env.EENGINE_SMTP_HOST || config.smtp.host || '127.0.0.1';
const SMTP_SECRET = process.env.EENGINE_SMTP_SECRET || config.smtp.secret;
const SMTP_PROXY =
    /^\s*(true|y|yes|1)\s*$/i.test(process.env.EENGINE_SMTP_PROXY) || config.smtp.proxy === true || /^\s*(true|y|yes|1)\s*$/i.test(config.smtp.proxy);

const ACCOUNT_CACHE = new WeakMap();

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response');
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
        removeOnComplete: true,
        removeOnFail: true,
        attempts: 5,
        backoff: {
            type: 'exponential',
            delay: 2000
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

async function onAuth(auth, session) {
    if (auth.password !== SMTP_SECRET) {
        throw new Error('Failed to authenticate user');
    }

    let accountObject = new Account({ account: auth.username, redis, call, secret: await getSecret() });
    let accountData;
    try {
        accountData = await accountObject.loadAccountData();
    } catch (err) {
        let respErr = new Error('Failed to authenticate user');

        if (!err.output || err.output.statusCode !== 404) {
            // only log non-obvious errors
            logger.error({ msg: 'Failed to load account data', account: auth.username, err });
            respErr.statusCode = 454;
        }

        throw respErr;
    }

    if (!accountData) {
        throw new Error('Failed to authenticate user');
    }

    ACCOUNT_CACHE.set(session, accountObject);
    return { user: accountData.account };
}

async function init() {
    if (!SMTP_SECRET) {
        return;
    }

    let serverOptions = {
        disabledCommands: ['STARTTLS'],
        allowInsecureAuth: true,
        logger: smtpLogger,
        disableReverseLookup: true,
        banner: 'EmailEngine MSA',
        size: MAX_SIZE,
        useProxy: SMTP_PROXY
    };

    serverOptions.onAuth = (auth, session, callback) => {
        onAuth(auth, session)
            .then(res => callback(null, res))
            .catch(err => callback(err));
    };

    serverOptions.onData = (stream, session, callback) => {
        let chunks = [];
        let chunklen = 0;

        stream.on('readable', () => {
            let chunk;
            while ((chunk = stream.read()) !== null) {
                if (!stream.sizeExceeded) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            }
        });

        stream.on('end', () => {
            let err;
            if (stream.sizeExceeded) {
                err = new Error('Message exceeds fixed maximum message size');
                err.responseCode = 552;
                return callback(err);
            }
            let accountObject = ACCOUNT_CACHE.get(session);
            if (!accountObject) {
                err = new Error('Faild to get account data');
                err.responseCode = 451;
                return callback(err);
            }

            let message = Buffer.concat(chunks, chunklen);

            let payload = {
                envelope: {
                    from: session.envelope.mailFrom.address,
                    to: session.envelope.rcptTo.map(entry => entry.address)
                },
                raw: message
            };

            accountObject
                .queueMessage(payload)
                .then(res => {
                    // queued for later
                    metrics(logger, 'events', 'inc', {
                        event: 'smtpSubmitQueued'
                    });

                    logger.info({
                        msg: 'Message queued',
                        account: session.user,
                        messageId: res.messageId,
                        sendAt: res.sendAt,
                        queueId: res.queueId
                    });

                    return callback(null, `Message queued for delivery as ${res.queueId} (${new Date(res.sendAt).toISOString()})`);
                })
                .catch(err => {
                    metrics(logger, 'events', 'inc', {
                        event: 'smtpSubmitFail'
                    });
                    logger.error({ msg: 'Failed to submit message', account: session.user, err });
                    callback(err);
                });
        });
    };

    const server = new SMTPServer(serverOptions);

    return await new Promise((resolve, reject) => {
        server.once('error', err => reject(err));
        server.listen(SMTP_PORT, SMTP_HOST, () => {
            server.on('error', err => {
                logger.error({
                    msg: 'SMTP Server Error',
                    err
                });
            });
            resolve();
        });
    });
}

submitQueue.process('*', async job => {
    let queueEntryBuf = await redis.hgetBuffer(`iaq:${job.data.account}`, job.data.qId);

    let queueEntry;
    try {
        queueEntry = msgpack.decode(queueEntryBuf);
    } catch (err) {
        logger.error({ msg: 'Failed to parse queued email entry', job: job.data, err });
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

init()
    .then(() => {
        logger.debug({
            msg: 'Started SMTP server thread',
            port: SMTP_PORT,
            host: SMTP_HOST,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.error(err);
        setImmediate(() => process.exit(3));
    });
