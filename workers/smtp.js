'use strict';

const { parentPort } = require('worker_threads');
const config = require('wild-config');
const logger = require('../lib/logger');
const { SMTPServer } = require('smtp-server');
const util = require('util');
const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const { getDuration } = require('../lib/tools');
const getSecret = require('../lib/get-secret');
const packageData = require('../package.json');

config.smtp = config.smtp || {
    port: 2525,
    host: '127.0.0.1'
};

config.service = config.service || {};

const MAX_SIZE = 20 * 1024 * 1024;
const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(process.env.EENGINE_TIMEOUT || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const SMTP_PORT = (process.env.EENGINE_SMTP_PORT && Number(process.env.EENGINE_SMTP_PORT)) || config.smtp.port;
const SMTP_HOST = process.env.EENGINE_SMTP_HOST || config.smtp.host;
const SMTP_SECRET = process.env.EENGINE_SMTP_SECRET || config.smtp.secret;

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
    let serverOptions = {
        disabledCommands: ['STARTTLS'],
        allowInsecureAuth: true,
        logger: smtpLogger,
        disableReverseLookup: true,
        banner: 'EmailEngine MSA',
        size: MAX_SIZE
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
                .submitMessage(payload)
                .then(res => {
                    metrics(logger, 'events', 'inc', {
                        event: 'smtpSubmitSuccess'
                    });

                    logger.info({ msg: 'Message submitted', account: session.user, response: res.response });
                    callback(null, `Remote response: ${res.response}`);
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
