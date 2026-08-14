'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');

const { getDuration, emitChangeEvent, readEnvValue, threadStats, loadTlsConfig, getByteSize } = require('../lib/tools');
const { createSmtpAuthHandler } = require('../lib/smtp-auth');

const { initSentry } = require('../lib/sentry');
initSentry('smtp');

const { SMTPServer } = require('smtp-server');
const util = require('util');
const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { collectMessage } = require('../lib/smtp-message-processor');
const settings = require('../lib/settings');

const { encrypt, decrypt } = require('../lib/encrypt');
const { Certs } = require('@postalsys/certs');

config.smtp = config.smtp || {
    enabled: false,
    port: 2525,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

config.service = config.service || {};

const { REDIS_PREFIX, DEFAULT_MAX_SMTP_MESSAGE_SIZE } = require('../lib/consts');

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const MAX_SMTP_MESSAGE_SIZE = getByteSize(readEnvValue('EENGINE_MAX_SMTP_MESSAGE_SIZE') || config.smtp.maxMessageSize) || DEFAULT_MAX_SMTP_MESSAGE_SIZE;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const ACCOUNT_CACHE = new WeakMap();

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T4]');
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

// Authentication logic lives in lib/smtp-auth.js so it can be unit tested
// without booting this worker. The shared ACCOUNT_CACHE and call() are injected
// so onAuth caches the Account for later processing steps.
const onAuth = createSmtpAuthHandler({ accountCache: ACCOUNT_CACHE, call });

async function checkAccountData(session, messageMeta) {
    let accountObject;

    if (!session.eeAuthEnabled && messageMeta.requestedAccount) {
        // load account data
        accountObject = new Account({ account: messageMeta.requestedAccount, redis, call, secret: await getSecret() });
        let accountData;
        try {
            // throws if unknown user
            accountData = await accountObject.loadAccountData();
            if (accountData) {
                ACCOUNT_CACHE.set(session, accountObject);
                logger.debug({ msg: 'Resolved requested account', account: messageMeta.requestedAccount });
            }
        } catch (err) {
            logger.warn({ msg: 'Failed to resolve requested account', account: messageMeta.requestedAccount, err });
        }
    } else {
        accountObject = ACCOUNT_CACHE.get(session);
    }

    if (!session.eeAuthEnabled && !messageMeta.requestedAccount && !accountObject) {
        let err = new Error('Sender account ID not provided, can not send mail');
        err.responseCode = 451;
        throw err;
    }

    if (!accountObject) {
        let err = new Error('Failed to load account');
        err.responseCode = 451;
        throw err;
    }

    return accountObject;
}

async function init() {
    let server;

    let serverOptions = {
        disabledCommands: ['STARTTLS'],
        allowInsecureAuth: true,
        logger: smtpLogger,
        disableReverseLookup: true,
        banner: 'EmailEngine MSA',
        size: MAX_SMTP_MESSAGE_SIZE,
        useProxy: await settings.get('smtpServerProxy')
    };

    let certs = new Certs({
        redis,
        namespace: `${REDIS_PREFIX}`,

        environment: 'ee',

        logger: logger.child({ sub: 'acme' }),

        encryptFn: async value => {
            const encryptSecret = await getSecret();
            return encrypt(value, encryptSecret);
        },

        decryptFn: async value => {
            const encryptSecret = await getSecret();
            return decrypt(value, encryptSecret);
        }
    });

    // check and update authentication settings on connection
    serverOptions.onConnect = (session, callback) => {
        settings
            .get('smtpServerAuthEnabled')
            .then(authEnabled => {
                if (authEnabled && server.options.disabledCommands.includes('AUTH')) {
                    let disabledCommands = new Set(server.options.disabledCommands);
                    disabledCommands.delete('AUTH');
                    server.options.disabledCommands = Array.from(disabledCommands);
                    logger.info({ msg: 'Enabled authentication for the SMTP server', disabledCommands: server.options.disabledCommands });
                } else if (!authEnabled && !server.options.disabledCommands.includes('AUTH')) {
                    server.options.disabledCommands.push('AUTH');
                    logger.info({ msg: 'Disabled authentication for the SMTP server', disabledCommands: server.options.disabledCommands });
                }

                session.eeAuthEnabled = !!authEnabled;

                return settings.get('smtpServerProxy');
            })
            .then(smtpServerProxy => {
                server.options.useProxy = smtpServerProxy;
            })
            .then(() => {
                callback();
            })
            .catch(err => {
                callback(err);
            });
    };

    serverOptions.onAuth = (auth, session, callback) => {
        onAuth(auth, session)
            .then(res => callback(null, res))
            .catch(err => callback(err));
    };

    serverOptions.onData = (rawStream, session, callback) => {
        let messageMeta = {};

        // Collecting the message lives in lib/smtp-message-processor.js so that the control
        // header stripping, the stream error handling and the size verdict are unit testable -
        // this worker can not be required from a test, it boots an SMTP server on load.
        // collectMessage() rejects on a processing error instead of leaving it unhandled, which
        // used to kill the entire worker thread rather than the one failing submission.
        collectMessage(rawStream, messageMeta)
            .then(async ({ message, sizeExceeded }) => {
                if (sizeExceeded) {
                    let err = new Error('Message exceeds fixed maximum message size');
                    err.responseCode = 552;
                    throw err;
                }

                let accountObject = await checkAccountData(session, messageMeta);

                let payload = {
                    envelope: {
                        from: session.envelope.mailFrom.address,
                        to: session.envelope.rcptTo.map(entry => entry.address)
                    },
                    raw: message
                };

                let res = await accountObject.queueMessage(payload, {
                    source: 'smtp',
                    idempotencyKey: messageMeta.idempotencyKey
                });

                // queued for later
                metrics(logger, 'events', 'inc', {
                    event: 'smtpSubmitQueued'
                });

                logger.info({
                    msg: 'Message queued',
                    account: accountObject.account,
                    messageId: res.messageId,
                    sendAt: res.sendAt,
                    queueId: res.queueId,
                    idempotency: res.idempotency
                });

                callback(null, `Message queued for delivery as ${res.queueId} (${new Date(res.sendAt).toISOString()})`);
            })
            .catch(err => {
                metrics(logger, 'events', 'inc', {
                    event: 'smtpSubmitFail'
                });
                // a responseCode means the submission was refused with an SMTP reply,
                // which is a client-caused rejection rather than a server fault
                logger[err.responseCode ? 'warn' : 'error']({
                    msg: 'Failed to submit message',
                    account: session.user || messageMeta.requestedAccount,
                    err
                });
                callback(err);
            });
    };

    let tls = await settings.get('smtpServerTLSEnabled');

    if (tls) {
        serverOptions.secure = true;
        serverOptions.allowInsecureAuth = false;

        loadTlsConfig(serverOptions, 'EENGINE_SMTP_TLS_');

        // load certificates
        let serviceUrl = await settings.get('serviceUrl');
        let hostname = (new URL(serviceUrl).hostname || '').toString().toLowerCase().trim();
        if (hostname) {
            let certificateData = await certs.getCertificate(hostname, true);
            if (certificateData && certificateData.status === 'valid') {
                serverOptions.cert =
                    certificateData.cert +
                    '\n' +
                    []
                        .concat(certificateData.ca || [])
                        .flatMap(entry => entry)
                        .join('\n');
                serverOptions.key = certificateData.privateKey;
            }
        }
    } else {
        serverOptions.disabledCommands = ['STARTTLS'];
        serverOptions.hideSTARTTLS = true;
    }

    server = new SMTPServer(serverOptions);

    let port = await settings.get('smtpServerPort');
    let host = await settings.get('smtpServerHost');

    try {
        await new Promise((resolve, reject) => {
            server.once('error', err => reject(err));
            server.listen(port, host, () => {
                server.on('error', err => {
                    if (/Socket closed unexpectedly/.test(err.message)) {
                        return;
                    }
                    logger.error({
                        msg: 'SMTP server error',
                        err
                    });
                });
                resolve();
            });
        });
        await emitChangeEvent(logger, null, 'smtpServerState', 'listening');
    } catch (err) {
        await emitChangeEvent(logger, null, 'smtpServerState', 'failed', {
            error: { message: err.message, code: err.code || null }
        });
        throw err;
    }

    return server;
}

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
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
    .then(smtpServer => {
        let address = smtpServer.server.address();
        logger.info({
            msg: 'Started SMTP server thread',
            address,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.fatal({ msg: 'Failed to initialize SMTP server', err });
        logger.flush(() => process.exit(3));
    });
