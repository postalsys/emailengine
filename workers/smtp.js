'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');

const { getDuration, emitChangeEvent, readEnvValue, matchIp, threadStats, loadTlsConfig } = require('../lib/tools');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'smtp', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'smtp', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'smtp', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'smtp', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const { SMTPServer } = require('smtp-server');
const util = require('util');
const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { Splitter, Joiner } = require('mailsplit');
const { HeadersRewriter } = require('../lib/headers-rewriter');
const settings = require('../lib/settings');
const tokens = require('../lib/tokens');

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

const MAX_SIZE = 20 * 1024 * 1024;
const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const { REDIS_PREFIX } = require('../lib/consts');

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

async function onAuth(auth, session) {
    if (!session.eeAuthEnabled) {
        throw new Error('Authentication not enabled');
    }

    let account = auth.username;

    let smtpPassword = await settings.get('smtpServerPassword');
    let authPass = false;

    if (!smtpPassword || auth.password !== smtpPassword) {
        if (/^[0-9a-f]{64}$/i.test(auth.password)) {
            // fallback to tokens
            let tokenData;
            try {
                tokenData = await tokens.get(auth.password, false, { log: true, remoteAddress: session.remoteAddress });
            } catch (err) {
                // ignore?
            }

            if (tokenData) {
                if (tokenData.account && tokenData.account !== auth.username) {
                    throw new Error('Access denied, invalid username');
                }

                if (tokenData.scopes && !tokenData.scopes.includes('smtp') && !tokenData.scopes.includes('*')) {
                    logger.error({
                        msg: 'Trying to use invalid scope for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account,
                        requestedScope: 'smtp',
                        scopes: tokenData.scopes
                    });

                    throw new Error('Access denied, invalid scope');
                }

                if (tokenData.restrictions && tokenData.restrictions.addresses && !matchIp(session.remoteAddress, tokenData.restrictions.addresses)) {
                    logger.error({
                        msg: 'Trying to use invalid IP for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account,
                        remoteAddress: session.remoteAddress,
                        addressAllowlist: tokenData.restrictions.addresses
                    });

                    throw new Error('Access denied, traffic not accepted from this IP');
                }

                authPass = true;
            }
        }

        if (!authPass) {
            throw new Error('Failed to authenticate user');
        }
    }

    let accountObject = new Account({ account, redis, call, secret: await getSecret() });
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

function processMessage(stream, session, meta) {
    meta = meta || {};
    const splitter = new Splitter();
    const joiner = new Joiner();

    const headersRewriter = new HeadersRewriter(async headers => {
        let requestedAccount = headers.getFirst('x-ee-account');
        headers.remove('x-ee-account');
        if (requestedAccount) {
            meta.requestedAccount = requestedAccount;
        }
    });

    stream.once('error', err => joiner.emit('error', err));
    headersRewriter.once('error', err => joiner.emit('error', err));

    return stream.pipe(splitter).pipe(headersRewriter).pipe(joiner);
}

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
                logger.info({ msg: 'Resolved requested account', account: messageMeta.requestedAccount });
            }
        } catch (err) {
            logger.error({ msg: 'Failed resolving requested account', account: messageMeta.requestedAccount, err });
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
        size: MAX_SIZE,
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
        let chunks = [];
        let chunklen = 0;

        let messageMeta = {};
        let stream = processMessage(rawStream, session, messageMeta);

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

            checkAccountData(session, messageMeta)
                .then(accountObject => {
                    let message = Buffer.concat(chunks, chunklen);

                    let payload = {
                        envelope: {
                            from: session.envelope.mailFrom.address,
                            to: session.envelope.rcptTo.map(entry => entry.address)
                        },
                        raw: message
                    };

                    accountObject
                        .queueMessage(payload, { source: 'smtp' })
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
                })
                .catch(err => callback(err));
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
                    logger.error({
                        msg: 'SMTP Server Error',
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
        logger.debug({
            msg: 'Started SMTP server thread',
            address,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.error({ msg: 'Failed to initialize SMTP', err });
        logger.flush(() => process.exit(3));
    });
