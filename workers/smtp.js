'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');

const { getDuration, emitChangeEvent, readEnvValue, threadStats, loadTlsConfig, assertTlsCredentials, getByteSize } = require('../lib/tools');
const { createTlsContext, applyTlsContext } = require('../lib/tls/context');
const { createSmtpAuthHandler, createSmtpAccountResolver } = require('../lib/smtp-auth');

const { initSentry } = require('../lib/sentry');
initSentry('smtp');

const { SMTPServer } = require('smtp-server');
const util = require('util');
const { collectMessage } = require('../lib/smtp-message-processor');
const settings = require('../lib/settings');

const { createCertHandler } = require('../lib/cert-handler');

config.smtp = config.smtp || {
    enabled: false,
    port: 2525,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

config.service = config.service || {};

const { DEFAULT_MAX_SMTP_MESSAGE_SIZE } = require('../lib/consts');

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const MAX_SMTP_MESSAGE_SIZE = getByteSize(readEnvValue('EENGINE_MAX_SMTP_MESSAGE_SIZE') || config.smtp.maxMessageSize) || DEFAULT_MAX_SMTP_MESSAGE_SIZE;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

// Every connection buffers its message in memory up to MAX_SMTP_MESSAGE_SIZE before it is queued,
// so the concurrent connection count is what bounds this worker's memory. Excess connections are
// refused with a 421, which any SMTP client retries. The default matches Postfix's smtpd limit.
const DEFAULT_SMTP_MAX_CLIENTS = 100;
const SMTP_MAX_CLIENTS = Number(readEnvValue('EENGINE_SMTP_MAX_CLIENTS') || config.smtp.maxClients) || DEFAULT_SMTP_MAX_CLIENTS;

const ACCOUNT_CACHE = new WeakMap();

// The running listener and the TLS material it serves, kept at module level so the certificate
// reload command can reach both. A renewal used to terminate this worker, which cut every
// submission in flight; the listener can be handed a new secure context instead.
let smtpServer = null;
let tlsContext = null;

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

// Authentication and account resolution live in lib/smtp-auth.js so they can be unit tested
// without booting this worker. The shared ACCOUNT_CACHE and call() are injected so onAuth
// caches the Account that the resolver hands to the submission.
const onAuth = createSmtpAuthHandler({ accountCache: ACCOUNT_CACHE, call });
const resolveAccount = createSmtpAccountResolver({ accountCache: ACCOUNT_CACHE, call });

async function init() {
    let server;

    let serverOptions = {
        disabledCommands: ['STARTTLS'],
        allowInsecureAuth: true,
        logger: smtpLogger,
        disableReverseLookup: true,
        banner: 'EmailEngine MSA',
        size: MAX_SMTP_MESSAGE_SIZE,
        maxClients: SMTP_MAX_CLIENTS,
        useProxy: await settings.get('smtpServerProxy')
    };

    // Reads what the API worker provisioned; this one never orders a certificate itself.
    let certs = createCertHandler(logger);

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

                let accountObject = await resolveAccount(session, messageMeta);

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

        // Environment and config-file material first. It used to be loaded here and then
        // overwritten by whatever Let's Encrypt had provisioned, so an operator who pinned a
        // certificate through EENGINE_SMTP_TLS_CERT was silently served a different one.
        // lib/tls/context.js keeps it ahead of every automatic source instead.
        loadTlsConfig(serverOptions, 'EENGINE_SMTP_TLS_');

        // The material loaded above is snapshotted inside, at entry. The resolved material is
        // written back into serverOptions below, so a later refresh reading this object again would
        // believe the operator had supplied whatever it resolved through the environment.
        tlsContext = await createTlsContext({ certs, logger, listenerOptions: serverOptions });
        Object.assign(serverOptions, tlsContext.options);

        // Reached only when there is no material at all, which now means the self-signed fallback
        // could not be generated either - a broken instance rather than a missing certificate.
        assertTlsCredentials(serverOptions, 'The SMTP server');
    } else {
        serverOptions.disabledCommands = ['STARTTLS'];
        serverOptions.hideSTARTTLS = true;
    }

    server = new SMTPServer(serverOptions);
    smtpServer = server;

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
        await emitChangeEvent(logger, null, 'smtpServerState', 'listening', { tls: tlsContext ? tlsContext.active : null });
    } catch (err) {
        await emitChangeEvent(logger, null, 'smtpServerState', 'failed', {
            error: { message: err.message, code: err.code || null }
        });
        throw err;
    }

    return server;
}

/**
 * Re-resolves the TLS material and hands it to the running listener.
 *
 * Connections already established keep the context they negotiated with; the next handshake gets
 * the new one. Nothing here restarts the server, which is the whole point: a renewal is not a
 * reason to drop a submission that is halfway through DATA.
 *
 * @returns {Promise<Object>} What the listener is serving after the reload
 */
async function reloadCertificates() {
    const result = await applyTlsContext({
        context: smtpServer ? tlsContext : null,
        apply: options => smtpServer.updateSecureContext(options),
        logger
    });

    if (result.updated) {
        await emitChangeEvent(logger, null, 'smtpServerState', 'listening', { tls: result.tls });
    }

    return result;
}

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();

        case 'smtpReloadCertificates':
            return await reloadCertificates();
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
