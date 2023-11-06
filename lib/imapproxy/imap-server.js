'use strict';

const { parentPort } = require('worker_threads');

const config = require('wild-config');
const logger = require('../logger');
const { oauth2Apps, oauth2ProviderData } = require('../oauth2-apps');

const {
    getDuration,
    getBoolean,
    resolveCredentials,
    hasEnvValue,
    readEnvValue,
    emitChangeEvent,
    matchIp,
    getLocalAddress,
    loadTlsConfig
} = require('../tools');

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const settings = require('../settings');
const tokens = require('../tokens');

const { encrypt, decrypt } = require('../encrypt');
const { Certs } = require('@postalsys/certs');

config.imap = config.imap || {
    enabled: false,
    port: 9993,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

config.service = config.service || {};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const EENGINE_LOG_RAW = hasEnvValue('EENGINE_LOG_RAW') ? getBoolean(readEnvValue('EENGINE_LOG_RAW')) : getBoolean(config.log.raw);
const DISABLE_IMAP_COMPRESSION = getBoolean(readEnvValue('EENGINE_DISABLE_COMPRESSION'));

const { REDIS_PREFIX, TLS_DEFAULTS } = require('../consts');

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

const { ImapFlow } = require('imapflow');
const { IMAPServer, imapHandler } = require('./imap-core/index.js');
const { PassThrough } = require('./imap-core/lib/length-limiter.js');

const packageInfo = require('../../package.json');
const util = require('util');

const CLIENT_INFO = {
    name: packageInfo.name,
    version: packageInfo.version,
    vendor: packageInfo.author
};

class PassThroughLogger extends PassThrough {
    constructor(opts = {}) {
        super();
        this.logger = opts.logger;
        this.src = opts.src;
        this.cid = opts.cid;
        this.imapClient = opts.imapClient;
    }
    _transform(chunk, encoding, next) {
        if (EENGINE_LOG_RAW) {
            this.logger.trace({
                src: this.src,
                msg: 'write to socket',
                data: chunk.toString('base64'),
                compress: !!this.imapClient._deflate,
                secure: !!this.imapClient.secureConnection,
                cid: this.id
            });
        }

        this.push(chunk);
        next();
    }

    _flush(next) {
        next();
    }
}

async function onAuth(auth, session) {
    let account = auth.username;

    let imapPassword = await settings.get('imapProxyServerPassword');
    let authPass = false;

    if (!imapPassword || auth.password !== imapPassword) {
        if (/^[0-9a-f]{64}$/i.test(auth.password)) {
            // fallback to tokens
            let tokenData;
            try {
                tokenData = await tokens.get(auth.password, false, { log: true, remoteAddress: session.remoteAddress });
            } catch (err) {
                logger.error({
                    msg: 'Failed to fetch token',
                    err
                });
            }

            if (tokenData) {
                if (tokenData.account && tokenData.account !== auth.username) {
                    let err = new Error('Access denied, invalid username');
                    err.serverResponseCode = 'AUTHENTICATIONFAILED';
                    err.responseStatus = 'NO';
                    throw err;
                }

                if (tokenData.scopes && !tokenData.scopes.includes('imap-proxy') && !tokenData.scopes.includes('*')) {
                    logger.error({
                        msg: 'Trying to use invalid scope for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account,
                        requestedScope: 'imap-proxy',
                        scopes: tokenData.scopes
                    });

                    let err = new Error('Access denied, invalid scope');
                    err.serverResponseCode = 'AUTHENTICATIONFAILED';
                    err.responseStatus = 'NO';
                    throw err;
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

                    let err = new Error('Access denied, traffic not accepted from this IP');
                    err.serverResponseCode = 'AUTHENTICATIONFAILED';
                    err.responseStatus = 'NO';
                    throw err;
                }

                authPass = true;
            }
        }

        if (!authPass) {
            let err = new Error('Access denied, failed to authenticate user');
            err.serverResponseCode = 'AUTHENTICATIONFAILED';
            err.responseStatus = 'NO';
            throw err;
        }
    }

    let accountObject = new Account({ account, redis, call, secret: await getSecret() });
    let accountData;
    try {
        accountData = await accountObject.loadAccountData();
    } catch (err) {
        let respErr = new Error('Failed to authenticate user');
        respErr.serverResponseCode = 'AUTHENTICATIONFAILED';
        respErr.responseStatus = 'NO';

        if (!err.output || err.output.statusCode !== 404) {
            // only log non-obvious errors
            logger.error({ msg: 'Failed to load account data', account: auth.username, err });
        }

        throw respErr;
    }

    if (!accountData) {
        let err = new Error('Access denied, failed to authenticate user');
        err.serverResponseCode = 'AUTHENTICATIONFAILED';
        err.responseStatus = 'NO';
        throw err;
    }

    if (!accountData.imap && !accountData.oauth2) {
        // can not make connection
        return { accountData, imapConfig: false };
    }

    let imapConnectionConfig;
    if (accountData.oauth2 && accountData.oauth2.auth) {
        // load OAuth2 tokens
        let now = Date.now();
        let accessToken;
        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
            // renew access token
            try {
                accountData = await accountObject.renewAccessToken();
                accessToken = accountData.oauth2.accessToken;
            } catch (err) {
                err.authenticationFailed = true;
                err.serverResponseCode = 'AUTHENTICATIONFAILED';
                err.responseStatus = 'NO';
                throw err;
            }
        } else {
            accessToken = accountData.oauth2.accessToken;
        }

        const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
        if (!oauth2App) {
            throw new Error('Missing or disabled OAuth2 app');
        }
        const providerData = oauth2ProviderData(oauth2App.provider);

        imapConnectionConfig = Object.assign(
            {
                auth: {
                    user: accountData.oauth2.auth.user,
                    accessToken
                }
            },
            providerData.imap || {}
        );
    } else {
        // deep copy of imap settings
        imapConnectionConfig = JSON.parse(JSON.stringify(accountData.imap));
    }

    // If authentication server is set then it overrides authentication data
    if (imapConnectionConfig.useAuthServer) {
        try {
            imapConnectionConfig.auth = await resolveCredentials(account, 'imap');
        } catch (err) {
            err.authenticationFailed = true;
            err.serverResponseCode = 'AUTHENTICATIONFAILED';
            err.responseStatus = 'NO';
            throw err;
        }
    }

    if (!imapConnectionConfig.tls) {
        imapConnectionConfig.tls = {};
    }
    imapConnectionConfig.tls.localAddress = (await getLocalAddress(redis, 'imap', account)).localAddress;

    // reload log config

    let imapConfig = imapConnectionConfig;

    // set up proxy if needed
    if (accountData.proxy) {
        imapConfig.proxy = accountData.proxy;
    } else {
        let proxyUrl = await settings.get('proxyUrl');
        let proxyEnabled = await settings.get('proxyEnabled');
        if (proxyEnabled && proxyUrl && !imapConfig.proxy) {
            imapConfig.proxy = proxyUrl;
        }
    }

    return { accountData, imapConfig };
}

const createProxy = async (options = {}) => {
    const imapConfig = Object.assign(
        {
            id: options.id,
            disableAutoEnable: true,
            clientInfo: Object.assign({}, CLIENT_INFO),
            logger: options.logger
        },
        options.imapConfig || {}
    );

    if (!imapConfig.tls) {
        imapConfig.tls = {};
    }

    for (let key of Object.keys(TLS_DEFAULTS)) {
        if (!(key in imapConfig.tls)) {
            imapConfig.tls[key] = TLS_DEFAULTS[key];
        }
    }

    if (DISABLE_IMAP_COMPRESSION) {
        imapConfig.disableCompression = true;
    }

    const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
    if (ignoreMailCertErrors && imapConfig?.tls?.rejectUnauthorized !== false) {
        imapConfig.tls = imapConfig.tls || {};
        imapConfig.tls.rejectUnauthorized = false;
    }

    let imapClient = new ImapFlow(imapConfig);

    await imapClient.connect();

    let { readSocket, writeSocket } = imapClient.unbind();

    return { readSocket, writeSocket, imapClient };
};

let serverLogger = logger.child({ propery: 'downstream' });
const createServer = function (options = {}) {
    // Setup server

    let imapLogger = {};

    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        imapLogger[level] = (data, message, ...args) => {
            if (args && args.length) {
                message = util.format(message, ...args);
            }
            data.msg = message;
            if (typeof logger[level] === 'function') {
                serverLogger[level](data);
            } else {
                serverLogger.debug(data);
            }
        };
    }

    options.logger = imapLogger;

    let server = new IMAPServer(options);

    server.on('error', err => {
        serverLogger.error({ msg: 'Server error', err });
    });

    server.onAuth = function (login, session, callback) {
        onAuth(login, session)
            .then(accountData => {
                let { account, imapConfig } = accountData;
                if (!imapConfig) {
                    throw new Error('IMAP not enabled for account');
                }

                createProxy({ imapConfig, id: session.id, logger: logger.child({ property: 'upstream', account }) })
                    .then(downstream => {
                        session.onProxy = upstream => {
                            metrics(logger, 'events', 'inc', {
                                event: 'imapProxyConnected'
                            });

                            const proxyLogger = logger.child({ property: 'proxy', account, cid: session.id });

                            let upstreamLogger = new PassThroughLogger({
                                src: 's',
                                cid: session.id,
                                imapClient: downstream.imapClient,
                                logger: proxyLogger.child({ src: 'S' })
                            });

                            let downstreamLogger = new PassThroughLogger({
                                src: 'c',
                                cid: session.id,
                                imapClient: downstream.imapClient,
                                logger: proxyLogger.child({ src: 'C' })
                            });

                            downstream.readSocket.pipe(upstreamLogger).pipe(upstream.socket);
                            upstream.socket.pipe(downstreamLogger).pipe(downstream.writeSocket);

                            upstreamLogger.on('error', err => {
                                proxyLogger.error({ msg: 'Client error', err });
                                upstream.socket.end();
                            });

                            downstreamLogger.on('error', err => {
                                proxyLogger.error({ msg: 'Server error', err });
                                downstream.writeSocket.end();
                                downstream.readSocket.end();
                            });

                            downstream.readSocket.on('error', err => {
                                proxyLogger.error({ msg: 'Client error', err });
                                upstreamLogger.end('* BYE Upstream connection error\r\n');
                            });

                            upstream.socket.on('error', err => {
                                proxyLogger.error({ msg: 'Upstream error', err });
                                downstreamLogger.end();
                            });

                            downstream.readSocket.on('end', () => {
                                proxyLogger.info({ msg: 'Client connection closed' });
                                upstreamLogger.end();
                            });

                            upstream.socket.on('end', () => {
                                proxyLogger.info({ msg: 'Server connection closed' });
                                downstreamLogger.end();
                            });

                            proxyLogger.info({ msg: 'Proxy mode enabled' });
                        };

                        if (downstream.imapClient.rawCapabilities) {
                            login.connection.send(
                                imapHandler.compiler({
                                    tag: '*',
                                    command: 'CAPABILITY',
                                    attributes: downstream.imapClient.rawCapabilities
                                })
                            );
                        }

                        callback(null, {
                            user: {
                                id: 'id.' + login.username,
                                username: login.username
                            }
                        });
                    })
                    .catch(err => {
                        if (err.authenticationFailed || err.serverResponseCode === 'AUTHENTICATIONFAILED') {
                            let error = new Error(
                                `${err.serverResponseCode ? `[${err.serverResponseCode}] ` : ''}${err.responseText || err.message || 'Authentication failed'}`
                            );
                            error.response = err.responseStatus || 'NO';
                            return callback(error);
                        } else {
                            serverLogger.error({ msg: 'Failed to create proxy', err });
                            return callback(err);
                        }
                    });
            })
            .catch(err => {
                serverLogger.error({ msg: 'Authentication check failed', username: login.username, err });
                if (err.authenticationFailed || err.serverResponseCode === 'AUTHENTICATIONFAILED') {
                    let error = new Error(
                        `${err.serverResponseCode ? `[${err.serverResponseCode}] ` : ''}${err.responseText || err.message || 'Authentication failed'}`
                    );
                    error.response = err.responseStatus || 'NO';
                    return callback(error);
                }
                return callback(err);
            });
    };

    return server;
};

module.exports.run = async () => {
    const serverOptions = {
        useProxy: await settings.get('imapProxyServerProxy'),
        secure: false,
        disableSTARTTLS: true,
        proxyMode: true,
        id: Object.assign({}, CLIENT_INFO, {
            name: 'EmailEngine IMAP Proxy'
        })
    };

    const port = await settings.get('imapProxyServerPort');
    const host = await settings.get('imapProxyServerHost');

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

    let tls = await settings.get('imapProxyServerTLSEnabled');

    if (tls) {
        serverOptions.secure = true;

        // load certificates
        let serviceUrl = await settings.get('serviceUrl');
        let hostname = (new URL(serviceUrl).hostname || '').toString().toLowerCase().trim();

        loadTlsConfig(serverOptions, 'EENGINE_IMAPPROXY_TLS_');

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
    }

    const server = createServer(serverOptions);

    try {
        await new Promise((resolve, reject) => {
            server.once('error', err => reject(err));
            server.listen(port || config.imap.port, host || config.imap.host, () => resolve(server));
        });
        await emitChangeEvent(logger, null, 'imapProxyServerState', 'listening');
    } catch (err) {
        await emitChangeEvent(logger, null, 'imapProxyServerState', 'failed', {
            error: { message: err.message, code: err.code || null }
        });
        throw err;
    }

    return server;
};
