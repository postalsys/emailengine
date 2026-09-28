'use strict';

const { parentPort } = require('worker_threads');

const config = require('@zone-eu/wild-config');
const logger = require('../logger');
const { oauth2Apps, oauth2ProviderData } = require('../oauth2-apps');

const {
    getDuration,
    getBoolean,
    resolveCredentials,
    useAuthServerForOAuth2,
    useAuthServerForConnection,
    hasEnvValue,
    readEnvValue,
    emitChangeEvent,
    loadTlsConfig,
    assertTlsCredentials
} = require('../tools');
const { getLocalAddress } = require('../utils/network');

const { redis } = require('../db');
const { createImapProxyAuthHandler, classifyCredentialFailure } = require('../imap-proxy-auth');
const settings = require('../settings');

const { createCertHandler } = require('../cert-handler');
const { createTlsContext, applyTlsContext } = require('../tls/context');

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

// Every connection can buffer up to a 1MB command line before it authenticates, so the number of
// open connections bounds the worker's memory. Excess connections get a BYE and are closed.
const DEFAULT_IMAP_PROXY_MAX_CLIENTS = 1000;
const IMAP_PROXY_MAX_CLIENTS = Number(readEnvValue('EENGINE_IMAPPROXY_MAX_CLIENTS') || config.imap.maxClients) || DEFAULT_IMAP_PROXY_MAX_CLIENTS;

const { TLS_DEFAULTS } = require('../consts');

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

// Resolve pending call() promises when the main thread answers. Without this any
// RPC issued from this worker (via the `call` passed into Account) would never settle
// and would reject on timeout. Mirrors the handlers in workers/imap.js and smtp.js.
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
        }

        return resolve(message.response);
    }
});

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

const { createUpstreamClient } = require('./upstream-client');
const { IMAPServer } = require('./imap-core/index.js');
const { createProxyAuthHandler } = require('./proxy-handoff');

const packageInfo = require('../../package.json');
const util = require('util');

const CLIENT_INFO = {
    name: packageInfo.name,
    version: packageInfo.version,
    vendor: packageInfo.author
};

// Authentication logic lives in lib/imap-proxy-auth.js so it can be unit tested
// without booting this worker. call() is injected for the Account instance.
const authenticateImapProxy = createImapProxyAuthHandler({ call });

async function onAuth(auth, session) {
    let account = auth.username;

    let { accountObject, accountData } = await authenticateImapProxy(auth, session);

    if (!accountData.imap && !accountData.oauth2) {
        // can not make connection
        return { accountData, imapConfig: false };
    }

    let imapConnectionConfig;
    if (accountData.oauth2 && accountData.oauth2.auth) {
        // load OAuth2 tokens
        let imapAuth;

        if (await useAuthServerForOAuth2(accountData.oauth2, logger, { account, target: 'imap' })) {
            // An external authentication server owns this account's tokens, so ask it for one
            // rather than renewing from a stored refresh token (there is none). The response is
            // already in the { user, accessToken } shape the connection config expects.
            try {
                imapAuth = await resolveCredentials(account, 'imap');
            } catch (err) {
                throw classifyCredentialFailure(err);
            }
        } else {
            if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(Date.now() + 30 * 1000)) {
                // renew access token
                try {
                    accountData = await accountObject.renewAccessToken();
                } catch (err) {
                    throw classifyCredentialFailure(err);
                }
            }
            imapAuth = { user: accountData.oauth2.auth.user, accessToken: accountData.oauth2.accessToken };
        }

        const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
        if (!oauth2App) {
            throw new Error('Missing or disabled OAuth2 app');
        }
        const providerData = oauth2ProviderData(oauth2App.provider, oauth2App.cloud);

        imapConnectionConfig = Object.assign({ auth: imapAuth }, providerData.imap || {});
    } else {
        // deep copy of imap settings
        imapConnectionConfig = JSON.parse(JSON.stringify(accountData.imap));
    }

    // If authentication server is set then it overrides authentication data
    if (await useAuthServerForConnection(imapConnectionConfig, logger, { account, target: 'imap' })) {
        try {
            imapConnectionConfig.auth = await resolveCredentials(account, 'imap');
        } catch (err) {
            throw classifyCredentialFailure(err);
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

    // Carries its own permanent error sink - see lib/imapproxy/upstream-client.js
    let imapClient = createUpstreamClient(imapConfig);

    await imapClient.connect();

    let { readSocket, writeSocket } = imapClient.unbind();

    return { readSocket, writeSocket, imapClient };
};

let serverLogger = logger.child({ property: 'downstream' });
const createServer = function (options = {}) {
    // Setup server

    let imapLogger = {};

    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        imapLogger[level] = (data, message, ...args) => {
            if (args && args.length) {
                message = util.format(message, ...args);
            }
            data.msg = message;
            if (typeof serverLogger[level] === 'function') {
                serverLogger[level](data);
            } else {
                serverLogger.debug(data);
            }
        };
    }

    options.logger = imapLogger;

    let server = new IMAPServer(options);

    server.on('error', err => {
        if (err && err.processed) {
            // already logged by the connection that raised it
            return;
        }
        let entry = { msg: 'Server error', err };
        if (err && err.meta && err.meta.remoteAddress) {
            entry.remoteAddress = err.meta.remoteAddress;
        }
        if (err && err.report === false) {
            // e.g. a scanner closing the socket while initiating TLS
            serverLogger.debug(entry);
        } else if (err && (err.code === 'TLSError' || err.code === 'SocketError')) {
            // client-caused connection or TLS handshake failure
            serverLogger.warn(entry);
        } else {
            serverLogger.error(entry);
        }
    });

    server.onAuth = createProxyAuthHandler({
        onAuth,
        createProxy,
        logger,
        serverLogger,
        metrics,
        logRaw: EENGINE_LOG_RAW
    });

    return server;
};

// The running listener and the TLS material it serves, kept at module level so the certificate
// reload command can reach both without restarting the worker.
let proxyServer = null;
let tlsContext = null;

module.exports.run = async () => {
    const serverOptions = {
        useProxy: await settings.get('imapProxyServerProxy'),
        secure: false,
        disableSTARTTLS: true,
        proxyMode: true,
        maxConnections: IMAP_PROXY_MAX_CLIENTS,
        id: Object.assign({}, CLIENT_INFO, {
            name: 'EmailEngine IMAP Proxy'
        })
    };

    const port = await settings.get('imapProxyServerPort');
    const host = await settings.get('imapProxyServerHost');

    // Reads what the API worker provisioned; this one never orders a certificate itself.
    let certs = createCertHandler(logger);

    let tls = await settings.get('imapProxyServerTLSEnabled');

    if (tls) {
        serverOptions.secure = true;

        // Environment and config-file material first, then whatever EmailEngine manages itself.
        // The order used to be the other way round here, so an operator-supplied certificate was
        // overwritten by an automatic one; lib/tls/context.js owns the precedence now.
        loadTlsConfig(serverOptions, 'EENGINE_IMAPPROXY_TLS_');

        // The material loaded above is snapshotted inside, at entry, so a later refresh does not
        // read what this resolution wrote back into serverOptions as if the operator had supplied
        // it.
        tlsContext = await createTlsContext({ certs, logger, listener: 'imapProxy', listenerOptions: serverOptions });
        Object.assign(serverOptions, tlsContext.options);

        assertTlsCredentials(serverOptions, 'The IMAP proxy');
    }

    const server = createServer(serverOptions);
    proxyServer = server;

    try {
        await new Promise((resolve, reject) => {
            server.once('error', err => reject(err));
            server.listen(port || config.imap.port, host || config.imap.host, () => resolve(server));
        });
        await emitChangeEvent(logger, null, 'imapProxyServerState', 'listening', { tls: tlsContext ? tlsContext.active : null });
    } catch (err) {
        await emitChangeEvent(logger, null, 'imapProxyServerState', 'failed', {
            error: { message: err.message, code: err.code || null }
        });
        throw err;
    }

    return server;
};

/**
 * Re-resolves the TLS material and hands it to the running proxy.
 *
 * Sessions already established keep the context they negotiated with. An IMAP client can hold a
 * connection open for days, so restarting the worker to install a renewed certificate is the
 * expensive way to do this.
 *
 * @returns {Promise<Object>} What the listener is serving after the reload
 */
module.exports.reloadCertificates = async () => {
    const result = await applyTlsContext({
        context: proxyServer ? tlsContext : null,
        apply: options => proxyServer.updateSecureContext(options),
        logger
    });

    if (result.updated) {
        await emitChangeEvent(logger, null, 'imapProxyServerState', 'listening', { tls: result.tls });
    }

    return result;
};
