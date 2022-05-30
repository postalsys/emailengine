'use strict';

const { parentPort } = require('worker_threads');
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const Cookie = require('@hapi/cookie');
const Crumb = require('@hapi/crumb');
const Joi = require('joi');
const logger = require('../lib/logger');
const hapiPino = require('hapi-pino');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const packageData = require('../package.json');
const pathlib = require('path');
const config = require('wild-config');
const crypto = require('crypto');
const { Transform, finished } = require('stream');
const { getOAuth2Client } = require('../lib/oauth');
const consts = require('../lib/consts');
const { REDIS_PREFIX } = consts;
const handlebars = require('handlebars');
const AuthBearer = require('hapi-auth-bearer-token');
const tokens = require('../lib/tokens');
const msgpack = require('msgpack5')();
const { autodetectImapSettings } = require('../lib/autodetect-imap-settings');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');

const Hecks = require('@hapipal/hecks');
const { arenaExpress } = require('../lib/arena-express');
const outbox = require('../lib/outbox');

const { redis, REDIS_CONF, notifyQueue, documentsQeueue } = require('../lib/db');
const { Account } = require('../lib/account');
const settings = require('../lib/settings');
const {
    getByteSize,
    getDuration,
    getStats,
    flash,
    failAction,
    verifyAccountInfo,
    isEmail,
    getLogs,
    getWorkerCount,
    normalizePath,
    unpackUIDRangeForSearch,
    matcher
} = require('../lib/tools');

const getSecret = require('../lib/get-secret');

const routesUi = require('../lib/routes-ui');

const { TRACK_OPEN_NOTIFY, TRACK_CLICK_NOTIFY } = require('../lib/consts');

const {
    settingsSchema,
    addressSchema,
    settingsQuerySchema,
    imapSchema,
    imapUpdateSchema,
    smtpSchema,
    smtpUpdateSchema,
    oauth2Schema,
    oauth2UpdateSchema,
    messageDetailsSchema,
    messageListSchema,
    mailboxesSchema,
    shortMailboxesSchema,
    licenseSchema,
    lastErrorSchema
} = require('../lib/schemas');

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024;

const { OUTLOOK_SCOPES } = require('../lib/outlook-oauth');
const { GMAIL_SCOPES } = require('../lib/gmail-oauth');
const { MAIL_RU_SCOPES } = require('../lib/mail-ru-oauth');

const REDACTED_KEYS = ['req.headers.authorization', 'req.headers.cookie'];

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1',
    proxy: false
};

config.service = config.service || {};

const EENGINE_TIMEOUT = getDuration(process.env.EENGINE_TIMEOUT || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const MAX_ATTACHMENT_SIZE = getByteSize(process.env.EENGINE_MAX_SIZE || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

const API_PORT = (process.env.EENGINE_PORT && Number(process.env.EENGINE_PORT)) || (process.env.PORT && Number(process.env.PORT)) || config.api.port;
const API_HOST = process.env.EENGINE_HOST || config.api.host;

const IMAP_WORKER_COUNT = getWorkerCount(process.env.EENGINE_WORKERS || (config.workers && config.workers.imap)) || 4;

const TRACKER_IMAGE = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

let registeredPublishers = new Set();

class ResponseStream extends Transform {
    constructor() {
        super();
        registeredPublishers.add(this);
        this.periodicKeepAliveTimer = false;
        this.updateTimer();
    }

    updateTimer() {
        clearTimeout(this.periodicKeepAliveTimer);
        this.periodicKeepAliveTimer = setTimeout(() => {
            this.write(': still here\n\n');
            if (this._compressor) {
                this._compressor.flush();
            }
            this.updateTimer();
        }, 90 * 1000);
        this.periodicKeepAliveTimer.unref();
    }

    setCompressor(compressor) {
        this._compressor = compressor;
    }

    sendMessage(payload) {
        let sendData = JSON.stringify(payload);
        this.write('event: message\ndata:' + sendData + '\n\n');
        if (this._compressor) {
            this._compressor.flush();
        }
        this.updateTimer();
    }

    finalize() {
        clearTimeout(this.periodicKeepAliveTimer);
        registeredPublishers.delete(this);
    }

    _transform(data, encoding, done) {
        this.push(data);
        done();
    }

    _flush(done) {
        this.finalize();
        done();
    }
}

const esClientCache = { version: -1, config: false, client: false, index: false };

const getESClient = async () => {
    const documentStoreVersion = (await settings.get('documentStoreVersion')) || 0;
    if (esClientCache.version === documentStoreVersion) {
        return esClientCache;
    }

    let documentStoreEnabled = await settings.get('documentStoreEnabled');
    let documentStoreUrl = await settings.get('documentStoreUrl');

    if (!documentStoreEnabled || !documentStoreUrl) {
        esClientCache.version = documentStoreVersion;
        esClientCache.client = false;
        esClientCache.index = false;
        return esClientCache;
    }

    esClientCache.index = (await settings.get('documentStoreIndex')) || 'emailengine';

    let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
    let documentStoreUsername = await settings.get('documentStoreUsername');
    let documentStorePassword = await settings.get('documentStorePassword');

    esClientCache.config = {
        node: { url: new URL(documentStoreUrl), tls: { rejectUnauthorized: false } },
        auth:
            documentStoreAuthEnabled && documentStoreUsername
                ? {
                      username: documentStoreUsername,
                      password: documentStorePassword
                  }
                : false
    };

    esClientCache.version = documentStoreVersion;
    esClientCache.client = new ElasticSearch(esClientCache.config);

    return esClientCache;
};

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T2]');
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

async function notify(cmd, data) {
    parentPort.postMessage({
        cmd,
        data
    });
}

async function sendWebhook(account, event, data) {
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

    let queueKeep = (await settings.get('queueKeep')) || true;
    await notifyQueue.add(event, payload, {
        removeOnComplete: queueKeep,
        removeOnFail: queueKeep,
        attempts: 10,
        backoff: {
            type: 'exponential',
            delay: 5000
        }
    });
}

async function onCommand(command) {
    logger.debug({ msg: 'Unhandled command', command });
}

function publishChangeEvent(data) {
    let { account, type, key, payload } = data;

    for (let stream of registeredPublishers) {
        try {
            stream.sendMessage({ account, type, key, payload });
        } catch (err) {
            logger.error({ msg: 'Failed to publish change event', err, account, type, key, payload });
        }
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

    if (message && message.cmd === 'change') {
        publishChangeEvent(message);
    }
});

const init = async () => {
    const server = Hapi.server({
        port: API_PORT,
        host: API_HOST,

        router: {
            stripTrailingSlash: true
        }
    });

    server.decorate('toolkit', 'getESClient', async () => await getESClient());

    server.ext('onRequest', async (request, h) => {
        // check if client IP is resolved from X-Forwarded-For or not
        let enableApiProxy = (await settings.get('enableApiProxy')) || false;
        if (enableApiProxy) {
            // check for the IP address from the Forwarded-For header
            const xFF = request.headers['x-forwarded-for'];
            request.app.ip = xFF ? xFF.split(',')[0] : request.info.remoteAddress;
        } else {
            // use socket address
            request.app.ip = request.info.remoteAddress;
        }

        // check if access tokens for api requests are required
        let disableTokens = await settings.get('disableTokens');
        if (disableTokens && !request.url.searchParams.get('access_token')) {
            // make sure that we have a access_token value set in query args
            let url = new URL(request.url.href);
            url.searchParams.set('access_token', 'preauth');
            request.setUrl(`${url.pathname}${url.search}`);
        }

        // make license info available for the request
        request.app.licenseInfo = await call({ cmd: 'license' });

        // flash notifications
        request.flash = async message => await flash(redis, request, message);

        return h.continue;
    });

    const swaggerOptions = {
        swaggerUI: true,
        swaggerUIPath: '/admin/iframe/swagger/',
        documentationPage: true,
        documentationPath: '/admin/iframe/docs',

        grouping: 'tags',

        //auth: 'api-token',

        info: {
            title: 'EmailEngine',
            version: packageData.version,
            contact: {
                name: 'Postal Systems OÜ',
                email: 'info@emailengine.app'
            },
            description: `You will need an Access Token to use this API (generate one <a href="/admin/tokens" target="_parent">here</a>).

When making API calls remember that requests against the same account are queued and not executed in parallel. If a previous request takes too much time to finish, a queued request might time out before EmailEngine can run it.`
        },

        securityDefinitions: {
            bearerAuth: {
                type: 'apiKey',
                //scheme: 'bearer',
                name: 'access_token',
                in: 'query'
            }
        },
        security: [{ bearerAuth: [] }]
    };

    await server.register(AuthBearer);

    // Authentication for API calls
    server.auth.strategy('api-token', 'bearer-access-token', {
        allowQueryToken: true, // optional, false by default
        validate: async (request, token /*, h*/) => {
            let disableTokens = await settings.get('disableTokens');
            if (disableTokens) {
                // tokens check are disabled, allow all
                return {
                    isValid: true,
                    credentials: {},
                    artifacts: {}
                };
            }

            let scope = false;
            let tags = (request.route && request.route.settings && request.route.settings.tags) || [];
            if (tags.includes('api')) {
                scope = 'api';
            } else {
                for (let tag of tags) {
                    if (/^scope:/.test(tag)) {
                        scope = tag.substr('scope:'.length);
                    }
                }
            }

            let tokenData;
            try {
                tokenData = await tokens.get(token, false, { log: true, remoteAddress: request.app.ip });
            } catch (err) {
                return {
                    isValid: false,
                    credentials: {},
                    artifacts: { err: err.message }
                };
            }

            if (scope && tokenData.scopes && !tokenData.scopes.includes(scope) && !tokenData.scopes.includes('*')) {
                // failed scope validation
                logger.error({
                    msg: 'Trying to use invalid scope for a token',
                    tokenAccount: tokenData.account,
                    tokenId: tokenData.id,
                    requestedScope: scope,
                    tokenScopes: tokenData.scopes
                });

                return {
                    isValid: false,
                    credentials: { token },
                    artifacts: { err: 'Unauthorized scope' }
                };
            }

            if (tokenData.account) {
                // account token
                if (!request.params || request.params.account !== tokenData.account) {
                    logger.error({
                        msg: 'Trying to use invalid account for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account: (request.params && request.params.account) || null
                    });
                    return {
                        isValid: false,
                        credentials: { token },
                        artifacts: { err: 'Unauthorized account' }
                    };
                }
            }

            if (tokenData.restrictions) {
                if (tokenData.restrictions.addresses && !tokenData.restrictions.addresses.includes(request.app.ip)) {
                    logger.error({
                        msg: 'Trying to use invalid account for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account: (request.params && request.params.account) || null,
                        remoteAddress: request.app.ip,
                        addressAllowlist: tokenData.restrictions.addresses
                    });

                    return {
                        isValid: false,
                        credentials: { token },
                        artifacts: { err: 'Unauthorized address' }
                    };
                }

                if (
                    tokenData.restrictions.referrers &&
                    tokenData.restrictions.referrers.length &&
                    !matcher(tokenData.restrictions.referrers, request.headers.referer)
                ) {
                    logger.error({
                        msg: 'Trying to use invalid referer for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account: (request.params && request.params.account) || null,
                        referer: request.headers.referer,
                        referrerAllowlist: tokenData.restrictions.referrers
                    });

                    return {
                        isValid: false,
                        credentials: { token },
                        artifacts: { err: 'Unauthorized referrer' }
                    };
                }
            }

            return { isValid: true, credentials: { token }, artifacts: tokenData };
        }
    });

    // needed for auth session and flash messages
    await server.register(Cookie);

    // Authentication for admin pages
    server.auth.strategy('session', 'cookie', {
        cookie: {
            name: 'ee',
            password: await settings.get('cookiePassword'),
            isSecure: false,
            path: '/',
            clearInvalid: true
        },
        appendNext: true,
        redirectTo: '/admin/login',
        validateFunc: async (request, session) => {
            const authData = await settings.get('authData');
            if (!authData) {
                return { valid: true, credentials: { enabled: false } };
            }

            const account = authData.user === session.user;

            if (!account) {
                return { valid: false };
            }

            return {
                valid: true,
                credentials: {
                    enabled: true,
                    user: authData.user
                },
                artifacts: authData
            };
        }
    });

    const authData = await settings.get('authData');
    if (authData) {
        server.auth.default('session');
    }

    await server.register({
        plugin: hapiPino,
        options: {
            instance: logger.child({ component: 'api' }, { redact: REDACTED_KEYS }),
            // Redact Authorization headers, see https://getpino.io/#/docs/redaction
            redact: REDACTED_KEYS
        }
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: swaggerOptions
        }
    ]);

    server.events.on('response', request => {
        if (!/^\/v1\//.test(request.route.path)) {
            // only log API calls
            return;
        }
        metrics(logger, 'apiCall', 'inc', {
            method: request.method,
            route: request.route.path,
            statusCode: request.response && request.response.statusCode
        });
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'static', 'index.html'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/favicon.ico',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'static', 'favicon.ico'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/licenses.html',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'static', 'licenses.html'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/LICENSE.txt',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'LICENSE.txt'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/LICENSE_EMAILENGINE.txt',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/robots.txt',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'static', 'robots.txt'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/static/{file*}',
        handler: {
            directory: {
                path: pathlib.join(__dirname, '..', 'static')
            }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/health',
        async handler() {
            const imapWorkerCount = await call({ cmd: 'imapWorkerCount' });
            if (imapWorkerCount < IMAP_WORKER_COUNT) {
                let error = Boom.boomify(new Error('Not all IMAP workers available'), { statusCode: 500 });
                throw error;
            }

            let checkKey = `test:${Date.now()}`;
            let expected = crypto.randomBytes(8).toString('hex');
            let res = await redis.multi().set(checkKey, expected).get(checkKey).del(checkKey).exec();
            if (res[1] && res[1][1] === expected && res[2] && res[2][1] === 1) {
                return { success: true };
            }
            let error = Boom.boomify(new Error('Database check failed'), { statusCode: 500 });
            throw error;
        },
        options: {
            description: 'Health check',
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/redirect',
        async handler(request, h) {
            let data = Buffer.from(request.query.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.query.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);
            if (!data || !data.url || data.act !== 'click') {
                let error = Boom.boomify(new Error('Invalid query'), { statusCode: 403 });
                throw error;
            }

            if (!data.url) {
                let error = Boom.boomify(new Error('Missing URL'), { statusCode: 403 });
                throw error;
            }

            await sendWebhook(data.acc, TRACK_CLICK_NOTIFY, {
                messageId: data.msg,
                url: data.url,
                remoteAddress: request.info.remoteAddress,
                userAgent: request.headers['user-agent']
            });

            return h.redirect(data.url);
        },
        options: {
            description: 'Click tracking redirect',

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true })
                })
            },

            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/open.gif',
        async handler(request, h) {
            // TODO: track an open

            let data = Buffer.from(request.query.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.query.sig) {
                    let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                    throw error;
                }
            }

            data = JSON.parse(data);
            if (!data || data.act !== 'open') {
                let error = Boom.boomify(new Error('Invalid query'), { statusCode: 403 });
                throw error;
            }

            await sendWebhook(data.acc, TRACK_OPEN_NOTIFY, {
                messageId: data.msg,
                remoteAddress: request.info.remoteAddress,
                userAgent: request.headers['user-agent']
            });

            // respond with a static image file
            return h
                .response(TRACKER_IMAGE)
                .header('Content-Type', 'image/gif')
                .header('Content-Disposition', 'inline; filename="open.gif"')
                .header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0')
                .header('Pragma', 'no-cache')
                .code(200);
        },
        options: {
            description: 'Open tracking image',

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true })
                })
            },

            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/oauth',
        async handler(request, h) {
            if (request.query.error) {
                let error = Boom.boomify(new Error(`Oauth failed: ${request.query.error}`), { statusCode: 400 });
                throw error;
            }

            if (!request.query.code) {
                // throw
                let error = Boom.boomify(new Error(`Oauth failed: node code received`), { statusCode: 400 });
                throw error;
            }

            if (!/^account:add:/.test(request.query.state)) {
                let error = Boom.boomify(new Error(`Oauth failed: invalid state received`), { statusCode: 400 });
                throw error;
            }

            let [[, accountData]] = await redis.multi().get(`${REDIS_PREFIX}${request.query.state}`).del(`${REDIS_PREFIX}${request.query.state}`).exec();
            if (!accountData) {
                let error = Boom.boomify(new Error(`Oauth failed: session expired`), { statusCode: 400 });
                throw error;
            }

            try {
                accountData = JSON.parse(accountData);
            } catch (E) {
                let error = Boom.boomify(new Error(`Oauth failed: invalid session`), { statusCode: 400 });
                throw error;
            }

            const accountMeta = accountData._meta || {};
            delete accountData._meta;

            const redirectUrl = accountMeta.redirectUrl;

            const provider = accountData.oauth2.provider;

            const oAuth2Client = await getOAuth2Client(provider);

            switch (provider) {
                case 'gmail': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    let profileRes;
                    try {
                        profileRes = await oAuth2Client.request(r.access_token, 'https://gmail.googleapis.com/gmail/v1/users/me/profile');
                    } catch (err) {
                        let response = err.oauthRequest && err.oauthRequest.response;
                        if (response && response.error) {
                            let message;
                            if (/Gmail API has not been used in project/.test(response.error.message)) {
                                message =
                                    'Can not perform requests against Gmail API as the project has not been enabled. If you are the admin, check notifications on the dashboard.';
                            } else {
                                message = response.error.message;
                            }

                            let error = Boom.boomify(new Error(message), { statusCode: response.error.code });
                            throw error;
                        }
                        throw err;
                    }

                    if (!profileRes || !profileRes || !profileRes.emailAddress) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    accountData.email = accountData.email || (isEmail(profileRes.emailAddress) ? profileRes.emailAddress : '');

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : GMAIL_SCOPES,
                            tokenType: r.token_type
                        },
                        {
                            auth: {
                                user: profileRes.emailAddress
                            }
                        }
                    );
                    break;
                }

                case 'outlook': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    let userInfo = {};

                    let clientInfo = request.query.client_info ? JSON.parse(Buffer.from(request.query.client_info, 'base64url').toString()) : false;

                    if (clientInfo && typeof clientInfo.name === 'string') {
                        userInfo.name = clientInfo.name;
                    }

                    if (clientInfo && clientInfo.preferred_username && isEmail(clientInfo.preferred_username)) {
                        userInfo.email = clientInfo.preferred_username;
                    }

                    if (r.id_token && typeof r.id_token === 'string') {
                        let [, encodedValue] = r.id_token.split('.');
                        if (encodedValue) {
                            try {
                                let decodedValue = JSON.parse(Buffer.from(encodedValue, 'base64url').toString());
                                if (decodedValue && typeof decodedValue.name === 'string') {
                                    userInfo.name = decodedValue.name;
                                }

                                if (decodedValue && typeof decodedValue.email === 'string' && isEmail(decodedValue.email)) {
                                    userInfo.email = decodedValue.email;
                                }

                                if (decodedValue && typeof decodedValue.preferred_username === 'string' && isEmail(decodedValue.preferred_username)) {
                                    userInfo.email = decodedValue.preferred_username;
                                }
                            } catch (err) {
                                request.logger.error({ msg: 'Failed to decode JWT payload', err, encodedValue });
                            }
                        }
                    }

                    if (!userInfo.email) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    accountData.name = accountData.name || userInfo.name || '';
                    accountData.email = accountData.email || userInfo.email;

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : OUTLOOK_SCOPES,
                            tokenType: r.token_type
                        },
                        {
                            auth: {
                                user: userInfo.email
                            }
                        }
                    );
                    break;
                }

                case 'mailRu': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    let profileRes;
                    try {
                        profileRes = await oAuth2Client.request(r.access_token, 'https://oauth.mail.ru/userinfo');
                    } catch (err) {
                        let response = err.oauthRequest && err.oauthRequest.response;
                        if (response && response.error) {
                            let message = response.error.message;
                            let error = Boom.boomify(new Error(message), { statusCode: response.error.code });
                            throw error;
                        }
                        throw err;
                    }

                    if (!profileRes || !profileRes || !profileRes.email) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    accountData.name = accountData.name || profileRes.name || '';
                    accountData.email = accountData.email || (isEmail(profileRes.email) ? profileRes.email : '');

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : MAIL_RU_SCOPES,
                            tokenType: r.token_type
                        },
                        {
                            auth: {
                                user: profileRes.email
                            }
                        }
                    );
                    break;
                }

                default: {
                    throw new Error('Unknown OAuth2 provider');
                }
            }

            let accountObject = new Account({ redis, call, secret: await getSecret() });
            let result = await accountObject.create(accountData);

            let httpRedirectUrl;
            if (redirectUrl) {
                let serviceUrl = await settings.get('serviceUrl');
                let url = new URL(redirectUrl, serviceUrl);
                url.searchParams.set('account', result.account);
                url.searchParams.set('state', result.state);
                httpRedirectUrl = url.href;
            } else {
                httpRedirectUrl = `/admin/accounts/${result.account}`;
            }

            // have to use HTML redirect, otherwise samesite=strict cookies are not passed on
            return h.view(
                'redirect',
                { httpRedirectUrl },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            description: 'OAuth2 response endpoint',

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    state: Joi.string()
                        .empty('')
                        .max(100 * 1024)
                        .example('account:add:12345')
                        .description('OAuth2 state info'),
                    code: Joi.string()
                        .empty('')
                        .max(100 * 1024)
                        .example('67890...')
                        .description('OAuth2 setup code'),
                    scope: Joi.string()
                        .empty('')
                        .max(100 * 1024)
                        .example('https://mail.google.com/')
                        .description('OAuth2 scopes'),
                    client_info: Joi.string()
                        .empty('')
                        .max(1024 * 1024)
                        .base64({ urlSafe: true, paddingRequired: false })
                        .description('Outlook client info'),
                    error: Joi.string()
                        .empty('')
                        .max(100 * 1024)
                        .example('access_denied')
                        .description('OAuth2 Error')
                }).label('CreateAccount')
            },

            auth: false
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/token',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.payload.account, call, secret: await getSecret() });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();

                let token = await tokens.provision(Object.assign({}, request.payload, { remoteAddress: request.app.ip }));

                return { token };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'Provision an access token',
            notes: 'Provisions a new access token for an account',
            tags: ['api', 'token'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),

                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),

                    metadata: Joi.string()
                        .empty('')
                        .max(1024 * 1024)
                        .custom((value, helpers) => {
                            try {
                                // check if parsing fails
                                JSON.parse(value);
                                return value;
                            } catch (err) {
                                return helpers.message('Metadata must be a valid JSON string');
                            }
                        })
                        .example('{"example": "value"}')
                        .description('Related metadata in JSON format')
                        .label('JsonMetaData'),

                    restrictions: Joi.object()
                        .keys({
                            referrers: Joi.array()
                                .items(Joi.string())
                                .empty('')
                                .allow(false)
                                .default(false)
                                .example(['*web.domain.org/*', '*.domain.org/*', 'https://domain.org/*'])
                                .label('ReferrerAllowlist')
                                .description('HTTP referrer allowlist'),
                            addresses: Joi.array()
                                .items(
                                    Joi.string().ip({
                                        version: ['ipv4', 'ipv6'],
                                        cidr: 'forbidden'
                                    })
                                )
                                .empty('')
                                .allow(false)
                                .default(false)
                                .example(['1.2.3.4', '5.6.7.8'])
                                .label('AddressAllowlist')
                                .description('IP address allowlist')
                        })
                        .empty('')
                        .allow(false)
                        .label('TokenRestrictions')
                        .description('Access restrictions'),

                    ip: Joi.string()
                        .empty('')
                        .trim()
                        .ip({
                            version: ['ipv4', 'ipv6'],
                            cidr: 'forbidden'
                        })
                        .example('127.0.0.1')
                        .description('IP address of the requestor')
                }).label('CreateToken')
            },

            response: {
                schema: Joi.object({
                    token: Joi.string().length(64).hex().required().example('123456').description('Access token')
                }).label('CreateTokenResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/token/{token}',

        async handler(request) {
            try {
                return { deleted: await tokens.delete(request.params.token, { remoteAddress: request.app.ip }) };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Remove a token',
            notes: 'Delete an access token',
            tags: ['api', 'token'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    token: Joi.string().length(64).hex().required().example('123456').description('Access token')
                }).label('DeleteTokenRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteTokenRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens',

        async handler() {
            try {
                return { tokens: await tokens.list() };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'List root tokens',
            notes: 'Lists access tokens registered for root access',
            tags: ['api', 'token'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: Joi.string().max(256).required().example('example').description('Account ID'),
                                description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                                metadata: Joi.string()
                                    .empty('')
                                    .max(1024 * 1024)
                                    .custom((value, helpers) => {
                                        try {
                                            // check if parsing fails
                                            JSON.parse(value);
                                            return value;
                                        } catch (err) {
                                            return helpers.message('Metadata must be a valid JSON string');
                                        }
                                    })
                                    .example('{"example": "value"}')
                                    .description('Related metadata in JSON format')
                                    .label('JsonMetaData'),
                                ip: Joi.string()
                                    .empty('')
                                    .trim()
                                    .ip({
                                        version: ['ipv4', 'ipv6'],
                                        cidr: 'forbidden'
                                    })
                                    .example('127.0.0.1')
                                    .description('IP address of the requestor')
                            }).label('AccountResponseItem')
                        )
                        .label('AccountEntries')
                }).label('AccountsFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/account/{account}',

        async handler(request) {
            try {
                return { tokens: await tokens.list(request.params.account) };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'List account tokens',
            notes: 'Lists access tokens registered for an account',
            tags: ['api', 'token'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,
                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: Joi.string().max(256).required().example('example').description('Account ID'),
                                description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                                metadata: Joi.string()
                                    .empty('')
                                    .max(1024 * 1024)
                                    .custom((value, helpers) => {
                                        try {
                                            // check if parsing fails
                                            JSON.parse(value);
                                            return value;
                                        } catch (err) {
                                            return helpers.message('Metadata must be a valid JSON string');
                                        }
                                    })
                                    .example('{"example": "value"}')
                                    .description('Related metadata in JSON format')
                                    .label('JsonMetaData'),

                                restrictions: Joi.object()
                                    .keys({
                                        referrers: Joi.array()
                                            .items(Joi.string())
                                            .empty('')
                                            .allow(false)
                                            .default(false)
                                            .example(['*web.domain.org/*', '*.domain.org/*', 'https://domain.org/*'])
                                            .label('ReferrerAllowlist')
                                            .description('HTTP referrer allowlist'),
                                        addresses: Joi.array()
                                            .items(
                                                Joi.string().ip({
                                                    version: ['ipv4', 'ipv6'],
                                                    cidr: 'forbidden'
                                                })
                                            )
                                            .empty('')
                                            .allow(false)
                                            .default(false)
                                            .example(['1.2.3.4', '5.6.7.8'])
                                            .label('AddressAllowlist')
                                            .description('IP address allowlist')
                                    })
                                    .empty('')
                                    .allow(false)
                                    .label('TokenRestrictions')
                                    .description('Access restrictions'),

                                ip: Joi.string()
                                    .empty('')
                                    .trim()
                                    .ip({
                                        version: ['ipv4', 'ipv6'],
                                        cidr: 'forbidden'
                                    })
                                    .example('127.0.0.1')
                                    .description('IP address of the requestor')
                            }).label('AccountResponseItem')
                        )
                        .label('AccountEntries')
                }).label('AccountsFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account',

        async handler(request) {
            let accountObject = new Account({ redis, call, secret: await getSecret() });

            try {
                if (request.payload.oauth2 && request.payload.oauth2.authorize) {
                    // redirect to OAuth2 consent screen

                    const oAuth2Client = await getOAuth2Client(request.payload.oauth2.provider);
                    let nonce = crypto.randomBytes(12).toString('hex');

                    delete request.payload.oauth2.authorize; // do not store this property
                    // store account data
                    await redis
                        .multi()
                        .set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(request.payload))
                        .expire(`${REDIS_PREFIX}account:add:${nonce}`, 1 * 24 * 3600)
                        .exec();

                    // Generate the url that will be used for the consent dialog.
                    let authorizeUrl;
                    switch (request.payload.oauth2.provider) {
                        case 'gmail': {
                            let requestData = {
                                state: `account:add:${nonce}`
                            };

                            if (request.payload.email) {
                                requestData.email = request.payload.email;
                            }

                            authorizeUrl = oAuth2Client.generateAuthUrl(requestData);

                            break;
                        }

                        case 'outlook':
                        case 'mailRu':
                            authorizeUrl = oAuth2Client.generateAuthUrl({
                                state: `account:add:${nonce}`
                            });
                            break;

                        default: {
                            let error = Boom.boomify(new Error('Unknown OAuth provider'), { statusCode: 400 });
                            throw error;
                        }
                    }

                    return {
                        redirect: authorizeUrl
                    };
                }

                let result = await accountObject.create(request.payload);
                return result;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'Register new account',
            notes: 'Registers new IMAP account to be synced',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string()
                        .empty('')
                        .max(256)
                        .allow(null)
                        .required()
                        .example('example')
                        .description('Account ID. If null then will be autogenerated'),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: Joi.string().empty('').max(1024).default('*').example('INBOX').description('Check changes only on selected path'),

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean().allow(null).example(true).description('Copy submitted messages to Sent folder. Set to `null` to unset.'),
                    logs: Joi.boolean().example(true).description('Store recent logs').default(false),

                    notifyFrom: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Notify messages from date').default('now'),

                    proxy: settingsSchema.proxyUrl,

                    imap: Joi.object(imapSchema).allow(false).xor('useAuthServer', 'auth').description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP'),

                    oauth2: Joi.object(oauth2Schema).xor('authorize', 'auth').allow(false).description('OAuth2 configuration').label('OAuth2')
                }).label('CreateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    state: Joi.string().required().valid('existing', 'new').example('new').description('Is the account new or updated existing')
                }).label('CreateAccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.update(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Update account info',
            notes: 'Updates account information',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: Joi.string().empty('').max(1024).default('*').example('INBOX').description('Check changes only on selected path'),

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean().allow(null).example(true).description('Copy submitted messages to Sent folder. Set to `null` to unset.'),
                    logs: Joi.boolean().example(true).description('Store recent logs'),

                    notifyFrom: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Notify messages from date'),

                    proxy: settingsSchema.proxyUrl,

                    imap: Joi.object(imapUpdateSchema).allow(false).oxor('useAuthServer', 'auth').description('IMAP configuration').label('IMAPUpdate'),
                    smtp: Joi.object(smtpUpdateSchema).allow(false).oxor('useAuthServer', 'auth').description('SMTP configuration').label('SMTPUpdate'),
                    oauth2: Joi.object(oauth2UpdateSchema).xor('authorize', 'auth').allow(false).description('OAuth2 configuration').label('OAuth2Update')
                }).label('UpdateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('UpdateAccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/reconnect',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return { reconnect: await accountObject.requestReconnect(request.payload) };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Request reconnect',
            notes: 'Requests connection to be reconnected',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnect')
            },

            response: {
                schema: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Reconnection status')
                }).label('RequestReconnectResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/sync',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return { sync: await accountObject.requestSync(request.payload) };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Request syncing',
            notes: 'Requests account syncing to be run immediatelly',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    sync: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only sync if true')
                }).label('RequestSync')
            },

            response: {
                schema: Joi.object({
                    sync: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Sync status')
                }).label('RequestSyncResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                documentsQeueue,
                call,
                secret: await getSecret()
            });

            try {
                return await accountObject.delete();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Remove synced account',
            notes: 'Stop syncing IMAP account and delete cached values',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('DeleteRequest')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/accounts',

        async handler(request) {
            try {
                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

                return await accountObject.listAccounts(request.query.state, request.query.page, request.query.pageSize);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'List accounts',
            notes: 'Lists registered accounts',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    state: Joi.string()
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState')
                }).label('AccountsFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),

                    accounts: Joi.array()
                        .items(
                            Joi.object({
                                account: Joi.string().max(256).required().example('example').description('Account ID'),
                                name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                                email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),
                                state: Joi.string()
                                    .required()
                                    .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                                    .example('connected')
                                    .description('Account state'),
                                syncTime: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last sync time'),
                                lastError: lastErrorSchema.allow(null)
                            }).label('AccountResponseItem')
                        )
                        .label('AccountEntries')
                }).label('AccountsFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            try {
                let accountData = await accountObject.loadAccountData();

                // remove secrets
                for (let type of ['imap', 'smtp', 'oauth2']) {
                    if (accountData[type] && accountData[type].auth) {
                        for (let key of ['pass', 'accessToken', 'refreshToken']) {
                            if (key in accountData[type].auth) {
                                accountData[type].auth[key] = '******';
                            }
                        }
                    }

                    if (accountData[type]) {
                        for (let key of ['accessToken', 'refreshToken']) {
                            if (key in accountData[type]) {
                                accountData[type][key] = '******';
                            }
                        }
                    }
                }

                let result = {};

                for (let key of ['account', 'name', 'email', 'copy', 'notifyFrom', 'imap', 'smtp', 'oauth2', 'state', 'smtpStatus']) {
                    if (key in accountData) {
                        result[key] = accountData[key];
                    }
                }

                if (accountData.sync) {
                    result.syncTime = accountData.sync;
                }

                if (accountData.state) {
                    result.lastError = accountData.state === 'connected' ? null : accountData.lastErrorState;
                }

                return result;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Get account info',
            notes: 'Returns stored information about the account. Passwords are not included.',
            tags: ['api', 'account'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder'),
                    logs: Joi.boolean().example(true).description('Store recent logs'),

                    notifyFrom: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Notify messages from date'),

                    proxy: settingsSchema.proxyUrl,

                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).description('SMTP configuration').label('SMTP'),

                    lastError: lastErrorSchema.allow(null)
                }).label('AccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/mailboxes',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return { mailboxes: await accountObject.getMailboxListing() };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'List mailboxes',
            notes: 'Lists all available mailboxes',
            tags: ['api', 'mailbox'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    mailboxes: mailboxesSchema
                }).label('MailboxesFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.createMailbox(request.payload.path);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'Create mailbox',
            notes: 'Create new mailbox folder',
            tags: ['api', 'mailbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).example('example').required().description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.array()
                        .items(Joi.string().max(256))
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array. If account is namespaced then namespace prefix is added by default.')
                        .label('MailboxPath')
                }).label('CreateMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    mailboxId: Joi.string().example('1439876283476').description('Mailbox ID (if server has support)').label('MailboxId'),
                    created: Joi.boolean().example(true).description('Was the mailbox created')
                }).label('CreateMailboxResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.deleteMailbox(request.query.path);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'Delete mailbox',
            notes: 'Delete existing mailbox folder',
            tags: ['api', 'mailbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('My Outdated Mail').description('Mailbox folder path to delete').label('MailboxPath')
                }).label('DeleteMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    deleted: Joi.boolean().example(true).description('Was the mailbox deleted')
                }).label('DeleteMailboxResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}/source',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.getRawMessage(request.params.message);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Download raw message',
            notes: 'Fetches raw message as a stream',
            tags: ['api', 'message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).example('AAAAAQAACnA').required().description('Message ID')
                }).label('RawMessageRequest')
            } /*,

            response: {
                schema: Joi.binary().example('MIME-Version: 1.0...').description('RFC822 formatted email').label('RawMessageResponse'),
                failAction: 'log'
            }
            */
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/attachment/{attachment}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.getAttachment(request.params.attachment);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Download attachment',
            notes: 'Fetches attachment file as a binary stream',
            tags: ['api', 'message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    attachment: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcde')
                        .description('Attachment ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                if (request.query.documentStore) {
                    let documentStoreEnabled = await settings.get('documentStoreEnabled');
                    if (!documentStoreEnabled) {
                        let error = Boom.boomify(new Error('Document store is not enabled'), { statusCode: 503 });
                        error.output.payload.code = 'DisabledDocumentStore';
                        throw error;
                    }

                    const { index, client } = await getESClient();

                    const reqOpts = {
                        index,
                        id: `${request.params.account}:${request.params.message}`
                    };

                    switch (request.query.textType) {
                        case '*':
                            break;
                        case 'html':
                            reqOpts._source_excludes = 'text.plain';
                            break;
                        case 'plain':
                            reqOpts._source_excludes = 'text.html';
                            break;
                        default:
                            reqOpts._source_excludes = 'text.plain,text.html';
                    }

                    let getResult = await client.get(reqOpts);

                    if (!getResult || !getResult._source) {
                        let message = 'Requested message was not found';
                        let error = Boom.boomify(new Error(message), { statusCode: 404 });
                        throw error;
                    }

                    let messageData = getResult._source;

                    // restore headers and text object as per the API response
                    let headersObj = {};
                    for (let { key, value } of messageData.headers) {
                        headersObj[key] = value;
                    }
                    messageData.headers = headersObj;

                    if (messageData.text && (messageData.text.html || messageData.text.plain)) {
                        messageData.text.hasMore = false;
                    }

                    for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                        if (messageData[key] === false) {
                            messageData[key] = undefined;
                        }
                    }

                    for (let key of ['account', 'created', 'specialUse']) {
                        if (messageData[key]) {
                            messageData[key] = undefined;
                        }
                    }

                    return messageData;
                } else {
                    // regular IMAP request
                    return await accountObject.getMessage(request.params.message, request.query);
                }
            } catch (err) {
                request.logger.error({ msg: 'Request processing failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Get message information',
            notes: 'Returns details of a specific message. By default text content is not included, use textType value to force retrieving text',
            tags: ['api', 'message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(5 * 1025 * 1024)
                        .description('Max length of text content. This setting is ignored if `documentStore` is `true`.'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default text content is not returned.'),
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch the data from the Document Store instead of IMAP')
                        .label('UseDocumentStore')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).required().example('AAAAAQAACnA').description('Message ID')
                })
            },

            response: {
                schema: messageDetailsSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/message',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.uploadMessage(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Upload message',
            notes: 'Upload a message structure, compile it into an EML file and store it into selected mailbox.',
            tags: ['api', 'message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    flags: Joi.array().items(Joi.string().max(128)).example(['\\Seen', '\\Draft']).default([]).description('Message flags').label('Flags'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is EmailEngine specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    from: addressSchema.required().example({ name: 'From Me', address: 'sender@example.com' }),

                    to: Joi.array()
                        .items(addressSchema)
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers')
                }).label('MessageUpload')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string()
                        .example('AAAAAgAACrI')
                        .description('Message ID. NB! This and other fields might not be present if server did not provide enough information')
                        .label('MessageAppendId'),
                    path: Joi.string().example('INBOX').description('Folder this message was uploaded to').label('MessageAppendPath'),
                    uid: Joi.number().example(12345).description('UID of uploaded message'),
                    seq: Joi.number().example(12345).description('Sequence number of uploaded message')
                }).label('MessageUploadResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.updateMessage(request.params.message, request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Update message',
            notes: 'Update message information. Mainly this means changing message flag values',
            tags: ['api', 'message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    flags: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new flags').example(['\\Seen']).label('AddFlags'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific flags').example(['\\Flagged']).label('DeleteFlags'),
                        set: Joi.array().items(Joi.string().max(128)).description('Override all flags').example(['\\Seen', '\\Flagged']).label('SetFlags')
                    })
                        .description('Flag updates')
                        .label('FlagUpdate'),

                    labels: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new labels').example(['Some label']).label('AddLabels'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific labels').example(['Some label']).label('DeleteLabels'),
                        set: Joi.array()
                            .items(Joi.string().max(128))
                            .description('Override all labels')
                            .example(['First label', 'Second label'])
                            .label('SetLabels')
                    })
                        .description('Label updates')
                        .label('LabelUpdate')
                }).label('MessageUpdate')
            },
            response: {
                schema: Joi.object({
                    flags: Joi.object({
                        add: Joi.boolean().example(true),
                        delete: Joi.boolean().example(false),
                        set: Joi.boolean().example(false)
                    }).label('FlagResponse'),
                    labels: Joi.object({
                        add: Joi.boolean().example(true),
                        delete: Joi.boolean().example(false),
                        set: Joi.boolean().example(false)
                    }).label('FlagResponse')
                }).label('MessageUpdateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}/move',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.moveMessage(request.params.message, request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Move message',
            notes: 'Move message to another folder',
            tags: ['api', 'message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path')
                }).label('MessageMove')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),
                    id: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID'),
                    uid: Joi.number().example(12345).description('UID of moved message')
                }).label('MessageMoveResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.deleteMessage(request.params.message, request.query.force);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Delete message',
            notes: 'Move message to Trash or delete it if already in Trash',
            tags: ['api', 'message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Delete message even if not in Trash')
                        .label('ForceDelete')
                }).label('MessageDeleteQuery'),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }).label('MessageDelete')
            },
            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(true).description('Present if message was actually deleted'),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),
                        message: Joi.string().required().example('AAAAAwAAAWg').description('Message ID in Trash').label('TrashMessageId')
                    }).description('Present if message was moved to Trash')
                }).label('MessageDeleteResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/text/{text}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                if (request.query.documentStore) {
                    let documentStoreEnabled = await settings.get('documentStoreEnabled');
                    if (!documentStoreEnabled) {
                        let error = Boom.boomify(new Error('Document store is not enabled'), { statusCode: 503 });
                        error.output.payload.code = 'DisabledDocumentStore';
                        throw error;
                    }

                    let buf = Buffer.from(request.params.text, 'base64url');
                    let message = buf.slice(0, 8).toString('base64url');

                    const { index, client } = await getESClient();
                    let getResult = await client.get({
                        index,
                        id: `${request.params.account}:${message}`
                    });

                    if (!getResult || !getResult._source) {
                        let message = 'Requested message was not found';
                        let error = Boom.boomify(new Error(message), { statusCode: 404 });
                        throw error;
                    }

                    let messageData = getResult._source;
                    let response = {};
                    for (let textType of Object.keys(messageData.text || {})) {
                        if (['plain', 'html'].includes(textType) && (request.query.textType === '*' || request.query.textType === textType)) {
                            response[textType] = messageData.text[textType];
                        }
                    }
                    response.hasMore = false;

                    return response;
                } else {
                    return await accountObject.getText(request.params.text, request.query);
                }
            } catch (err) {
                request.logger.error({ msg: 'Request processing failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Retrieve message text',
            notes: 'Retrieves message text',
            tags: ['api', 'message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(MAX_ATTACHMENT_SIZE)
                        .description('Max length of text content. This setting is ignored if `documentStore` is `true`.'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .default('*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default all contents are returned.'),
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch the data from the Document Store instead of IMAP')
                        .label('UseDocumentStore')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    text: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcdfaaN')
                        .description('Message text ID')
                }).label('Text')
            },

            response: {
                schema: Joi.object({
                    plain: Joi.string().example('Hello world').description('Plaintext content'),
                    html: Joi.string().example('<p>Hello world</p>').description('HTML content'),
                    hasMore: Joi.boolean().example(false).description('Is the current text output capped or not')
                }).label('TextResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/messages',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            try {
                if (request.query.documentStore) {
                    let documentStoreEnabled = await settings.get('documentStoreEnabled');
                    if (!documentStoreEnabled) {
                        let error = Boom.boomify(new Error('Document store is not enabled'), { statusCode: 503 });
                        error.output.payload.code = 'DisabledDocumentStore';
                        throw error;
                    }

                    let inboxData = await redis.hgetBuffer(accountObject.getMailboxListKey(), 'INBOX');
                    let delimiter;
                    if (inboxData) {
                        try {
                            inboxData = msgpack.decode(inboxData);
                            delimiter = inboxData.delimiter;
                        } catch (err) {
                            delimiter = '/'; // hope for the best
                            inboxData = false;
                        }
                    }

                    inboxData = inboxData || {
                        path: 'INBOX',
                        delimiter
                    };

                    inboxData.specialUse = inboxData.specialUse || '\\Inbox';

                    let path = normalizePath(request.query.path, delimiter);
                    let mailboxData = path === 'INBOX' ? inboxData : false;
                    if (!mailboxData) {
                        mailboxData = await redis.hgetBuffer(accountObject.getMailboxListKey(), path);
                        if (mailboxData) {
                            try {
                                mailboxData = msgpack.decode(mailboxData);
                            } catch (err) {
                                mailboxData = false;
                            }
                        }
                    }

                    let query = {
                        bool: {
                            must: [
                                {
                                    term: {
                                        account: request.params.account
                                    }
                                }
                            ]
                        }
                    };

                    query.bool.must.push({
                        bool: {
                            should: [
                                {
                                    term: {
                                        path
                                    }
                                },
                                {
                                    term: {
                                        labels: mailboxData.specialUse || path
                                    }
                                }
                            ],
                            minimum_should_match: 1
                        }
                    });

                    const { index, client } = await getESClient();
                    let searchResult = await client.search({
                        index,
                        size: request.query.pageSize,
                        from: request.query.pageSize * request.query.page,
                        query,
                        sort: { uid: 'desc' },
                        _source_excludes: 'headers,text.plain,text.html'
                    });

                    let response = {
                        total: searchResult.hits.total.value,
                        page: request.query.page,
                        pages: Math.max(Math.ceil(searchResult.hits.total.value / request.query.pageSize), 1),
                        messages: searchResult.hits.hits.map(entry => {
                            let messageData = entry._source;

                            // normalize as per the API response

                            for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                                if (messageData[key] === false) {
                                    messageData[key] = undefined;
                                }
                            }

                            for (let key of ['account', 'created', 'specialUse']) {
                                if (messageData[key]) {
                                    messageData[key] = undefined;
                                }
                            }

                            return messageData;
                        })
                    };

                    return response;
                } else {
                    return await accountObject.listMessages(request.query);
                }
            } catch (err) {
                request.logger.error({ msg: 'Request processing failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'List messages in a folder',
            notes: 'Lists messages in a mailbox folder',
            tags: ['api', 'message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID').label('AccountId')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Mailbox folder path').label('Path'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch the data from the Document Store instead of IMAP')
                        .label('UseDocumentStore')
                }).label('MessageQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/search',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            try {
                if (request.query.documentStore) {
                    let documentStoreEnabled = await settings.get('documentStoreEnabled');
                    if (!documentStoreEnabled) {
                        let error = Boom.boomify(new Error('Document store is not enabled'), { statusCode: 503 });
                        error.output.payload.code = 'DisabledDocumentStore';
                        throw error;
                    }

                    let query = {
                        bool: {
                            must: [
                                {
                                    term: {
                                        account: request.params.account
                                    }
                                }
                            ]
                        }
                    };

                    if (request.query.path) {
                        let inboxData = await redis.hgetBuffer(accountObject.getMailboxListKey(), 'INBOX');
                        let delimiter;

                        if (inboxData) {
                            try {
                                inboxData = msgpack.decode(inboxData);
                                delimiter = inboxData.delimiter;
                            } catch (err) {
                                delimiter = '/'; // hope for the best
                                inboxData = false;
                            }
                        }

                        inboxData = inboxData || {
                            path: 'INBOX',
                            delimiter
                        };

                        inboxData.specialUse = inboxData.specialUse || '\\Inbox';

                        let path = normalizePath(request.query.path, delimiter);
                        let mailboxData = path === 'INBOX' ? inboxData : false;
                        if (!mailboxData) {
                            mailboxData = await redis.hgetBuffer(accountObject.getMailboxListKey(), path);
                            if (mailboxData) {
                                try {
                                    mailboxData = msgpack.decode(mailboxData);
                                } catch (err) {
                                    mailboxData = false;
                                }
                            }
                        }

                        query.bool.must.push({
                            bool: {
                                should: [
                                    {
                                        term: {
                                            path
                                        }
                                    },
                                    {
                                        term: {
                                            labels: mailboxData.specialUse || path
                                        }
                                    }
                                ],
                                minimum_should_match: 1
                            }
                        });
                    }

                    for (let key of ['answered', 'deleted', 'draft', 'unseen', 'flagged']) {
                        if (typeof request.payload.search[key] === 'boolean') {
                            query.bool.must.push({
                                term: {
                                    [key]: request.payload.search[key]
                                }
                            });
                        }
                    }

                    if (typeof request.payload.search.seen === 'boolean') {
                        query.bool.must.push({
                            term: {
                                unseen: !request.payload.search.seen
                            }
                        });
                    }

                    for (let key of ['from', 'to', 'cc', 'bcc']) {
                        if (request.payload.search[key]) {
                            query.bool.must.push({
                                bool: {
                                    should: [
                                        {
                                            match: {
                                                [`${key}.name`]: {
                                                    query: request.payload.search[key]
                                                }
                                            }
                                        },
                                        {
                                            term: {
                                                [`${key}.address`]: request.payload.search[key]
                                            }
                                        }
                                    ],
                                    minimum_should_match: 1
                                }
                            });
                        }
                    }

                    if (request.payload.search.uid) {
                        let uidEntries = unpackUIDRangeForSearch(request.payload.search.uid);
                        if (uidEntries && uidEntries.length) {
                            let mustList = [];
                            for (let entry of uidEntries) {
                                if (typeof entry === 'number') {
                                    mustList.push({
                                        match: {
                                            uid: {
                                                query: entry
                                            }
                                        }
                                    });
                                } else if (typeof entry === 'object') {
                                    mustList.push({
                                        range: {
                                            uid: entry
                                        }
                                    });
                                }
                            }

                            if (mustList.length) {
                                query.bool.must.push({
                                    bool: {
                                        should: mustList,
                                        minimum_should_match: 1
                                    }
                                });
                            }
                        }
                    }

                    for (let key of ['emailId', 'threadId']) {
                        if (request.payload.search[key]) {
                            query.bool.must.push({
                                term: {
                                    key: request.payload.search[key]
                                }
                            });
                        }
                    }

                    if (request.payload.search.subject) {
                        query.bool.must.push({
                            match: {
                                subject: {
                                    query: request.payload.search.subject
                                }
                            }
                        });
                    }

                    if (request.payload.search.body) {
                        query.bool.must.push({
                            bool: {
                                should: [
                                    {
                                        match: {
                                            'text.plain': {
                                                query: request.payload.search.body
                                            }
                                        }
                                    },
                                    {
                                        match: {
                                            'text.html': {
                                                query: request.payload.search.body
                                            }
                                        }
                                    }
                                ],
                                minimum_should_match: 1
                            }
                        });
                    }

                    let dateMatch = {};

                    for (let key of ['before', 'sentBefore']) {
                        if (request.payload.search[key]) {
                            dateMatch.lte = request.payload.search[key];
                        }
                    }

                    for (let key of ['since', 'sentSince']) {
                        if (request.payload.search[key]) {
                            dateMatch.gte = request.payload.search[key];
                        }
                    }

                    if (Object.keys(dateMatch).length) {
                        query.bool.must.push({
                            range: { date: dateMatch }
                        });
                    }

                    let sizeMatch = {};

                    if (request.payload.search.larger) {
                        dateMatch.gte = request.payload.search.larger;
                    }

                    if (request.payload.search.smaller) {
                        dateMatch.lte = request.payload.search.smaller;
                    }

                    if (Object.keys(sizeMatch).length) {
                        query.bool.must.push({
                            range: { size: sizeMatch }
                        });
                    }

                    // headers, nested query
                    if (Object.keys(request.payload.search.header || {}).length) {
                        Object.keys(request.payload.search.header).forEach(header => {
                            query.bool.must.push({
                                nested: {
                                    path: 'headers',
                                    query: {
                                        bool: {
                                            must: [
                                                {
                                                    term: {
                                                        'headers.key': header.toLowerCase()
                                                    }
                                                },
                                                {
                                                    match: {
                                                        'headers.value': { query: (request.payload.search.header[header] || '').toString() }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                }
                            });
                        });
                    }

                    const { index, client } = await getESClient();
                    let searchResult = await client.search({
                        index,
                        size: request.query.pageSize,
                        from: request.query.pageSize * request.query.page,
                        query,
                        sort: { uid: 'desc' },
                        _source_excludes: 'headers,text.plain,text.html'
                    });

                    let response = {
                        total: searchResult.hits.total.value,
                        page: request.query.page,
                        pages: Math.max(Math.ceil(searchResult.hits.total.value / request.query.pageSize), 1),
                        messages: searchResult.hits.hits.map(entry => {
                            let messageData = entry._source;

                            // normalize as per the API response

                            for (let key of ['unseen', 'flagged', 'answered', 'draft']) {
                                if (messageData[key] === false) {
                                    messageData[key] = undefined;
                                }
                            }

                            for (let key of ['account', 'created', 'specialUse']) {
                                if (messageData[key]) {
                                    messageData[key] = undefined;
                                }
                            }

                            return messageData;
                        })
                    };

                    return response;
                } else {
                    return await accountObject.listMessages(Object.assign(request.query, request.payload));
                }
            } catch (err) {
                request.logger.error({ msg: 'Request processing failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Search for messages',
            notes: 'Filter messages from a mailbox folder by search options. Search is performed against a specific folder and not for the entire account.',
            tags: ['api', 'message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string()
                        .when('documentStore', {
                            is: true,
                            then: Joi.optional(),
                            otherwise: Joi.required()
                        })
                        .example('INBOX')
                        .description('Mailbox folder path. Not required if `documentStore` is `true`'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page'),
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch the data from the Document Store instead of IMAP')
                        .label('UseDocumentStore')
                }),

                payload: Joi.object({
                    search: Joi.object({
                        seq: Joi.string()
                            .max(256)
                            .description('Sequence number range. Ignored when `documentStore` is `true` as Document Store does not assign sequence numbers.'),

                        answered: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is answered or not')
                            .label('AnsweredFlag'),
                        deleted: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked for being deleted or not')
                            .label('DeletedFlag'),
                        draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is a draft').label('DraftFlag'),
                        unseen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as unseen or not')
                            .label('UnseenFlag'),
                        flagged: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is flagged or not')
                            .label('Flagged'),
                        seen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as seen or not')
                            .label('SeenFlag'),

                        from: Joi.string().max(256).description('Match From: header').label('From'),
                        to: Joi.string().max(256).description('Match To: header').label('To'),
                        cc: Joi.string().max(256).description('Match Cc: header').label('Cc'),
                        bcc: Joi.string().max(256).description('Match Bcc: header').label('Bcc'),

                        body: Joi.string().max(256).description('Match text body').label('MessageBody'),
                        subject: Joi.string().max(256).description('Match message subject').label('Subject'),

                        larger: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages larger than value')
                            .label('MessageLarger'),

                        smaller: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages smaller than value')
                            .label('MessageSmaller'),

                        uid: Joi.string().max(256).description('UID range').label('UIDRange'),

                        modseq: Joi.number()
                            .min(0)
                            .description('Matches messages with modseq higher than value. Ignored when `documentStore` is `true`.')
                            .label('ModseqLarger'),

                        before: Joi.date().description('Matches messages received before date').label('EnvelopeBefore'),
                        since: Joi.date().description('Matches messages received after date').label('EnvelopeSince'),

                        sentBefore: Joi.date().description('Matches messages sent before date').label('HeaderBefore'),
                        sentSince: Joi.date().description('Matches messages sent after date').label('HeaderSince'),

                        emailId: Joi.string().max(256).description('Match specific Gmail unique email UD'),
                        threadId: Joi.string().max(256).description('Match specific Gmail unique thread UD'),

                        header: Joi.object().unknown(true).description('Headers to match against').label('Headers')
                    })
                        .required()
                        .description('Search query to filter messages')
                        .label('SearchQuery')
                }).label('SearchQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/contacts',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
            try {
                return await accountObject.buildContacts();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Builds a contact listing',
            notes: 'Builds a contact listings from email addresses. For larger mailboxes this could take a lot of time.',
            tags: [/*'api', */ 'experimental'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/submit',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.queueMessage(request.payload, { source: 'api' });
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Submit message for delivery',
            notes: 'Submit message for delivery. If reference message ID is provided then EmailEngine adds all headers and flags required for a reply/forward automatically.',
            tags: ['api', 'submit'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is EmailEngine specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    envelope: Joi.object({
                        from: Joi.string().email().allow('').example('sender@example.com'),
                        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com')).single()
                    })
                        .description('Optional SMTP envelope. If not set then derived from message headers.')
                        .label('SMTPEnvelope'),

                    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).description('The From address').label('From'),
                    replyTo: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).description('The Reply-To address').label('ReplyTo'),

                    to: Joi.array()
                        .items(addressSchema.label('ToAddress'))
                        .single()
                        .description('List of recipient addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('ToAddressList'),

                    cc: Joi.array().items(addressSchema.label('CcAddress')).single().description('List of CC addresses').label('CcAddressList'),

                    bcc: Joi.array().items(addressSchema.label('BccAddress')).single().description('List of BCC addresses').label('BccAddressList'),

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'Base64 encoded email message in rfc822 format. If you provide other keys as well then these will override the values in the raw message.'
                        )
                        .label('RFC822Raw'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers'),

                    trackingEnabled: Joi.boolean().example(false).description('Should EmailEngine track clicks and opens for this message'),

                    copy: Joi.boolean()
                        .example(true)
                        .description(
                            "If set then either copies the message to the Sent Mail folder or not. If not set then uses the account's default setting."
                        ),

                    sendAt: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Send message at specified time'),
                    deliveryAttempts: Joi.number()
                        .example(10)
                        .description('How many delivery attempts to make until message is considered as failed')
                        .default(10)
                })
                    .oxor('raw', 'html')
                    .oxor('raw', 'text')
                    .oxor('raw', 'text')
                    .oxor('raw', 'attachments')
                    .label('SubmitMessage')
            },

            response: {
                schema: Joi.object({
                    response: Joi.string().example('Queued for delivery'),
                    messageId: Joi.string().example('<a2184d08-a470-fec6-a493-fa211a3756e9@example.com>').description('Message-ID header value'),
                    sendAt: Joi.date().example('2021-07-08T07:06:34.336Z').description('Scheduled send time'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier for scheduled email')
                }).label('SubmitMessageResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/settings',

        async handler(request) {
            let values = {};
            for (let key of Object.keys(request.query)) {
                if (request.query[key]) {
                    if (key === 'eventTypes') {
                        values[key] = Object.keys(consts)
                            .map(key => {
                                if (/_NOTIFY?/.test(key)) {
                                    return consts[key];
                                }
                                return false;
                            })
                            .map(key => key);
                        continue;
                    }

                    let value = await settings.get(key);

                    if (settings.encryptedKeys.includes(key)) {
                        // do not reveal secret values
                        // instead show boolean value true if value is set, or false if it's not
                        value = value ? true : false;
                    }

                    values[key] = value;
                }
            }
            return values;
        },
        options: {
            description: 'List specific settings',
            notes: 'List setting values for specific keys',
            tags: ['api', 'settings'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object(settingsQuerySchema).label('SettingsQuery')
            },

            response: {
                schema: Joi.object(settingsSchema).label('SettingsQueryResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/settings',

        async handler(request) {
            let updated = [];
            for (let key of Object.keys(request.payload)) {
                switch (key) {
                    case 'serviceUrl': {
                        let url = new URL(request.payload.serviceUrl);
                        request.payload.serviceUrl = url.origin;
                        break;
                    }
                }

                await settings.set(key, request.payload[key]);
                updated.push(key);
            }

            notify('settings', request.payload);
            return { updated };
        },
        options: {
            description: 'Set setting values',
            notes: 'Set setting values for specific keys',
            tags: ['api', 'settings'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object(settingsSchema).label('Settings')
            },

            response: {
                schema: Joi.object({ updated: Joi.array().items(Joi.string().example('notifyHeaders')).description('List of updated setting keys') }).label(
                    'SettingsResponse'
                ),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/logs/{account}',

        async handler(request) {
            return getLogs(redis, request.params.account);
        },
        options: {
            description: 'Return IMAP logs for an account',
            notes: 'Output is a downloadable text file',
            tags: ['api', 'logs'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/stats',

        async handler(request) {
            return await getStats(redis, call, request.query.seconds);
        },

        options: {
            description: 'Return server stats',
            tags: ['api', 'stats'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    seconds: Joi.number()
                        .empty('')
                        .min(0)
                        .max(consts.MAX_DAYS_STATS * 24 * 3600)
                        .default(3600)
                        .example(3600)
                        .description('Duration for counters')
                        .label('CounterSeconds')
                }).label('ServerStats')
            },

            response: {
                schema: Joi.object({
                    version: Joi.string().example(packageData.version).description('EmailEngine version number'),
                    license: Joi.string().example(packageData.license).description('EmailEngine license'),
                    accounts: Joi.number().example(26).description('Number of registered accounts'),
                    node: Joi.string().example('16.10.0').description('Node.js Version'),
                    redis: Joi.string().example('6.2.4').description('Redis Version'),
                    connections: Joi.object({
                        init: Joi.number().example(2).description('Accounts not yet initialized'),
                        connected: Joi.number().example(8).description('Successfully connected accounts'),
                        connecting: Joi.number().example(7).description('Connection is being established'),
                        authenticationError: Joi.number().example(3).description('Authentication failed'),
                        connectError: Joi.number().example(5).description('Connection failed due to technical error'),
                        unset: Joi.number().example(0).description('Accounts without valid IMAP settings'),
                        disconnected: Joi.number().example(1).description('IMAP connection was closed')
                    })
                        .description('Counts of accounts in different connection states')
                        .label('ConnectionsStats'),
                    counters: Joi.object().label('CounterStats')
                }).label('SettingsResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/verifyAccount',

        async handler(request) {
            try {
                return await verifyAccountInfo(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Verify IMAP and SMTP settings',
            notes: 'Checks if can connect and authenticate using provided account info',
            tags: ['api', 'account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    mailboxes: Joi.boolean().example(false).description('Include mailbox listing in response').default(false),
                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAP'),
                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SMTP'),
                    proxy: settingsSchema.proxyUrl
                }).label('VerifyAccount')
            },
            response: {
                schema: Joi.object({
                    imap: Joi.object({
                        success: Joi.boolean().example(true).description('Was IMAP account verified').label('VerifyImapSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for IMAP verification. Only present if success=false')
                            .label('VerifyImapError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifyImapCode')
                    }),
                    smtp: Joi.object({
                        success: Joi.boolean().example(true).description('Was SMTP account verified').label('VerifySmtpSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for SMTP verification. Only present if success=false')
                            .label('VerifySmtpError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifySmtpCode')
                    }),
                    mailboxes: shortMailboxesSchema
                }).label('VerifyAccountResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/license',

        async handler() {
            try {
                const licenseInfo = await call({ cmd: 'license' });
                if (!licenseInfo) {
                    let err = new Error('Failed to load license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Request license info',
            notes: 'Get active license information',
            tags: ['api', 'license'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            response: {
                schema: licenseSchema.label('LicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/license',

        async handler() {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense' });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Remove license',
            notes: 'Remove registered active license',
            tags: ['api', 'license'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            response: {
                schema: Joi.object({
                    active: Joi.boolean().example(false),
                    details: Joi.boolean().example(false),
                    type: Joi.string().example('AGPL-3.0-or-later')
                }).label('EmptyLicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/license',

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Register a license',
            notes: 'Set up a license for EmailEngine to unlock all features',
            tags: ['api', 'license'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    license: Joi.string()
                        .max(10 * 1024)
                        .required()
                        .example('-----BEGIN LICENSE-----\r\n...')
                        .description('License file')
                }).label('RegisterLicense')
            },

            response: {
                schema: licenseSchema.label('LicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/autoconfig',

        async handler(request) {
            try {
                let serverSettings = await autodetectImapSettings(request.query.email);
                return serverSettings;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                return { imap: false, smtp: false, _source: 'unknown' };
            }
        },

        options: {
            description: 'Discover Email settings',
            notes: 'Try to discover IMAP and SMTP settings for an email account',
            tags: ['api', 'settings'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    email: Joi.string()
                        .email()
                        .required()
                        .example('sender@example.com')
                        .description('Email address to discover email settings for')
                        .label('EmailAddress')
                }).label('AutodiscoverQuery')
            },

            response: {
                schema: Joi.object({
                    imap: Joi.object({
                        auth: Joi.object({
                            user: Joi.string().max(256).example('myuser@gmail.com').description('Account username')
                        }).label('DetectedAuthenticationInfo'),

                        host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                        port: Joi.number()
                            .min(1)
                            .max(64 * 1024)
                            .required()
                            .example(993)
                            .description('Service port number'),
                        secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993')
                    }).label('ResolvedServerSettings'),
                    smtp: Joi.object({
                        auth: Joi.object({
                            user: Joi.string().max(256).example('myuser@gmail.com').description('Account username')
                        }).label('DetectedAuthenticationInfo'),

                        host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
                        port: Joi.number()
                            .min(1)
                            .max(64 * 1024)
                            .required()
                            .example(993)
                            .description('Service port number'),
                        secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993')
                    }).label('DiscoveredServerSettings'),
                    _source: Joi.string().example('srv').description('Source for the detected info')
                }).label('DiscoveredEmailSettings'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/outbox',

        async handler(request) {
            try {
                return await outbox.list(Object.assign({ logger }, request.query));
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'List queued messages',
            notes: 'Lists messages in the Outbox',
            tags: ['api', 'outbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('OutbixListFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),

                    messages: Joi.array()
                        .items(
                            Joi.object({
                                queueId: Joi.string().example('1869c5692565f756b33').description('Outbox queue ID'),
                                account: Joi.string().max(256).required().example('example').description('Account ID'),
                                source: Joi.string().example('smtp').valid('smtp', 'api').description('How this message was added to the queue'),

                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                envelope: Joi.object({
                                    from: Joi.string().email().allow('').example('sender@example.com'),
                                    to: Joi.array().items(Joi.string().email().required().example('recipient@example.com'))
                                }).description('SMTP envelope'),
                                subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this message was queued'),
                                scheduled: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('When this message is supposed to be delivered'),
                                nextAttempt: Joi.date().iso().example('2021-02-17T13:43:18.860Z').allow(false).description('Next delivery attempt'),

                                attemptsMade: Joi.number().example(3).description('How many times EmailEngine has tried to deliver this email'),
                                attempts: Joi.number().example(3).description('How many delivery attempts to make until message is considered as failed'),

                                progress: Joi.object({
                                    status: Joi.string()
                                        .valid('queued', 'processing', 'submitted', 'error')
                                        .example('queued')
                                        .description('Current state of the sending'),
                                    response: Joi.string()
                                        .example('250 Message Accepted')
                                        .description('Response from the SMTP server. Only if state=processing'),
                                    error: Joi.object({
                                        message: Joi.string().example('Authentication failed').description('Error message'),
                                        code: Joi.string().example('EAUTH').description('Error code'),
                                        statusCode: Joi.string().example(502).description('SMTP response code')
                                    })
                                        .label('OutboxListProgressError')
                                        .description('Error information if state=error')
                                }).label('OutboxListProgress')
                            }).label('OutboxListItem')
                        )
                        .label('OutboxListEntries')
                }).label('OutboxListResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                return {
                    deleted: await outbox.del({ queueId: request.params.queueId, logger })
                };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Remove a message',
            notes: 'Remove a message from the outbox',
            tags: ['api', 'outbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    queueId: Joi.string().max(100).example('d41f0423195f271f').description('Queue identifier for scheduled email').required()
                }).label('DeleteOutboxEntry')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the message deleted')
                }).label('DeleteOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });

    // Web UI routes

    await server.register({
        plugin: Crumb,

        options: {
            cookieOptions: {
                isSecure: false
            },

            skip: (request /*, h*/) => {
                let tags = (request.route && request.route.settings && request.route.settings.tags) || [];

                if (tags.includes('api') || tags.includes('metrics') || tags.includes('external')) {
                    return true;
                }

                return false;
            }
        }
    });

    server.views({
        engines: {
            hbs: handlebars
        },

        relativeTo: pathlib.join(__dirname, '..'),
        path: './views',
        layout: 'app',
        layoutPath: './views/layout',
        partialsPath: './views/partials',

        isCached: false,

        async context(request) {
            const pendingMessages = await flash(redis, request);
            const authData = await settings.get('authData');

            let systemAlerts = [];
            let upgradeInfo = await settings.get('upgrade');
            if (upgradeInfo && upgradeInfo.canUpgrade) {
                systemAlerts.push({
                    url: '/admin/upgrade',
                    level: 'info',
                    icon: 'exclamation-triangle',
                    message: `An update is available: Emailengine v${upgradeInfo.available}`
                });
            }

            let outlookAuthFlag = await settings.get('outlookAuthFlag');
            if (outlookAuthFlag && outlookAuthFlag.message) {
                systemAlerts.push({
                    url: outlookAuthFlag.url || '/admin/config/oauth/outlook',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: outlookAuthFlag.message
                });
            }

            let gmailAuthFlag = await settings.get('gmailAuthFlag');
            if (gmailAuthFlag && gmailAuthFlag.message) {
                systemAlerts.push({
                    url: gmailAuthFlag.url || '/admin/config/oauth/gmail',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: gmailAuthFlag.message
                });
            }

            let gmailServiceAuthFlag = await settings.get('gmailServiceAuthFlag');
            if (gmailServiceAuthFlag && gmailServiceAuthFlag.message) {
                systemAlerts.push({
                    url: gmailServiceAuthFlag.url || '/admin/config/oauth/gmailService',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: gmailServiceAuthFlag.message
                });
            }

            let webhookErrorFlag = await settings.get('webhookErrorFlag');
            let webhooksEnabled = await settings.get('webhooksEnabled');
            if (webhooksEnabled && webhookErrorFlag && webhookErrorFlag.message) {
                systemAlerts.push({
                    url: '/admin/config/webhooks',
                    level: 'danger',
                    icon: 'link',
                    message: 'Webhooks are failing, please review'
                });
            }

            if (!request.app.licenseInfo || !request.app.licenseInfo.active) {
                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'warning',
                    icon: 'key',
                    message: 'License key is not registered'
                });
            }

            let licenseDetails = Object.assign({}, (request.app.licenseInfo && request.app.licenseInfo.details) || {});

            if (licenseDetails.expires) {
                let delayMs = new Date(licenseDetails.expires) - Date.now();
                licenseDetails.expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);
            }

            if (licenseDetails.expires && licenseDetails.expiresDays < 31) {
                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'warning',
                    icon: 'key',
                    message: `Your ${licenseDetails.trial ? `trial ` : ''}license key will expire in ${licenseDetails.expiresDays} days`
                });
            }

            let disableTokens = await settings.get('disableTokens');
            if (disableTokens) {
                systemAlerts.push({
                    url: '/admin/config/service#security',
                    level: 'warning',
                    icon: 'key',
                    message: `Access tokens are disabled for API requests`
                });
            }

            return {
                values: request.payload || {},
                errors: (request.error && request.error.details) || {},
                pendingMessages,
                licenseInfo: request.app.licenseInfo,
                licenseDetails,
                authEnabled: !!(authData && authData.password),
                trialPossible: !(await settings.get('tract')),
                authData,
                packageData,
                systemAlerts,
                embeddedTemplateHeader: await settings.get('templateHeader'),
                currentYear: new Date().getFullYear(),
                showDocumentStore: (await settings.get('labsDocumentStore')) || (await settings.get('documentStoreEnabled'))
            };
        }
    });

    const preResponse = async (request, h) => {
        const response = request.response;
        if (!response.isBoom) {
            return h.continue;
        }

        // Replace error with friendly HTML
        const error = response;
        const ctx = {
            message:
                error.output.statusCode === 404
                    ? 'page not found'
                    : (error.output && error.output.payload && error.output.payload.message) || 'something went wrong'
        };

        if (error.output && error.output.payload) {
            request.errorInfo = error.output.payload;
        }

        if (error.output && error.output.statusCode === 401 && error.output.headers && /^Bearer/.test(error.output.headers['WWW-Authenticate'])) {
            // bearer auth failed
            return h
                .response({ statusCode: 401, error: 'Unauthorized', message: error.message })
                .header('WWW-Authenticate', error.output.headers['WWW-Authenticate'])
                .code(error.output.statusCode);
        }

        if (request.errorInfo && request.route && request.route.settings && request.route.settings.tags && request.route.settings.tags.includes('api')) {
            // JSON response for API requests
            return h.response(request.errorInfo).code(request.errorInfo.statusCode || 500);
        }

        if (/^\/v1\//.test(request.path) || /^\/health$/.test(request.path)) {
            // API path
            return h.response(request.errorInfo).code(request.errorInfo.statusCode || 500);
        }

        logger.error({ path: request.path, method: request.method, err: error });

        return h
            .view('error', ctx, {
                layout: 'public'
            })
            .code(error.output.statusCode);
    };

    server.ext('onPreResponse', preResponse);

    server.route({
        method: 'GET',
        path: '/admin/changes',
        async handler(request, h) {
            request.app.stream = new ResponseStream();
            finished(request.app.stream, err => request.app.stream.finalize(err));
            setImmediate(() => {
                try {
                    request.app.stream.write(`: EmailEngine v${packageData.version}\n\n`);
                } catch (err) {
                    // ignore
                }
            });
            return h
                .response(request.app.stream)
                .header('X-Accel-Buffering', 'no')
                .header('Connection', 'keep-alive')
                .header('Cache-Control', 'no-cache')
                .type('text/event-stream');
        }
    });

    routesUi(server, call);

    // Bull-UI
    const arenaBasePath = '/admin/iframe/arena';
    await server.register(Hecks);
    server.route({
        method: '*',
        path: `${arenaBasePath}/{expressPath*}`,
        options: {
            tags: ['external'],
            //auth: false,
            handler: {
                express: arenaExpress(Object.assign({ connectionName: `${REDIS_CONF.connectionName}[arena]` }, REDIS_CONF), arenaBasePath)
            },
            state: {
                parse: true,
                failAction: 'error'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/metrics',

        async handler(request, h) {
            const renderedMetrics = await call({ cmd: 'metrics' });
            const response = h.response('success');
            response.type('text/plain');
            return renderedMetrics;
        },
        options: {
            tags: ['scope:metrics'],
            auth: {
                strategy: 'api-token',
                mode: 'required'
            }
        }
    });

    server.route({
        method: '*',
        path: '/{any*}',
        async handler() {
            throw Boom.notFound('Requested page not found'); // 404
        }
    });

    await server.start();
};

// dynamic imports first, use a wrapper function or eslint parser will crash
init()
    .then(() => {
        logger.debug({
            msg: 'Started API server thread',
            port: API_PORT,
            host: API_HOST,
            maxSize: MAX_ATTACHMENT_SIZE,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.error(err);
        setImmediate(() => process.exit(3));
    });
