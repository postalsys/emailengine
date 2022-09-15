'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');
const Path = require('path');
const { loadTranslations, gt, joiLocales } = require('../lib/translations');
const util = require('util');

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
    assertPreconditions,
    matcher,
    readEnvValue,
    matchIp,
    getSignedFormData
} = require('../lib/tools');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'api', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'api', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'api', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'api', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
}

const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const Cookie = require('@hapi/cookie');
const Crumb = require('@hapi/crumb');
const Joi = require('joi');
const hapiPino = require('hapi-pino');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');

const pathlib = require('path');

const crypto = require('crypto');
const { Transform, finished } = require('stream');
const { getOAuth2Client } = require('../lib/oauth');

const handlebars = require('handlebars');
const AuthBearer = require('hapi-auth-bearer-token');
const tokens = require('../lib/tokens');
const { autodetectImapSettings } = require('../lib/autodetect-imap-settings');

const Hecks = require('@hapipal/hecks');
const { arenaExpress } = require('../lib/arena-express');
const outbox = require('../lib/outbox');
const { templates } = require('../lib/templates');

const { redis, REDIS_CONF, notifyQueue, documentsQeueue } = require('../lib/db');
const { Account } = require('../lib/account');
const { Gateway } = require('../lib/gateway');
const settings = require('../lib/settings');

const getSecret = require('../lib/get-secret');
const { getESClient } = require('../lib/document-store');

const routesUi = require('../lib/routes-ui');

const { encrypt, decrypt } = require('../lib/encrypt');
const { Certs } = require('@postalsys/certs');
const net = require('net');

const consts = require('../lib/consts');
const {
    TRACK_OPEN_NOTIFY,
    TRACK_CLICK_NOTIFY,
    REDIS_PREFIX,
    MAX_DAYS_STATS,
    RENEW_TLS_AFTER,
    BLOCK_TLS_RENEW,
    TLS_RENEW_CHECK_INTERVAL,
    DEFAULT_CORS_MAX_AGE
} = consts;

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
    lastErrorSchema,
    templateSchemas,
    documentStoreSchema,
    searchSchema,
    messageUpdateSchema
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

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const MAX_ATTACHMENT_SIZE = getByteSize(readEnvValue('EENGINE_MAX_SIZE') || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

const API_PORT =
    (readEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (readEnvValue('PORT') && Number(readEnvValue('PORT'))) || config.api.port;
const API_HOST = readEnvValue('EENGINE_HOST') || config.api.host;

const IMAP_WORKER_COUNT = getWorkerCount(readEnvValue('EENGINE_WORKERS') || (config.workers && config.workers.imap)) || 4;

// CORS configuration for API requests
// By default, CORS is not enabled
const CORS_ORIGINS = readEnvValue('EENGINE_CORS_ORIGIN') || (config.cors && config.cors.origin);
const CORS_CONFIG = !CORS_ORIGINS
    ? false
    : {
          // crux to convert --cors.origin=".." and EENGINE_CORS_ORIGIN="..." into an array of origins
          origin: [].concat(
              Array.from(
                  new Set(
                      []
                          .concat(CORS_ORIGINS || [])
                          .flatMap(origin => origin)
                          .flatMap(origin => origin && origin.toString().trim().split(/\s+/))
                          .filter(origin => origin)
                  )
              ) || ['*']
          ),
          headers: ['Authorization'],
          exposedHeaders: ['Accept'],
          additionalExposedHeaders: [],
          maxAge:
              getDuration(readEnvValue('EENGINE_CORS_MAX_AGE') || (config.cors && config.cors.maxAge), {
                  seconds: true
              }) || DEFAULT_CORS_MAX_AGE,
          credentials: true
      };

logger.debug({ msg: 'CORS config for API requests', cors: CORS_CONFIG });

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

    if (message && message.cmd === 'change') {
        publishChangeEvent(message);
    }
});

const init = async () => {
    await loadTranslations();

    gt.setLocale((await settings.get('locale')) || 'en');

    handlebars.registerHelper('_', (...args) => {
        let params = args.slice(1, args.length - 1);
        let translated = gt.gettext(args[0]);
        if (params.length) {
            translated = util.format(translated, ...params);
        }

        return new handlebars.SafeString(translated);
    });

    handlebars.registerHelper('ngettext', (msgid, plural, count) => util.format(gt.ngettext(msgid, plural, count), count));

    handlebars.registerHelper('equals', (compareVal, baseVal, options) => {
        if (baseVal === compareVal) {
            return options.fn(this); // eslint-disable-line no-invalid-this
        }
        return options.inverse(this); // eslint-disable-line no-invalid-this
    });

    handlebars.registerHelper('inc', (nr, inc) => Number(nr) + Number(inc));

    const server = Hapi.server({
        port: API_PORT,
        host: API_HOST,

        router: {
            stripTrailingSlash: true
        },
        routes: {
            validate: { options: { messages: joiLocales } }
        }
    });

    let assertPreconditionResult;
    server.decorate('toolkit', 'getESClient', async (...args) => await getESClient(...args));

    let getServiceDomain = async () => {
        let serviceUrl = await settings.get('serviceUrl');
        let hostname = (new URL(serviceUrl).hostname || '').toString().toLowerCase().trim();
        if (!hostname || net.isIP(hostname) || ['localhost'].includes(hostname) || /(\.local|\.lan)$/i.test(hostname)) {
            return false;
        }
        return hostname;
    };

    let certHandler = new Certs({
        redis,
        namespace: `${REDIS_PREFIX}`,

        acme: {
            environment: 'emailengine',
            directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory'
            //directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
        },

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

    server.decorate('toolkit', 'serviceDomain', getServiceDomain);
    server.decorate('toolkit', 'certs', certHandler);

    server.decorate('toolkit', 'getCertificate', async provision => {
        let hostname = await getServiceDomain();
        let certificateData;

        if (hostname) {
            certificateData = await certHandler.getCertificate(hostname, !provision);
        }

        if (!certificateData) {
            certificateData = {
                domain: hostname,
                status: 'self_signed',
                label: { type: 'warning', text: 'Self-signed', title: 'Using a self-signed certificate' }
            };
        } else if (certificateData.status !== 'valid') {
            switch (certificateData.status) {
                case 'pending':
                    certificateData.label = { type: 'info', text: 'Provisioning...', title: 'Currently provisioning a certificate' };
                    break;
                case 'failed':
                    certificateData.label = {
                        type: 'danger',
                        text: 'Failed',
                        title: (certificateData.lastError && certificateData.lastError.err) || 'Failed to generate a certificate'
                    };
                    break;
            }
        } else if (certificateData.validFrom > new Date()) {
            certificateData.label = {
                type: 'warning',
                text: 'Future certificate',
                title: 'Certificate is not yet valid'
            };
        } else if (certificateData.validTo < new Date()) {
            certificateData.label = {
                type: 'warning',
                text: 'Expired certificate',
                title: (certificateData.lastError && certificateData.lastError.err) || 'Certificate has been expired'
            };
        } else {
            certificateData.label = {
                type: 'success',
                text: 'Valid certificate',
                title: certificateData.fingerprint
            };
        }

        return certificateData;
    });

    server.ext('onPostAuth', async (request, h) => {
        let defaultLocale = (await settings.get('locale')) || 'en';
        if (defaultLocale && gt.locale !== defaultLocale) {
            gt.setLocale(defaultLocale);
        }

        if (joiLocales[defaultLocale] && request.route.settings.validate.options) {
            if (!request.route.settings.validate.options.errors) {
                request.route.settings.validate.options.errors = {};
            }
            request.route.settings.validate.options.errors.language = defaultLocale;
        }
        return h.continue;
    });

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

        expanded: 'list',
        sortEndpoints: 'method',
        tryItOutEnabled: true,

        templates: Path.join(__dirname, '..', 'views', 'swagger', 'ui'),

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

        security: [{ bearerAuth: [] }],

        cors: !!CORS_CONFIG,
        cache: {
            expiresIn: 7 * 24 * 60 * 60 * 1000
        }
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
                if (tokenData.restrictions.addresses && !matchIp(request.app.ip, tokenData.restrictions.addresses)) {
                    logger.error({
                        msg: 'Trying to use invalid IP for a token',
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
            file: { path: pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), confine: false }
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

            let checkKey = `${REDIS_PREFIX}test:${Date.now()}`;
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

                    accountData.email = isEmail(profileRes.emailAddress) ? profileRes.emailAddress : accountData.email;

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
                    accountData.email = userInfo.email;

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
                    accountData.email = isEmail(profileRes.email) ? profileRes.email : accountData.email;

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Access Tokens'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                    scopes: Joi.array().items(Joi.string().valid('api', 'smtp', 'imap-proxy')).single().default(['api']).required().label('Scopes'),

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

                    restrictions: Joi.object({
                        referrers: Joi.array()
                            .items(Joi.string())
                            .empty('')
                            .single()
                            .allow(false)
                            .default(false)
                            .example(['*web.domain.org/*', '*.domain.org/*', 'https://domain.org/*'])
                            .label('ReferrerAllowlist')
                            .description('HTTP referrer allowlist for API requests'),
                        addresses: Joi.array()
                            .items(
                                Joi.string().ip({
                                    version: ['ipv4', 'ipv6'],
                                    cidr: 'optional'
                                })
                            )
                            .empty('')
                            .single()
                            .allow(false)
                            .default(false)
                            .example(['1.2.3.4', '5.6.7.8', '127.0.0.0/8'])
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Access Tokens'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

        async handler(request) {
            try {
                return { tokens: await tokens.list() };
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Access Tokens'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Access Tokens'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                                restrictions: Joi.object({
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
                                                cidr: 'optional'
                                            })
                                        )
                                        .empty('')
                                        .allow(false)
                                        .default(false)
                                        .example(['1.2.3.4', '5.6.7.8', '127.0.0.0/8'])
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                    imap: Joi.object(imapSchema).allow(false).xor('useAuthServer', 'auth', 'disabled').description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP'),

                    oauth2: Joi.object(oauth2Schema).xor('authorize', 'auth').allow(false).description('OAuth2 configuration').label('OAuth2'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
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
        method: 'POST',
        path: '/v1/authentication/form',

        async handler(request) {
            try {
                let { data, signature } = await getSignedFormData({
                    account: request.payload.account,
                    name: request.payload.name,
                    email: request.payload.email,
                    redirectUrl: request.payload.redirectUrl
                });

                let serviceUrl = await settings.get('serviceUrl');
                if (!serviceUrl) {
                    let err = new Error('Service URL not set up');
                    err.code = 'MissingServiceURLSetup';
                    throw err;
                }

                let url = new URL(`accounts/new`, serviceUrl);

                url.searchParams.append('data', data);
                if (signature) {
                    url.searchParams.append('sig', signature);
                }

                let type = request.payload.type;

                let enabledTypes = new Set();

                for (let accountType of ['gmail', 'outlook', 'mailRu']) {
                    let typeEnabled = await settings.get(`${accountType}Enabled`);
                    if (typeEnabled && (!(await settings.get(`${accountType}ClientId`)) || !(await settings.get(`${accountType}ClientSecret`)))) {
                        typeEnabled = false;
                        if (type === accountType) {
                            type = false;
                        }
                    }
                    if (typeEnabled) {
                        enabledTypes.add(accountType);
                    }
                }

                if (!enabledTypes.size) {
                    type = 'imap';
                }

                if (type) {
                    url.searchParams.append('type', type);
                }

                return {
                    url: url.href
                };
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Generate authentication link',
            notes: 'Generates a redirect link to the hosted authentication form',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                        .example('example')
                        .default(null)
                        .description(
                            'Account ID. If null then will be autogenerated. Using an existing account ID will update settings for that existing account.'
                        ),

                    name: Joi.string().empty('').max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    redirectUrl: Joi.string()
                        .empty('')
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .required()
                        .example('https://myapp/account/settings.php')
                        .description('The user will be redirected to this URL after submitting the authentication form'),

                    type: Joi.string()
                        .valid('imap', 'gmail', 'outlook', 'mailRu')
                        .empty('')
                        .allow(false)
                        .default(false)
                        .example('imap')
                        .description('Display the form for the specified account type instead of allowing the user to choose')
                }).label('RequestAuthForm')
            },

            response: {
                schema: Joi.object({
                    url: Joi.string()
                        .empty('')
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .required()
                        .example('https://ee.example.com/accounts/new?data=eyJhY2NvdW50IjoiZXhh...L0W_BkFH5HW6Krwmr7c&type=imap')
                        .description('Generated URL to the hosted authentication form')
                }).label('RequestAuthFormResponse'),
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                    imap: Joi.object(imapUpdateSchema)
                        .allow(false)
                        .oxor('useAuthServer', 'auth', 'disabled')
                        .description('IMAP configuration')
                        .label('IMAPUpdate'),
                    smtp: Joi.object(smtpUpdateSchema).allow(false).oxor('useAuthServer', 'auth').description('SMTP configuration').label('SMTPUpdate'),
                    oauth2: Joi.object(oauth2UpdateSchema).xor('authorize', 'auth').allow(false).description('OAuth2 configuration').label('OAuth2Update'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                return await accountObject.listAccounts(request.query.state, request.query.query, request.query.page, request.query.pageSize);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                        .label('AccountState'),
                    query: Joi.string().example('user@example').description('Filter accounts by string match').label('AccountQuery')
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
                                webhooks: Joi.string()
                                    .uri({
                                        scheme: ['http', 'https'],
                                        allowRelative: false
                                    })
                                    .example('https://myservice.com/imap/webhooks')
                                    .description('Account-specific webhook URL'),
                                proxy: settingsSchema.proxyUrl,
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

                for (let key of [
                    'account',
                    'name',
                    'email',
                    'copy',
                    'notifyFrom',
                    'imap',
                    'smtp',
                    'oauth2',
                    'state',
                    'smtpStatus',
                    'webhooks',
                    'proxy',
                    'locale',
                    'tz'
                ]) {
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),
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
                return { mailboxes: await accountObject.getMailboxListing(request.query) };
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Mailbox'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    counters: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then includes message counters in the response')
                        .label('MailboxCounters')
                }).label('MailboxListQuery')
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Mailbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Mailbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger)
            });

            try {
                return await accountObject.getMessage(request.params.message, request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    documentStore: documentStoreSchema.default(false)
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    internalDate: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Sets the internal date for this message'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply'),
                        inline: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then blockquotes the email that is being replied to')
                            .label('InlineReply'),
                        forwardAttachments: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then includes attachments in forwarded message')
                            .when('action', {
                                is: 'forward',
                                then: Joi.optional(),
                                otherwise: Joi.forbidden()
                            })
                            .label('ForwardAttachments'),
                        ignoreMissing: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then processes the email even if the original message is not available anymore')
                            .label('IgnoreMissing'),
                        documentStore: documentStoreSchema.default(false)
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
                            }).label('UploadAttachment')
                        )
                        .description('List of attachments')
                        .label('UploadAttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().label('CustomHeaders').description('Custom Headers').unknown(),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
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
                    seq: Joi.number().example(12345).description('Sequence number of uploaded message'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        success: Joi.boolean().example(true).description('Was the referenced message processed').label('ResponseReferenceSuccess'),
                        error: Joi.string().example('Referenced message was not found').description('An error message if referenced message processing failed')
                    })
                        .description('Reference info if referencing was requested')
                        .label('ResponseReference')
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

                payload: messageUpdateSchema
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
        path: '/v1/account/{account}/messages',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.updateMessages(request.query.path, request.payload.search, request.payload.update);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Update messages',
            notes: 'Update message information for matching emails',
            tags: ['api', 'Multi Message Actions'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    path: Joi.string().empty('').required().example('INBOX').description('Mailbox folder path')
                }).label('MessagesUpdateQuery'),

                payload: Joi.object({
                    search: searchSchema,
                    update: messageUpdateSchema
                }).label('MessagesUpdateRequest')
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
        method: 'PUT',
        path: '/v1/account/{account}/messages/move',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.moveMessages(request.query.path, request.payload.search, { path: request.payload.path });
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Move messages',
            notes: 'Move messages matching to a search query to another folder',
            tags: ['api', 'Multi Message Actions'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    path: Joi.string().empty('').required().example('INBOX').description('Source mailbox folder path')
                }).label('MessagesMoveQuery'),

                payload: Joi.object({
                    search: searchSchema,
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path')
                }).label('MessagesMoveRequest')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),
                    idMap: Joi.array()
                        .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')))
                        .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                        .description('An optional map of source and target ID values, if the server provided this info')
                }).label('MessagesMoveResponse'),
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    deleted: Joi.boolean().example(false).description('Was the delete action executed'),
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
        method: 'PUT',
        path: '/v1/account/{account}/messages/delete',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                return await accountObject.deleteMessages(request.query.path, request.payload.search, request.query.force);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Delete messages',
            notes: 'Move messages to Trash or delete these if already in Trash',
            tags: ['api', 'Multi Message Actions'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    path: Joi.string().empty('').required().example('INBOX').description('Mailbox folder path'),
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Delete messages even if not in Trash')
                        .label('ForceDelete')
                }).label('MessagesDeleteQuery'),

                payload: Joi.object({
                    search: searchSchema
                }).label('MessagesDeleteRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(false).description('Was the delete action executed'),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),
                        idMap: Joi.array()
                            .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')))
                            .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                            .description('An optional map of source and target ID values, if the server provided this info')
                    }).description('Present if messages were moved to Trash')
                }).label('MessagesDeleteResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/text/{text}',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger)
            });

            try {
                return await accountObject.getText(request.params.text, request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    documentStore: documentStoreSchema.default(false)
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

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger)
            });

            try {
                return await accountObject.listMessages(request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    documentStore: documentStoreSchema.default(false)
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

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger)
            });

            let extraValidationErrors = [];

            if (request.query.documentStore) {
                for (let key of ['seq', 'modseq']) {
                    if (request.payload.search && key in request.payload.search) {
                        extraValidationErrors.push({ message: 'Not allowed with documentStore', context: { key } });
                    }
                }
            } else {
                for (let key of ['documentQuery']) {
                    if (key in request.payload) {
                        extraValidationErrors.push({ message: 'Not allowed without documentStore', context: { key } });
                    }
                }
            }

            if (extraValidationErrors.length) {
                let error = new Error('Input validation failed');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            try {
                return await accountObject.searchMessages(Object.assign(request.query, request.payload));
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Message'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    documentStore: documentStoreSchema.default(false),
                    exposeQuery: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If enabled then returns the ElasticSearch query for debugging as part of the response')
                        .label('exposeQuery')
                        .when('documentStore', {
                            is: true,
                            then: Joi.optional(),
                            otherwise: Joi.forbidden()
                        })
                }),

                payload: Joi.object({
                    search: searchSchema,
                    documentQuery: Joi.object().min(1).description('Document Store query. Only allowed with `documentStore`.').label('DocumentQuery').unknown()
                }).label('SearchQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
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
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.info) {
                    error.output.payload.info = err.info;
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
            tags: ['api', 'Submit'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply'),
                        inline: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then blockquotes the email that is being replied to')
                            .label('InlineReply'),
                        forwardAttachments: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then includes attachments in forwarded message')
                            .when('action', {
                                is: 'forward',
                                then: Joi.optional(),
                                otherwise: Joi.forbidden()
                            })
                            .label('ForwardAttachments'),
                        ignoreMissing: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .default(false)
                            .description('If true, then processes the email even if the original message is not available anymore')
                            .label('IgnoreMissing'),
                        documentStore: documentStoreSchema.default(false)
                    })
                        .description('Message reference for a reply or a forward. This is EmailEngine specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    envelope: Joi.object({
                        from: Joi.string().email().allow('').example('sender@example.com'),
                        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com')).single()
                    })
                        .description('Optional SMTP envelope. If not set then derived from message headers.')
                        .label('SMTPEnvelope')
                        .when('mailMerge', { is: Joi.exist(), then: Joi.forbidden('y') }),

                    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).description('The From address').label('From'),

                    replyTo: Joi.array()
                        .items(addressSchema.label('ReplyToAddress'))
                        .single()
                        .example([{ name: 'From Me', address: 'sender@example.com' }])
                        .description('List of Reply-To addresses')
                        .label('ReplyTo'),

                    to: Joi.array()
                        .items(addressSchema.label('ToAddress'))
                        .single()
                        .example([{ address: 'recipient@example.com' }])
                        .description('List of recipient addresses')
                        .label('ToAddressList')
                        .when('mailMerge', { is: Joi.exist(), then: Joi.forbidden('y') }),

                    cc: Joi.array()
                        .items(addressSchema.label('CcAddress'))
                        .single()
                        .description('List of CC addresses')
                        .label('CcAddressList')
                        .when('mailMerge', { is: Joi.exist(), then: Joi.forbidden('y') }),

                    bcc: Joi.array()
                        .items(addressSchema.label('BccAddress'))
                        .single()
                        .description('List of BCC addresses')
                        .label('BccAddressList')
                        .when('mailMerge', { is: Joi.exist(), then: Joi.forbidden('y') }),

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'Base64 encoded email message in rfc822 format. If you provide other keys as well then these will override the values in the raw message.'
                        )
                        .label('RFC822Raw')
                        .when('mailMerge', {
                            is: Joi.exist(),
                            then: Joi.forbidden('y')
                        }),

                    subject: templateSchemas.subject,
                    text: templateSchemas.text,
                    html: templateSchemas.html,
                    previewText: templateSchemas.previewText,

                    template: Joi.string().max(256).example('example').description('Stored template ID to load the email content from'),

                    render: Joi.object({
                        format: Joi.string()
                            .valid('html', 'mjml', 'markdown')
                            .default('html')
                            .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                        params: Joi.object().label('RenderValues').description('An object of variables for the template renderer')
                    })
                        .allow(false)
                        .description('Template rendering options')
                        .when('mailMerge', {
                            is: Joi.exist(),
                            then: Joi.forbidden('y')
                        }),

                    mailMerge: Joi.array()
                        .items(
                            Joi.object({
                                to: addressSchema.label('ToAddress').required(),
                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                params: Joi.object().label('RenderValues').description('An object of variables for the template renderer'),
                                sendAt: Joi.date()
                                    .iso()
                                    .example('2021-07-08T07:06:34.336Z')
                                    .description('Send message at specified time. Overrides message level `sendAt` value.')
                            }).label('MailMergeListEntry')
                        )
                        .min(1)
                        .description(
                            'Mail merge options. A separate email is generated for each recipient. Using mail merge disables `messageId`, `envelope`, `to`, `cc`, `bcc`, `render` keys for the message root.'
                        )
                        .label('MailMergeList'),

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
                            }).label('UploadAttachment')
                        )
                        .description('List of attachments')
                        .label('UploadAttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().label('CustomHeaders').description('Custom Headers').unknown(),

                    trackingEnabled: Joi.boolean().example(false).description('Should EmailEngine track clicks and opens for this message'),

                    copy: Joi.boolean()
                        .example(true)
                        .description(
                            "If set then either copies the message to the Sent Mail folder or not. If not set then uses the account's default setting."
                        ),

                    sentMailPath: Joi.string()
                        .empty('')
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used."),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone'),

                    sendAt: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Send message at specified time'),
                    deliveryAttempts: Joi.number()
                        .example(10)
                        .description('How many delivery attempts to make until message is considered as failed')
                        .default(10),

                    gateway: Joi.string().max(256).example('example').description('Optional SMTP gateway ID for message routing'),

                    dryRun: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'If true, then EmailEngine does not send the email and returns an RFC822 formatted email file. Tracking information is not added to the email.'
                        )
                        .label('Preview')
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
                    messageId: Joi.string()
                        .example('<a2184d08-a470-fec6-a493-fa211a3756e9@example.com>')
                        .description('Message-ID header value. Not present for bulk messages.'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier for scheduled email. Not present for bulk messages.'),
                    sendAt: Joi.date().example('2021-07-08T07:06:34.336Z').description('Scheduled send time'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        documentStore: Joi.boolean()
                            .example(true)
                            .description('Was the message dat aloaded from the document store')
                            .label('ResponseDocumentStore'),
                        success: Joi.boolean().example(true).description('Was the referenced message processed successfully').label('ResponseReferenceSuccess'),
                        error: Joi.string().example('Referenced message was not found').description('An error message if referenced message processing failed')
                    })
                        .description('Reference info if referencing was requested')
                        .label('ResponseReference'),

                    preview: Joi.string()
                        .base64()
                        .example('Q29udGVudC1UeXBlOiBtdWx0aX...')
                        .description('Base64 encoded RFC822 email if a preview was requested')
                        .label('ResponsePreview'),

                    bulk: Joi.array()
                        .items(
                            Joi.object()
                                .label('BulkResponseEntry')
                                .example({
                                    success: true,
                                    to: {
                                        name: 'Andris 2',
                                        address: 'andris@ethereal.email'
                                    },
                                    messageId: '<19b9c433-d428-f6d8-1d00-d666ebcadfc4@ekiri.ee>',
                                    queueId: '1812477338914c8372a',
                                    reference: {
                                        message: 'AAAAAQAACnA',
                                        success: true
                                    },
                                    sendAt: '2021-07-08T07:06:34.336Z'
                                })
                                .unknown()
                        )
                        .label('BulkResponseList')
                        .description('Bulk message responses')
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
            tags: ['api', 'Settings'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
            tags: ['api', 'Settings'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
            tags: ['api', 'Logs'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
            tags: ['api', 'Stats'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                        .max(MAX_DAYS_STATS * 24 * 3600)
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
                    counters: Joi.object().label('CounterStats').unknown()
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'license' });
                if (!licenseInfo) {
                    let err = new Error('Failed to load license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'License'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            response: {
                schema: licenseSchema.label('LicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/license',

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense' });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'License'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            response: {
                schema: Joi.object({
                    active: Joi.boolean().example(false),
                    details: Joi.boolean().example(false),
                    type: Joi.string().example('SSPL-1.0-or-later')
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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'License'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                return { imap: false, smtp: false, _source: 'unknown' };
            }
        },

        options: {
            description: 'Discover Email settings',
            notes: 'Try to discover IMAP and SMTP settings for an email account',
            tags: ['api', 'Settings'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Outbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                request.logger.error({ msg: 'API request failed', err });
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
            tags: ['api', 'Outbox'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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

    server.route({
        method: 'POST',
        path: '/v1/templates/template',

        async handler(request) {
            try {
                if (request.payload.account) {
                    // throws if account does not exist
                    let accountObject = new Account({ redis, account: request.payload.account, call, secret: await getSecret() });
                    await accountObject.loadAccountData();
                }

                return await templates.create(
                    request.payload.account,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    request.payload.content
                );
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Create template',
            notes: 'Create a new stored template. Templates can be used when sending emails as the content of the message.',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string().allow(null).max(256).example('example').required().description('Account ID. Use `null` for public templates.'),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText
                    })
                        .required()
                        .label('CreateTemplateContent')
                }).label('CreateTemplate')
            },

            response: {
                schema: Joi.object({
                    created: Joi.boolean().description('Was the template created or not'),
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    id: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('CreateTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                let meta = {};
                for (let key of ['name', 'description', 'format']) {
                    if (typeof request.payload[key] !== 'undefined') {
                        meta[key] = request.payload[key];
                    }
                }

                return await templates.update(request.params.template, meta, request.payload.content);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Update a template',
            notes: 'Update a stored template.',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest'),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('Transaction receipt').description('Name of the template').label('TemplateName'),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .empty('')
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText
                    }).label('UpdateTemplateContent')
                }).label('UpdateTemplate')
            },

            response: {
                schema: Joi.object({
                    updated: Joi.boolean().description('Was the template updated or not'),
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    id: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('UpdateTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/templates',

        async handler(request) {
            try {
                if (request.query.account) {
                    // throws if account does not exist
                    let accountObject = new Account({ redis, account: request.query.account, call, secret: await getSecret() });
                    await accountObject.loadAccountData();
                }

                return await templates.list(request.query.account, request.query.page, request.query.pageSize);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'List account templates',
            notes: 'Lists stored templates for the account',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    account: Joi.string().empty('').max(256).example('example').description('Account ID to list the templates for'),

                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('AccountTemplatesRequest')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),

                    templates: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID'),
                                name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                                description: Joi.string()
                                    .allow('')
                                    .max(1024)
                                    .example('Something about the template')
                                    .description('Optional description of the template')
                                    .label('TemplateDescription'),
                                format: Joi.string()
                                    .valid('html', 'mjml', 'markdown')
                                    .default('html')
                                    .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was created'),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was last updated')
                            }).label('AccountTemplate')
                        )
                        .label('AccountTemplatesList')
                }).label('AccountTemplatesResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                return await templates.get(request.params.template);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Get template information',
            notes: 'Retrieve template content and information',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,
                params: Joi.object({
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID'),
                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was created'),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was last updated'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText,
                        format: Joi.string()
                            .valid('html', 'mjml', 'markdown')
                            .default('html')
                            .description('Markup language for HTML ("html", "markdown" or "mjml")')
                    }).label('RequestTemplateContent')
                }).label('AccountTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                return await templates.del(request.params.template);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Remove a template',
            notes: 'Delete a stored template',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the template deleted'),
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID')
                }).label('DeleteTemplateRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/templates/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();

                return await templates.flush(request.params.account);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Flush templates',
            notes: 'Delete all stored templates for an account',
            tags: ['api', 'Templates'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('GetTemplateRequest'),

                query: Joi.object({
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .valid(true)
                        .description('Must be true in order to flush templates')
                        .label('ForceFlush')
                }).label('FlushTemplateQuerye')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account flushed'),
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('DeleteTemplateRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/gateways',

        async handler(request) {
            try {
                let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });

                return await gatewayObject.listGateways(request.query.page, request.query.pageSize);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'List gateways',
            notes: 'Lists registered gateways',
            tags: ['api', 'SMTP Gateway'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                }).label('GatewaysFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),

                    gateways: Joi.array()
                        .items(
                            Joi.object({
                                gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                                name: Joi.string().max(256).example('My Email Gateway').description('Display name for the gateway'),
                                deliveries: Joi.number().empty('').example(100).description('Count of email deliveries using this gateway'),
                                lastUse: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last delivery time'),
                                lastError: lastErrorSchema.allow(null)
                            }).label('GatewayResponseItem')
                        )
                        .label('GatewayEntries')
                }).label('GatewaysFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/gateway/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });
            try {
                let gatewayData = await gatewayObject.loadGatewayData();

                // remove secrets
                if (gatewayData.pass) {
                    gatewayData.pass = '******';
                }

                let result = {};

                for (let key of ['gateway', 'name', 'host', 'port', 'user', 'pass', 'secure', 'deliveries', 'lastUse', 'lastError']) {
                    if (key in gatewayData) {
                        result[key] = gatewayData[key];
                    }
                }

                return result;
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Get gateway info',
            notes: 'Returns stored information about the gateway. Passwords are not included.',
            tags: ['api', 'SMTP Gateway'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                })
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),

                    name: Joi.string().max(256).required().example('My Email Gateway').description('Display name for the gateway'),
                    deliveries: Joi.number().empty('').example(100).description('Count of email deliveries using this gateway'),
                    lastUse: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last delivery time'),

                    user: Joi.string().empty('').trim().max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).label('Password'),
                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),
                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS'),

                    lastError: lastErrorSchema.allow(null)
                }).label('GatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/gateway',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, call, secret: await getSecret() });

            try {
                let result = await gatewayObject.create(request.payload);
                return result;
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Register new gateway',
            notes: 'Registers a new SMP gateway',
            tags: ['api', 'SMTP Gateway'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID').required(),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().default(null).max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),
                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                }).label('CreateGateway')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                    state: Joi.string().required().valid('existing', 'new').example('new').description('Is the gateway new or updated existing')
                }).label('CreateGatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/gateway/edit/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });

            try {
                return await gatewayObject.update(request.payload);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Update gateway info',
            notes: 'Updates gateway information',
            tags: ['api', 'SMTP Gateway'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name'),

                    user: Joi.string().empty('').trim().max(1024).allow(null).label('UserName'),
                    pass: Joi.string().empty('').max(1024).allow(null).label('Password'),

                    host: Joi.string().hostname().empty('').example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .min(1)
                        .empty('')
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),
                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                }).label('UpdateGateway')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }).label('UpdateGatewayResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/gateway/{gateway}',

        async handler(request) {
            let gatewayObject = new Gateway({
                redis,
                gateway: request.params.gateway,
                secret: await getSecret()
            });

            try {
                return await gatewayObject.delete();
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Remove SMTP gateway',
            notes: 'Delete SMTP gateway data',
            tags: ['api', 'SMTP Gateway'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID')
                }).label('DeleteRequest')
            },

            response: {
                schema: Joi.object({
                    gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the gateway deleted')
                }).label('DeleteRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/oauth-token',

        async handler(request) {
            let enableOAuthTokensApi = await settings.get('enableOAuthTokensApi');
            if (!enableOAuthTokensApi) {
                let error = Boom.boomify(new Error('Disabled API endpoint'), { statusCode: 403 });
                error.output.payload.code = 'ApiEndpointDisabled';
                throw error;
            }

            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                // throws if account does not exist
                let accountData = await accountObject.loadAccountData();
                if (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.user || !accountData.oauth2.provider) {
                    let error = Boom.boomify(new Error('Not an OAuth2 account'), { statusCode: 403 });
                    error.output.payload.code = 'AccountNotOAuth2';
                    throw error;
                }

                let now = Date.now();
                let accessToken;
                let cached = false;
                if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
                    // renew access token
                    try {
                        accountData = await accountObject.renewAccessToken();
                        accessToken = accountData.oauth2.accessToken;
                    } catch (err) {
                        let error = Boom.boomify(err, { statusCode: 403 });
                        error.output.payload.code = 'OauthRenewError';
                        error.output.payload.authenticationFailed = true;
                        if (err.tokenRequest) {
                            error.output.payload.tokenRequest = err.tokenRequest;
                        }
                        throw error;
                    }
                } else {
                    accessToken = accountData.oauth2.accessToken;
                    cached = true;
                }

                return {
                    account: accountData.account,
                    user: accountData.oauth2.auth.user,
                    accessToken,
                    provider: accountData.oauth2.auth.provider,
                    registeredScopes: accountData.oauth2.scope,
                    expires:
                        accountData.oauth2.expires && typeof accountData.oauth2.expires.toISOString === 'function'
                            ? accountData.oauth2.expires.toISOString()
                            : accountData.oauth2.expires,
                    cached
                };
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
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
            description: 'Get OAuth2 access token',
            notes: 'Get the active OAuth2 access token for an account. NB! This endpoint is disabled by default and needs activation on the Service configuration page.',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

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
                    user: Joi.string().max(256).required().example('user@example.com').description('Username'),
                    accessToken: Joi.string().max(256).required().example('aGVsbG8gd29ybGQ=').description('Access Token'),
                    provider: Joi.string().max(256).required().example('google').description('OAuth2 provider')
                }).label('AccountTokenResponse'),
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

            let subexp = await settings.get('subexp');
            if (subexp) {
                let delayMs = new Date(subexp) - Date.now();
                let expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);

                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'danger',
                    icon: 'exclamation-triangle',
                    message: `The license key needs to be renewed or replaced in ${expiresDays} day${expiresDays !== 1 ? 's' : ''}`
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
                    message: `Your ${licenseDetails.trial ? `trial ` : ''}license key will expire in ${licenseDetails.expiresDays} day${
                        licenseDetails.expiresDays !== 1 ? 's' : ''
                    }`
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
                showDocumentStore: (await settings.get('labsDocumentStore')) || (await settings.get('documentStoreEnabled')),
                showMailRu: (await settings.get('labsMailRu')) || (await settings.get('mailRuEnabled'))
            };
        }
    });

    const preResponse = async (request, h) => {
        let response = request.response;

        if (assertPreconditionResult && request.route && request.route.settings && request.route.settings.tags && request.route.settings.tags.includes('api')) {
            response = assertPreconditionResult;
        }

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

    // trigger a request to cache swagger.json
    setImmediate(() => {
        server
            .inject({
                method: 'get',
                url: '/swagger.json'
            })
            .then(res => {
                logger.debug({ msg: 'Triggered swagger caching request', statusCode: res.statusCode });
            })
            .catch(err => {
                logger.debug({ msg: 'Failed to trigger swagger caching request', err });
            });
    });

    // renew TLS certificates if needed
    setInterval(() => {
        async function handler() {
            let serviceDomain = await getServiceDomain();
            let currentCert = await certHandler.getCertificate(serviceDomain, true);

            try {
                await assertPreconditions(redis);
                assertPreconditionResult = false;
            } catch (err) {
                assertPreconditionResult = Boom.boomify(err);
            }

            if (
                currentCert &&
                currentCert.validTo < new Date(Date.now() - RENEW_TLS_AFTER) &&
                (!currentCert.lastCheck || currentCert.lastCheck < new Date(Date.now() - BLOCK_TLS_RENEW))
            ) {
                try {
                    await certHandler.acquireCert(serviceDomain);
                    await call({ cmd: 'smtpReload' });
                } catch (err) {
                    logger.error({ err });
                } finally {
                    try {
                        await certHandler.setCertificateData(serviceDomain, { lastCheck: new Date() });
                    } catch (err) {
                        logger.error({ msg: 'Failed to set certificate data', serviceDomain, err });
                    }
                }
            }
        }

        handler().catch(err => logger.error({ msg: 'Failed to run certificate handler', err }));
    }, TLS_RENEW_CHECK_INTERVAL).unref();
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
        logger.error({ msg: 'Failed to initialize API', err });
        setImmediate(() => process.exit(3));
    });
