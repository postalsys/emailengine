'use strict';

// NB! This file is processed by gettext parser and can not use newer syntax like ?.

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');
const Path = require('path');
const { loadTranslations, gt, joiLocales } = require('../lib/translations');
const util = require('util');
const { webhooks: Webhooks } = require('../lib/webhooks');
const featureFlags = require('../lib/feature-flags');
const Bell = require('@hapi/bell');
const marked = require('marked');

const fs = require('fs');
const eulaText = marked.parse(
    fs.readFileSync(Path.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), 'utf-8').replace(/\blicenses\.html\b/g, '[licenses.html](/licenses.html)')
);

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
    runPrechecks,
    matcher,
    readEnvValue,
    matchIp,
    getSignedFormData,
    threadStats,
    detectAutomatedRequest,
    hasEnvValue,
    getBoolean,
    loadTlsConfig
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
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
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
const { oauth2Apps, OAUTH_PROVIDERS } = require('../lib/oauth2-apps');

const handlebars = require('handlebars');
const AuthBearer = require('hapi-auth-bearer-token');
const tokens = require('../lib/tokens');
const { autodetectImapSettings } = require('../lib/autodetect-imap-settings');

const Hecks = require('@postalsys/hecks');
const { arenaExpress } = require('../lib/arena-express');
const outbox = require('../lib/outbox');

const { lists } = require('../lib/lists');

const { redis, REDIS_CONF, documentsQueue, notifyQueue, submitQueue } = require('../lib/db');
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
    DEFAULT_CORS_MAX_AGE,
    LIST_UNSUBSCRIBE_NOTIFY,
    FETCH_TIMEOUT,
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_MAX_PAYLOAD_TIMEOUT,
    DEFAULT_EENGINE_TIMEOUT,
    DEFAULT_MAX_ATTACHMENT_SIZE,
    MAX_FORM_TTL,
    NONCE_BYTES,
    OUTLOOK_EXPIRATION_TIME
} = consts;

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

const templateRoutes = require('../lib/api-routes/template-routes');
const chatRoutes = require('../lib/api-routes/chat-routes');

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
    messageUpdateSchema,
    accountSchemas,
    oauthCreateSchema,
    tokenRestrictionsSchema,
    accountIdSchema,
    ipSchema,
    accountCountersSchema,
    accountPathSchema,
    defaultAccountTypeSchema,
    fromAddressSchema,
    outboxEntrySchema,
    googleProjectIdSchema
} = require('../lib/schemas');

const listMessageFolderPathDescription =
    'Mailbox folder path. Can use special use labels like "\\Sent". Special value "\\All" is available for Gmail IMAP, Gmail API, MS Graph API accounts.';

const OAuth2ProviderSchema = Joi.string()
    .valid(...Object.keys(OAUTH_PROVIDERS))
    .required()
    .example('gmail')
    .description('OAuth2 provider')
    .label('OAuth2Provider');

const AccountTypeSchema = Joi.string()
    .valid(...['imap'].concat(Object.keys(OAUTH_PROVIDERS)).concat('oauth2'))
    .example('outlook')
    .description('Account type')
    .required();

const FLAG_SORT_ORDER = ['\\Inbox', '\\Flagged', '\\Sent', '\\Drafts', '\\All', '\\Archive', '\\Junk', '\\Trash'];

const { OUTLOOK_SCOPES } = require('../lib/oauth/outlook');
const { GMAIL_SCOPES } = require('../lib/oauth/gmail');
const { MAIL_RU_SCOPES } = require('../lib/oauth/mail-ru');

const REDACTED_KEYS = ['req.headers.authorization', 'req.headers.cookie', 'err.rawPacket'];

const SMTP_TEST_HOST = 'https://api.nodemailer.com';

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1',
    proxy: false,
    tls: false
};

config.service = config.service || {};

const OKTA_OAUTH2_ISSUER = readEnvValue('OKTA_OAUTH2_ISSUER');
const OKTA_OAUTH2_CLIENT_ID = readEnvValue('OKTA_OAUTH2_CLIENT_ID');
const OKTA_OAUTH2_CLIENT_SECRET = readEnvValue('OKTA_OAUTH2_CLIENT_SECRET');

const OKTA_BASE_URL = OKTA_OAUTH2_ISSUER ? new URL(OKTA_OAUTH2_ISSUER).origin : null;
const USE_OKTA_AUTH = !!(OKTA_OAUTH2_ISSUER && OKTA_OAUTH2_CLIENT_ID && OKTA_OAUTH2_CLIENT_SECRET);

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const MAX_ATTACHMENT_SIZE = getByteSize(readEnvValue('EENGINE_MAX_SIZE') || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

const API_PORT =
    (hasEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (hasEnvValue('PORT') && Number(readEnvValue('PORT'))) || config.api.port;
const API_HOST = readEnvValue('EENGINE_HOST') || config.api.host;

// Either an object (TLS enabled) or `false` (TLS disabled)
const API_TLS = hasEnvValue('EENGINE_API_TLS') ? getBoolean(readEnvValue('EENGINE_API_TLS')) && (config.api.tls || {}) : config.api.tls || false;

// Merge TLS settings from config params and environment
loadTlsConfig(API_TLS, 'EENGINE_API_TLS_');

const IMAP_WORKER_COUNT = getWorkerCount(readEnvValue('EENGINE_WORKERS') || (config.workers && config.workers.imap)) || 4;

// Max POST body size for message uploads
// NB! the default for other requests is 1MB
const MAX_BODY_SIZE = getByteSize(readEnvValue('EENGINE_MAX_BODY_SIZE') || config.api.maxBodySize) || DEFAULT_MAX_BODY_SIZE;

// Payload reception timeout in milliseconds for message upload requests
const MAX_PAYLOAD_TIMEOUT = getDuration(readEnvValue('EENGINE_MAX_PAYLOAD_TIMEOUT') || config.api.maxPayloadTimeout) || DEFAULT_MAX_PAYLOAD_TIMEOUT;

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
          additionalHeaders: ['X-EE-Timeout'],
          additionalExposedHeaders: ['Accept'],
          preflightStatusCode: 204,
          maxAge:
              getDuration(readEnvValue('EENGINE_CORS_MAX_AGE') || (config.cors && config.cors.maxAge), {
                  seconds: true
              }) || DEFAULT_CORS_MAX_AGE,
          credentials: true
      };

logger.info({
    msg: 'API server configuration',
    api: {
        port: API_PORT,
        host: API_HOST,
        maxPayloadTimeout: MAX_PAYLOAD_TIMEOUT,
        maxBodySize: MAX_BODY_SIZE,
        maxSize: MAX_ATTACHMENT_SIZE
    },
    service: {
        commandTimeout: EENGINE_TIMEOUT
    },
    cors: CORS_CONFIG
});

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

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T2]');
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

async function checkRateLimit(key, count, allowed, windowSize) {
    return await call({ cmd: 'rate-limit', key, count, allowed, windowSize });
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

    let serviceUrl = (await settings.get('serviceUrl')) || null;

    let payload = {
        serviceUrl,
        account,
        date: new Date().toISOString()
    };

    if (event) {
        payload.event = event;
    }

    if (data) {
        payload.data = data;
    }

    await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
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

    handlebars.registerHelper('featureFlag', function (flag, options) {
        if (featureFlags.enabled(flag)) {
            return options.fn(this); // eslint-disable-line no-invalid-this
        }
        return options.inverse(this); // eslint-disable-line no-invalid-this
    });

    handlebars.registerHelper('equals', function (compareVal, baseVal, options) {
        if (baseVal === compareVal) {
            return options.fn(this); // eslint-disable-line no-invalid-this
        }
        return options.inverse(this); // eslint-disable-line no-invalid-this
    });

    handlebars.registerHelper('inc', (nr, inc) => Number(nr) + Number(inc));

    handlebars.registerHelper('formatInteger', (intVal, locale) => {
        if (isNaN(intVal)) {
            // ignore non-numbers
            return intVal;
        }

        locale = (locale || 'en_US').replace(/_/g, '-');

        let formatter;
        try {
            formatter = new Intl.NumberFormat(locale, {});
        } catch (err) {
            formatter = new Intl.NumberFormat('en-US', {});
        }

        return formatter.format(intVal);
    });

    const server = Hapi.server({
        port: API_PORT,
        host: API_HOST,
        tls: API_TLS,

        state: {
            strictHeader: false
        },

        router: {
            stripTrailingSlash: true
        },
        routes: {
            validate: {
                options: {
                    messages: joiLocales,
                    convert: true
                },
                headers: Joi.object({
                    'x-ee-timeout': Joi.number()
                        .integer()
                        .min(0)
                        .max(2 * 3600 * 1000)
                        .optional()
                        .description(`Override the \`EENGINE_TIMEOUT\` environment variable for a single API request (in milliseconds)`)
                        .label('X-EE-Timeout')
                }).unknown()
            }
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

    server.decorate('toolkit', 'checkRateLimit', checkRateLimit);

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
        if (disableTokens && !request.url.searchParams.get('access_token') && !request.headers.authorization) {
            // make sure that we have a access_token value set in query args
            let url = new URL(request.url.href);
            url.searchParams.set('access_token', 'preauth');
            request.setUrl(`${url.pathname}${url.search}`);
        }

        // make license info available for the request
        request.app.licenseInfo = await call({ cmd: 'license', timeout: request.headers['x-ee-timeout'] });

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
            if (disableTokens && (!token || token === 'preauth')) {
                // tokens checks are disabled, allow all if token is not set
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

                let error = Boom.forbidden('Unauthorized scope');
                error.output.payload.requestedScope = scope;
                throw error;
            }

            if (tokenData.account) {
                // account token

                let accountIdSource;

                // allow specific routes that have an account component but not in the URL params section
                switch (request.route.path) {
                    case '/v1/templates':
                        switch (request.method) {
                            case 'get':
                                accountIdSource = request.query && request.query.account;
                                break;
                        }
                        break;

                    case '/v1/templates/template/{template}': {
                        let isAccountTemplate =
                            request.params.template && (await redis.sismember(`${REDIS_PREFIX}tpl:${tokenData.account}:i`, request.params.template));
                        if (isAccountTemplate) {
                            accountIdSource = tokenData.account;
                        }
                        break;
                    }

                    case '/v1/templates/template': {
                        switch (request.method) {
                            case 'post':
                                request.app.enforceAccount = tokenData.account;
                                accountIdSource = tokenData.account;
                                break;
                        }
                        break;
                    }

                    default:
                        accountIdSource = request.params && request.params.account;
                        break;
                }

                if (accountIdSource !== tokenData.account) {
                    logger.error({
                        msg: 'Trying to use invalid account for a token',
                        tokenAccount: tokenData.account,
                        tokenId: tokenData.id,
                        account: (request.params && request.params.account) || null
                    });

                    let error = Boom.forbidden('Unauthorized account');
                    throw error;
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

                    let error = Boom.forbidden('Unauthorized address');
                    error.output.payload.remoteAddress = request.app.ip;
                    throw error;
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

                    let error = Boom.forbidden('Unauthorized referrer');
                    throw error;
                }

                if (tokenData.restrictions.rateLimit) {
                    let rateLimit = await checkRateLimit(
                        `api:${tokenData.id}`,
                        1,
                        tokenData.restrictions.rateLimit.maxRequests,
                        tokenData.restrictions.rateLimit.timeWindow
                    );

                    if (!rateLimit.success) {
                        logger.error({ msg: 'Rate limited', token: tokenData.id, rateLimit });
                        let error = Boom.tooManyRequests('Rate limit exceeded');
                        error.output.payload.ttl = Math.ceil(rateLimit.ttl);
                        error.output.headers = {
                            'X-RateLimit-Limit': rateLimit.allowed,
                            'X-RateLimit-Reset': Math.ceil(rateLimit.ttl)
                        };
                        throw error;
                    } else {
                        request.app.rateLimitHeaders = {
                            'X-RateLimit-Limit': rateLimit.allowed,
                            'X-RateLimit-Reset': Math.ceil(rateLimit.ttl),
                            'X-RateLimit-Remaining': rateLimit.allowed - rateLimit.count
                        };
                    }
                }
            }

            return { isValid: true, credentials: { token }, artifacts: tokenData };
        }
    });

    // needed for auth session and flash messages
    await server.register(Cookie);
    await server.register(Bell);

    let secureCookie = false;
    try {
        let serviceUrl = await settings.get('serviceUrl');
        if (serviceUrl) {
            let parsedUrl = new URL(serviceUrl);
            secureCookie = parsedUrl.protocol === 'https:';
        }
    } catch (err) {
        // skip
    }

    // Authentication for admin pages
    server.auth.strategy('session', 'cookie', {
        cookie: {
            name: 'ee',
            password: await settings.get('cookiePassword'),
            isSecure: secureCookie,
            path: '/',
            isSameSite: 'Lax'
        },
        appendNext: true,
        redirectTo: '/admin/login',

        async validate(request, session) {
            switch (session.provider) {
                case 'okta': {
                    if (session.profile && session.profile.id) {
                        let profile = session.profile;
                        return {
                            isValid: true,
                            credentials: {
                                enabled: true,
                                user: profile.username
                            }
                        };
                    }
                }
            }

            const authData = await settings.get('authData');
            if (!authData) {
                return { isValid: true, credentials: { enabled: false } };
            }

            if (authData.passwordVersion && authData.passwordVersion !== session.passwordVersion) {
                // force logout
                return { isValid: false };
            }

            const account = authData.user === session.user;

            if (!account) {
                return { isValid: false };
            }

            // unless it is a login or TOPT (or public) page, require TOTP code
            if (session.requireTotp && !['/{any*}', '/admin/totp', '/admin/login'].includes(request.route && request.route.path)) {
                request.requireTotp = true;
            }

            authData.name = authData.name || authData.user;
            return {
                isValid: true,
                credentials: {
                    enabled: true,
                    user: authData.user
                },
                artifacts: authData
            };
        }
    });

    if (USE_OKTA_AUTH) {
        let redirectUrl = new URL((await settings.get('serviceUrl')) || `http://${API_HOST}${API_PORT !== 80 ? `:${API_PORT}` : ''}`);

        server.decorate('toolkit', 'validateOktaConfig', async () => {
            let activeRedirectUrl = new URL((await settings.get('serviceUrl')) || `http://${API_HOST}${API_PORT !== 80 ? `:${API_PORT}` : ''}`);
            return activeRedirectUrl.origin === redirectUrl.origin && USE_OKTA_AUTH;
        });

        server.auth.strategy('okta', 'bell', {
            provider: 'okta',
            config: {
                uri: OKTA_BASE_URL
            },
            password: await settings.get('cookiePassword'),
            isSecure: secureCookie,
            location: redirectUrl.origin,

            clientId: OKTA_OAUTH2_CLIENT_ID,
            clientSecret: OKTA_OAUTH2_CLIENT_SECRET
        });

        server.route({
            method: ['GET', 'POST'],
            path: '/admin/login/okta',
            handler(request, h) {
                if (!request.auth.isAuthenticated) {
                    let error = Boom.unauthorized('Failed to authorize user');
                    error.output.payload.details = [request.auth.error.message];
                    throw error;
                }
                request.cookieAuth.set(request.auth.credentials);
                return h.redirect('/admin');
            },
            options: {
                auth: {
                    mode: 'try',
                    strategy: 'okta'
                }
            }
        });
    }

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
        async handler(request, h) {
            return h.view(
                'index',
                {},
                {
                    layout: 'main'
                }
            );
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
        path: '/sbom.json',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'sbom.json'), confine: false }
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/license.html',
        async handler(request, h) {
            return h.view(
                'license',
                {
                    eulaText
                },
                {
                    layout: 'main'
                }
            );
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
        method: 'OPTIONS',
        path: '/v1/{any*}',
        handler: async (request, reply) => {
            const method = request.headers['access-control-request-method'];
            const response = reply.response(Buffer.alloc(0));

            if (method) {
                response.header('Access-Control-Allow-Methods', method);
            }

            return response.code(200);
        },
        options: {
            auth: false,
            cors: CORS_CONFIG
        }
    });

    server.route({
        method: 'GET',
        path: '/health',
        async handler(request) {
            const imapWorkerCount = await call({ cmd: 'imapWorkerCount', timeout: request.headers['x-ee-timeout'] });
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

            if (!(await detectAutomatedRequest(request.app.ip))) {
                await sendWebhook(data.acc, TRACK_CLICK_NOTIFY, {
                    messageId: data.msg,
                    url: data.url,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });
            } else {
                request.logger.info({
                    msg: 'Detected automated request',
                    account: data.acc,
                    event: TRACK_CLICK_NOTIFY,
                    messageId: data.msg,
                    url: data.url,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });
            }

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

            if (!(await detectAutomatedRequest(request.app.ip))) {
                await sendWebhook(data.acc, TRACK_OPEN_NOTIFY, {
                    messageId: data.msg,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });
            } else {
                request.logger.info({
                    msg: 'Detected automated request',
                    account: data.acc,
                    event: TRACK_OPEN_NOTIFY,
                    messageId: data.msg,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });
            }

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
        method: 'POST',
        path: '/unsubscribe',
        async handler(request) {
            // NB! Avoid throwing errors

            let data = Buffer.from(request.query.data, 'base64url').toString();
            let serviceSecret = await settings.get('serviceSecret');
            if (serviceSecret) {
                let hmac = crypto.createHmac('sha256', serviceSecret);
                hmac.update(data);
                if (hmac.digest('base64url') !== request.query.sig) {
                    return 'data validation failed';
                }
            }

            data = JSON.parse(data);

            if (!data || typeof data !== 'object' || data.act !== 'unsub') {
                return 'not ok';
            }

            let accountObject = new Account({
                redis,
                account: data.acc,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();
            } catch (err) {
                return 'unknown account';
            }

            let isNew = await redis.eeListAdd(
                `${REDIS_PREFIX}lists:unsub:lists`,
                `${REDIS_PREFIX}lists:unsub:entries:${data.list}`,
                data.list,
                data.rcpt.toLowerCase().trim(),
                JSON.stringify({
                    recipient: data.rcpt,
                    account: data.acc,
                    source: 'one-click',
                    reason: 'unsubscribe',
                    messageId: data.msg,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent'],
                    created: new Date().toISOString()
                })
            );

            if (isNew) {
                await sendWebhook(data.acc, LIST_UNSUBSCRIBE_NOTIFY, {
                    recipient: data.rcpt,
                    messageId: data.msg,
                    listId: data.list,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });
            }

            return 'ok';
        },
        options: {
            description: 'One-click unsubscribe',

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
                }).label('OneClickUnsubQuery'),

                payload: Joi.object({
                    'List-Unsubscribe': Joi.string().required().valid('One-Click')
                }).label('OneClickUnsubPayload')
            },

            plugins: {
                crumb: false
            },

            auth: false
        }
    });

    server.route({
        method: 'POST',
        path: '/oauth/msg/notification',
        async handler(request, h) {
            if (request.query.validationToken) {
                request.logger.debug({
                    msg: 'MS Graph subscription event',
                    type: 'notification',
                    account: request.query.account,
                    validationToken: request.query.validationToken
                });
                return h.response(request.query.validationToken).header('Content-Type', 'text/plain').code(200);
            }

            let accountObject = new Account({
                account: request.query.account,
                redis,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            let accountData = await accountObject.loadAccountData();
            if (!accountData.outlookSubscription) {
                request.logger.error({ msg: 'Subscription not found for account', account: request.query.account, payload: request.payload });
                return h.response(Buffer.alloc(0)).code(202);
            }

            const outlookSubscription = accountData.outlookSubscription;

            for (let entry of (request.payload && request.payload.value) || []) {
                // enumerate and queue all entries
                if (entry.subscriptionId !== outlookSubscription.id || entry.clientState !== outlookSubscription.clientState) {
                    request.logger.error({
                        msg: 'Invalid subcsription details',
                        account: request.query.account,
                        expected: {
                            subscriptionId: outlookSubscription.id,
                            clientState: outlookSubscription.clientState
                        },
                        actual: {
                            subscriptionId: entry.subscriptionId,
                            clientState: entry.clientState
                        },
                        entry
                    });
                    continue;
                }

                let event = {
                    type: entry.changeType,
                    message: entry.resourceData && entry.resourceData.id
                };

                await accountObject.pushQueueEvent(event);
            }

            return h.response(Buffer.alloc(0)).code(202);
        },
        options: {
            description: 'MS Graph API notification handler',

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    account: accountIdSchema.required(),
                    validationToken: Joi.string()
                }).label('MSGNotificationQuery')
            },

            plugins: {
                crumb: false
            },

            auth: false
        }
    });

    server.route({
        method: 'POST',
        path: '/oauth/msg/lifecycle',
        async handler(request, h) {
            if (request.query.validationToken) {
                request.logger.debug({
                    msg: 'MS Graph subscription event',
                    type: 'lifecycle',
                    account: request.query.account,
                    validationToken: request.query.validationToken
                });
                return h.response(request.query.validationToken).header('Content-Type', 'text/plain').code(200);
            }

            let accountObject = new Account({
                account: request.query.account,
                redis,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            let accountData = await accountObject.loadAccountData();
            if (!accountData.outlookSubscription) {
                request.logger.error({ msg: 'Subscription not found for account', account: request.query.account, payload: request.payload });
                return h.response(Buffer.alloc(0)).code(202);
            }

            const outlookSubscription = accountData.outlookSubscription;

            for (let entry of (request.payload && request.payload.value) || []) {
                request.logger.debug({
                    msg: 'MS Graph subscription event',
                    type: 'lifecycle',
                    account: request.query.account,
                    lifecycleEvent: entry.lifecycleEvent,
                    subscriptionId: entry.subscriptionId
                });

                // enumerate and queue all entries
                if (entry.subscriptionId !== outlookSubscription.id || entry.clientState !== outlookSubscription.clientState) {
                    request.logger.error({
                        msg: 'Invalid subcsription details',
                        account: request.query.account,
                        expected: {
                            subscriptionId: outlookSubscription.id,
                            clientState: outlookSubscription.clientState
                        },
                        actual: {
                            subscriptionId: entry.subscriptionId,
                            clientState: entry.clientState
                        },
                        entry
                    });
                    continue;
                }

                switch (entry.lifecycleEvent) {
                    case 'reauthorizationRequired': {
                        // Extend subscription lifetime

                        outlookSubscription.state = {
                            state: 'renewing',
                            time: Date.now()
                        };
                        await accountObject.update({ outlookSubscription });

                        let subscriptionPayload = {
                            expirationDateTime: new Date(Date.now() + OUTLOOK_EXPIRATION_TIME).toISOString()
                        };

                        let subscriptionRes;
                        try {
                            subscriptionRes = await accountObject.oauth2Request(
                                `https://graph.microsoft.com/v1.0/subscriptions/${outlookSubscription.id}`,
                                'PATCH',
                                subscriptionPayload
                            );
                            if (subscriptionRes && subscriptionRes.expirationDateTime) {
                                outlookSubscription.expirationDateTime = subscriptionRes.expirationDateTime;
                            }
                            outlookSubscription.state = {
                                state: 'created',
                                time: Date.now()
                            };
                        } catch (err) {
                            outlookSubscription.state = {
                                state: 'error',
                                error: `Renewal failed: ${
                                    (err.oauthRequest &&
                                        err.oauthRequest.response &&
                                        err.oauthRequest.response.error &&
                                        err.oauthRequest.response.error.message) ||
                                    err.message
                                }`,
                                time: Date.now()
                            };
                        } finally {
                            await accountObject.update({ outlookSubscription });
                        }

                        break;
                    }

                    case 'subscriptionRemoved': {
                        // subscription was removed, should we recreate it?
                        await accountObject.update({
                            outlookSubscription: {
                                state: {
                                    state: 'error',
                                    error: `Subscription removed`,
                                    time: Date.now()
                                }
                            }
                        });
                        break;
                    }
                }
            }

            return h.response(Buffer.alloc(0)).code(202);
        },
        options: {
            description: 'MS Graph API notification handler',

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                failAction
            },

            plugins: {
                crumb: false
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

            if (!accountData.account) {
                accountData.account = null;
            }

            const accountMeta = accountData._meta || {};
            delete accountData._meta;

            const redirectUrl = accountMeta.redirectUrl;

            const provider = accountData.oauth2.provider;

            const oauth2App = await oauth2Apps.get(provider);
            if (!oauth2App) {
                let error = Boom.boomify(new Error('Missing or disabled OAuth2 app'), { statusCode: 404 });
                throw error;
            }

            const oAuth2Client = await oauth2Apps.getClient(oauth2App.id);

            // `app.provider` is for example "gmail", `provider` is oauth2 app id
            switch (oauth2App.provider) {
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

                    const defaultScopes = (oauth2App.baseScopes && GMAIL_SCOPES[oauth2App.baseScopes]) || GMAIL_SCOPES.imap;

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : defaultScopes,
                            tokenType: r.token_type
                        },
                        {
                            auth: {
                                user: profileRes.emailAddress
                            }
                        }
                    );

                    accountData.googleHistoryId = Number(profileRes.historyId) || null;

                    request.logger.info({ msg: 'Provisioned OAuth2 tokens', user: profileRes.emailAddress, provider: oauth2App.provider });
                    break;
                }

                case 'outlook': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    let userInfo = {};

                    if (!oauth2App.baseScopes || oauth2App.baseScopes === 'imap') {
                        // Read account info from GET arguments
                        // This is needed because previously EmailEngine did not request for the User.Read scope

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
                                        userInfo.username = decodedValue.preferred_username;
                                    }
                                } catch (err) {
                                    request.logger.error({ msg: 'Failed to decode JWT payload', err, encodedValue });
                                }
                            }
                        }
                    } else {
                        // Request profile info from API

                        let profileRes;
                        try {
                            profileRes = await oAuth2Client.request(r.access_token, 'https://graph.microsoft.com/v1.0/me');
                        } catch (err) {
                            let response = err.oauthRequest && err.oauthRequest.response;
                            if (response && response.error) {
                                let message = response.error.message;
                                let error = Boom.boomify(new Error(message), { statusCode: response.error.code });
                                throw error;
                            }
                            throw err;
                        }

                        if (profileRes.displayName) {
                            userInfo.name = profileRes.displayName;
                        }

                        if (profileRes.mail) {
                            userInfo.email = profileRes.mail;
                        }

                        if (profileRes.userPrincipalName) {
                            userInfo.username = profileRes.userPrincipalName;
                        }
                    }

                    const authData = {
                        user: userInfo.username || userInfo.email
                    };

                    if (!authData.user) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    if (accountData.delegated && accountData.email && accountData.email !== userInfo.email) {
                        // Shared mailbox
                        authData.delegatedUser = accountData.email;
                    } else {
                        accountData.email = userInfo.email;
                    }

                    accountData.name = accountData.name || userInfo.name || '';

                    const defaultScopes = (oauth2App.baseScopes && OUTLOOK_SCOPES[oauth2App.baseScopes]) || OUTLOOK_SCOPES.imap;

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : defaultScopes,
                            tokenType: r.token_type
                        },
                        {
                            auth: authData
                        }
                    );

                    request.logger.info({ msg: 'Provisioned OAuth2 tokens', user: userInfo.email, provider: oauth2App.provider });
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

                    request.logger.info({ msg: 'Provisioned OAuth2 tokens', user: profileRes.email, provider: oauth2App.provider });
                    break;
                }

                default: {
                    throw new Error('Unknown OAuth2 provider');
                }
            }

            if ('delegated' in accountData) {
                // remove artefacts
                delete accountData.delegated;
            }

            let accountObject = new Account({
                redis,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });
            let result = await accountObject.create(accountData);

            if (accountMeta.n) {
                // store nonce to prevent this URL to be reused
                const keyName = `${REDIS_PREFIX}account:form:${accountMeta.n}`;
                try {
                    await redis
                        .multi()
                        .set(keyName, (accountMeta.t || '0').toString())
                        .expire(keyName, Math.floor(MAX_FORM_TTL / 1000))
                        .exec();
                } catch (err) {
                    request.logger.error({ msg: 'Failed to set nonce for an account form request', err });
                }
            }

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
            let accountObject = new Account({
                redis,
                account: request.payload.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required(),

                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),

                    scopes: Joi.array()
                        .items(Joi.string().valid('api', 'smtp', 'imap-proxy').label('TokenScope'))
                        .single()
                        .default(['api'])
                        .required()
                        .label('Scopes'),

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

                    restrictions: tokenRestrictionsSchema,

                    ip: ipSchema.description('IP address of the requestor').label('TokenIP')
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
                // TODO: allow paging
                return { tokens: (await tokens.list(null, 0, 1000)).tokens };
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
                                account: accountIdSchema.required(),
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
                                ip: ipSchema.description('IP address of the requestor').label('TokenIP')
                            }).label('RootTokensItem')
                        )
                        .label('RootTokensEntries')
                }).label('RootTokensResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/tokens/account/{account}',

        async handler(request) {
            try {
                // TODO: allow paging
                return { tokens: (await tokens.list(request.params.account, 0, 1000)).tokens };
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
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    tokens: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
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

                                restrictions: tokenRestrictionsSchema,

                                ip: ipSchema.description('IP address of the requestor').label('TokenIP')
                            }).label('AccountTokensItem')
                        )
                        .label('AccountTokensEntries')
                }).label('AccountsTokensResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account',

        async handler(request) {
            let accountObject = new Account({
                redis,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                if (request.payload.oauth2 && request.payload.oauth2.authorize) {
                    // redirect to OAuth2 consent screen

                    const oAuth2Client = await oauth2Apps.getClient(request.payload.oauth2.provider);
                    const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64url');

                    const accountData = request.payload;

                    if (accountData.oauth2.redirectUrl) {
                        accountData._meta = {
                            redirectUrl: accountData.oauth2.redirectUrl
                        };
                        delete accountData.oauth2.redirectUrl;
                    }

                    delete accountData.oauth2.authorize; // do not store this property
                    // store account data
                    await redis
                        .multi()
                        .set(`${REDIS_PREFIX}account:add:${nonce}`, JSON.stringify(accountData))
                        .expire(`${REDIS_PREFIX}account:add:${nonce}`, Math.floor(MAX_FORM_TTL / 1000))
                        .exec();

                    // Generate the url that will be used for the consent dialog.
                    let authorizeUrl;
                    switch (oAuth2Client.provider) {
                        case 'gmail': {
                            let requestData = {
                                state: `account:add:${nonce}`
                            };

                            if (accountData.email) {
                                requestData.email = accountData.email;
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
                        .trim()
                        .max(256)
                        .allow(null)
                        .example('example')
                        .description('Account ID. If the provided value is `null` then an unique ID will be autogenerated')
                        .required(),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description('Copy submitted messages to Sent folder. Set to `null` to unset and use provider specific default.'),

                    logs: Joi.boolean().example(false).description('Store recent logs').default(false),

                    notifyFrom: accountSchemas.notifyFrom.default('now'),
                    syncFrom: accountSchemas.syncFrom.default(null),

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.object(imapSchema).allow(false).description('IMAP configuration').label('ImapConfiguration'),

                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SmtpConfiguration'),

                    oauth2: Joi.object(oauth2Schema).allow(false).description('OAuth2 configuration').label('OAuth2'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
                })
                    .label('CreateAccount')
                    .example({
                        account: 'example',
                        name: 'Nyan Cat',
                        email: 'nyan.cat@example.com',
                        imap: {
                            auth: {
                                user: 'nyan.cat',
                                pass: 'sercretpass'
                            },
                            host: 'mail.example.com',
                            port: 993,
                            secure: true
                        },
                        smtp: {
                            auth: {
                                user: 'nyan.cat',
                                pass: 'secretpass'
                            },
                            host: 'mail.example.com',
                            port: 465,
                            secure: true
                        }
                    })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    state: Joi.string()
                        .required()
                        .valid('existing', 'new')
                        .example('new')
                        .description('Is the account new or updated existing')
                        .label('CreateAccountState')
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
                    syncFrom: request.payload.syncFrom,
                    notifyFrom: request.payload.notifyFrom,
                    subconnections: request.payload.subconnections,
                    redirectUrl: request.payload.redirectUrl,
                    delegated: request.payload.delegated,
                    path: request.payload.path && !request.payload.path.includes('*') ? request.payload.path : null,
                    // identify request
                    n: crypto.randomBytes(NONCE_BYTES).toString('base64'),
                    t: Date.now()
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

                if (type && type !== 'imap') {
                    let oauth2app = await oauth2Apps.get(type);
                    if (!oauth2app || !oauth2app.enabled) {
                        type = false;
                    }
                }

                if (!type) {
                    let oauth2apps = (await oauth2Apps.list(0, 100)).apps.filter(app => app.includeInListing);
                    if (!oauth2apps.length) {
                        type = 'imap';
                    }
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
                        .trim()
                        .max(256)
                        .allow(null)
                        .example('example')
                        .default(null)
                        .description(
                            'Account ID. If the provided value is `null` then an unique ID will be autogenerated. Using an existing account ID will update settings for that existing account.'
                        ),

                    name: Joi.string().empty('').max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    delegated: Joi.boolean()
                        .empty('')
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true then acts as a shared mailbox. Available for MS365 OAuth2 accounts.'),

                    syncFrom: accountSchemas.syncFrom,
                    notifyFrom: accountSchemas.notifyFrom,

                    subconnections: accountSchemas.subconnections,

                    path: accountPathSchema.example(['*']).label('AccountFormPath'),

                    redirectUrl: Joi.string()
                        .empty('')
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .required()
                        .example('https://myapp/account/settings.php')
                        .description('The user will be redirected to this URL after submitting the authentication form'),

                    type: defaultAccountTypeSchema
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description('Copy submitted messages to Sent folder. Set to `null` to unset and use provider specific default.'),

                    logs: Joi.boolean().example(false).description('Store recent logs'),

                    notifyFrom: accountSchemas.notifyFrom,
                    syncFrom: accountSchemas.syncFrom,

                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.object(imapUpdateSchema).allow(false).description('IMAP configuration').label('IMAPUpdate'),
                    smtp: Joi.object(smtpUpdateSchema).allow(false).description('SMTP configuration').label('SMTPUpdate'),
                    oauth2: Joi.object(oauth2UpdateSchema).allow(false).description('OAuth2 configuration').label('OAuth2Update'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
                })
                    .label('UpdateAccount')
                    .example({
                        name: 'Nyan Cat',
                        email: 'nyan.cat@example.com',
                        imap: {
                            partial: true,
                            disabled: true
                        },
                        smtp: {
                            partial: true,
                            host: 'mail.example.com'
                        }
                    })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required()
                }),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/reconnect',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
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
                documentsQueue,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
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
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/flush',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return { flush: await accountObject.flush(request.payload) };
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
            description: 'Request account flush',
            notes: 'Deletes all email indexes from Redis and ElasticSearch and re-creates the index for that account. You can only run a single flush operation at a time, so you must wait until the previous flush has finished before initiating a new one.',
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
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    flush: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only flush the account if true'),
                    notifyFrom: accountSchemas.notifyFrom.default('now'),
                    syncFrom: accountSchemas.syncFrom
                }).label('RequestFlush')
            },

            response: {
                schema: Joi.object({
                    flush: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Flush status')
                }).label('RequestFlushResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/accounts',

        async handler(request) {
            try {
                let accountObject = new Account({
                    redis,
                    account: request.params.account,
                    call,
                    secret: await getSecret(),
                    timeout: request.headers['x-ee-timeout']
                });

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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
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
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    accounts: Joi.array()
                        .items(
                            Joi.object({
                                account: accountIdSchema.required(),
                                name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                                email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),
                                type: AccountTypeSchema,
                                app: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
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
                                smtpEhloName: settingsSchema.smtpEhloName,

                                counters: accountCountersSchema,

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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });
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
                    'logs',
                    'notifyFrom',
                    'syncFrom',
                    'path',
                    'subconnections',
                    'webhooks',
                    'proxy',
                    'smtpEhloName',
                    'imap',
                    'smtp',
                    'oauth2',
                    'state',
                    'smtpStatus',
                    'syncError',
                    'connections',
                    'webhooksCustomHeaders',
                    'locale',
                    'tz'
                ]) {
                    if (key in accountData) {
                        result[key] = accountData[key];
                    }
                }

                // default false
                for (let key of ['logs']) {
                    result[key] = !!result[key];
                }

                // default null
                for (let key of ['notifyFrom', 'syncFrom', 'lastError', 'smtpStatus']) {
                    result[key] = result[key] || null;
                }

                if (accountData.oauth2 && accountData.oauth2.provider) {
                    let app = await oauth2Apps.get(accountData.oauth2.provider);

                    if (app) {
                        result.type = app.provider;
                        if (app.id !== app.provider) {
                            result.app = app.id;
                        }
                    } else {
                        result.type = 'oauth2';
                    }
                } else if (accountData.imap && !accountData.imap.disabled) {
                    result.type = 'imap';
                } else {
                    result.type = 'sending';
                }

                if (accountData.sync) {
                    result.syncTime = accountData.sync;
                }

                if (accountData.state) {
                    result.lastError = accountData.state === 'connected' ? null : accountData.lastErrorState;
                }

                if (accountData.counters) {
                    result.counters = accountData.counters;
                }

                if (request.query.quota) {
                    result.quota = await accountObject.getQuota();
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
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    quota: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then include quota information in the response')
                        .label('AccountQuota')
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),

                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                    email: Joi.string().empty('').email().example('user@example.com').description('Default email address of the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder'),
                    logs: Joi.boolean().example(false).description('Store recent logs'),

                    notifyFrom: accountSchemas.notifyFrom,
                    syncFrom: accountSchemas.syncFrom,

                    path: accountPathSchema.example(['*']).label('AccountPath'),

                    subconnections: accountSchemas.subconnections,

                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://myservice.com/imap/webhooks')
                        .description('Account-specific webhook URL'),
                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,

                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAPResponse'),

                    smtp: Joi.object(smtpSchema).description('SMTP configuration').label('SMTPResponse'),

                    oauth2: Joi.object(oauth2Schema).description('OAuth2 configuration').label('Oauth2Response'),

                    state: Joi.string()
                        .valid('init', 'syncing', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Informational account state')
                        .label('AccountInfoState'),

                    smtpStatus: Joi.object({
                        created: Joi.date()
                            .iso()
                            .allow(null)
                            .example('2021-07-08T07:06:34.336Z')
                            .description('When was the status for SMTP connection last updated'),
                        status: Joi.string().valid('ok', 'error').description('Was the last SMTP attempt successful or not').label('SMTPStatusStatus'),
                        response: Joi.string().example('250 OK').description('SMTP response message for delivery attempt'),
                        description: Joi.string().example('Authentication failed').description('Error information'),
                        responseCode: Joi.number().integer().example(500).description('Error status code'),
                        code: Joi.string().example('EAUTH').description('Error type identifier'),
                        command: Joi.string().example('AUTH PLAIN').description('SMTP command that failed')
                    })
                        .description('Information about the last SMTP connection attempt')
                        .label('SMTPInfoStatus'),

                    webhooksCustomHeaders: settingsSchema.webhooksCustomHeaders.label('AccountWebhooksCustomHeaders'),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone'),

                    type: AccountTypeSchema,
                    app: Joi.string().max(256).example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),

                    counters: accountCountersSchema,

                    quota: Joi.object({
                        usage: Joi.number().integer().example(8547884032).description('How many bytes has the account stored in emails'),
                        limit: Joi.number().integer().example(16106127360).description('How many bytes can the account store emails'),
                        status: Joi.string().example('53%').description('Textual information about the usage')
                    })
                        .label('AccountQuota')
                        .allow(false)
                        .description(
                            'Account quota information if query argument quota=true. This value will be false if the server does not provide quota information.'
                        ),

                    syncTime: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last sync time'),

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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                let mailboxes = await accountObject.getMailboxListing(request.query);

                if (mailboxes && Array.isArray(mailboxes)) {
                    mailboxes = mailboxes.sort((a, b) => {
                        if (a.specialUse && !b.specialUse) {
                            return -1;
                        }
                        if (!a.specialUse && b.specialUse) {
                            return 1;
                        }
                        if (a.specialUse && b.specialUse) {
                            return FLAG_SORT_ORDER.indexOf(a.specialUse) - FLAG_SORT_ORDER.indexOf(b.specialUse);
                        }

                        return a.path.localeCompare(b.path);
                    });
                }

                return { mailboxes };
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
                    account: accountIdSchema.required()
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                if (err.info) {
                    error.output.payload.details = err.info;
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
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    path: Joi.array()
                        .items(Joi.string().max(256))
                        .single()
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array or a string. If account is namespaced then namespace prefix is added by default.')
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
        method: 'PUT',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.renameMailbox(request.payload.path, request.payload.newPath);
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
                    error.output.payload.details = err.info;
                }
                throw error;
            }
        },

        options: {
            description: 'Rename mailbox',
            notes: 'Rename an existing mailbox folder',
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
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('Previous Mail').description('Mailbox folder path to rename').label('ExistingMailboxPath'),
                    newPath: Joi.array()
                        .items(Joi.string().max(256))
                        .single()
                        .example(['Parent folder', 'Subfolder'])
                        .description('New mailbox path as an array or a string. If account is namespaced then namespace prefix is added by default.')
                        .label('TargetMailboxPath')
                }).label('RenameMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Previous Mail').description('Mailbox folder path to rename').label('ExistingMailboxPath'),
                    newPath: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('NewMailboxPath'),
                    renamed: Joi.boolean().example(true).description('Was the mailbox renamed')
                }).label('RenameMailboxResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required(),
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required(),
                    attachment: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(2 * 1024)
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
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
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
                        .integer()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(5 * 1025 * 1024)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default text content is not returned.'),

                    webSafeHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'Shorthand option to fetch and preprocess HTML and inlined images. Overrides `textType`, `preProcessHtml`, and `preProcessHtml` options.'
                        )
                        .label('WebSafeHtml'),

                    embedAttachedImages: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then fetches attached images and embeds these in the HTML as data URIs')
                        .label('EmbedImages'),

                    preProcessHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then pre-processes HTML for compatibility')
                        .label('PreProcess'),

                    markAsSeen: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then marks unseen email as seen while returning the message')
                        .label('MarkAsSeen'),

                    documentStore: documentStoreSchema.default(false)
                }),

                params: Joi.object({
                    account: accountIdSchema.required(),
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
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
                    account: accountIdSchema.required()
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

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'Base64 encoded email message in rfc822 format. If you provide other keys as well then these will override the values in the raw message.'
                        )
                        .label('RFC822Raw'),

                    from: fromAddressSchema,

                    to: Joi.array()
                        .items(addressSchema)
                        .single()
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).single().description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).single().description('List of addresses').label('AddressList'),

                    subject: Joi.string()
                        .allow('')
                        .max(10 * 1024)
                        .example('What a wonderful message')
                        .description('Message subject'),

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
                                    .description('Base64 formatted attachment file')
                                    .when('reference', {
                                        is: Joi.exist().not(false, null),
                                        then: Joi.forbidden(),
                                        otherwise: Joi.required()
                                    }),

                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64'),

                                reference: Joi.string()
                                    .base64({ paddingRequired: false, urlSafe: true })
                                    .max(256)
                                    .allow(false, null)
                                    .example('AAAAAQAACnAcde')
                                    .description(
                                        'Reference an existing attachment ID instead of providing attachment content. If set, then `content` option is not allowed. Otherwise `content` is required.'
                                    )
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
                    uid: Joi.number().integer().example(12345).description('UID of uploaded message'),
                    uidValidity: Joi.string().example('12345').description('UIDVALIDTITY of the target folder. Numeric value cast as string.'),
                    seq: Joi.number().integer().example(12345).description('Sequence number of uploaded message'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        success: Joi.boolean().example(true).description('Was the referenced message processed').label('ResponseReferenceSuccess'),
                        documentStore: documentStoreSchema.default(false),
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required(),
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription)
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required(),
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
                    uid: Joi.number().integer().example(12345).description('UID of moved message')
                }).label('MessageMoveResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/messages/move',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription)
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
                        .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')).label('IdMapTuple'))
                        .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                        .description('An optional map of source and target ID values, if the server provided this info')
                        .label('IdMapArray'),

                    emailIds: Joi.array()
                        .items(Joi.string().example('1278455344230334865'))
                        .description('An optional list of emailId values, if the server supports unique email IDs')
                        .label('EmailIdsArray')
                }).label('MessagesMoveResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                        .description('Delete message even if not in Trash. Not supported for Gmail API accounts.')
                        .label('ForceDelete')
                }).label('MessageDeleteQuery'),

                params: Joi.object({
                    account: accountIdSchema.required(),
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription),
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
                            .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')).label('IdMapTuple'))
                            .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                            .description('An optional map of source and target ID values, if the server provided this info')
                            .label('IdMapArray'),

                        emailIds: Joi.array()
                            .items(Joi.string().example('1278455344230334865'))
                            .description('An optional list of emailId values, if the server supports unique email IDs')
                            .label('EmailIdsArray')
                    })
                        .label('MessagesMovedToTrash')
                        .description('Value is present if messages were moved to Trash')
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
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
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
                        .integer()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(MAX_ATTACHMENT_SIZE)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .default('*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default all contents are returned.'),
                    documentStore: documentStoreSchema.default(false)
                }),

                params: Joi.object({
                    account: accountIdSchema.required(),
                    text: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(10 * 1024)
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
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
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
                    account: accountIdSchema.required().label('AccountId')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description(listMessageFolderPathDescription).label('SpecialPath'),

                    cursor: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024 * 1024)
                        .example('imap_kcQIji3UobDDTxc')
                        .description('Paging cursor from `nextPageCursor` or `prevPageCursor` value')
                        .label('PageCursor'),
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description(
                            'Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts. Deprecated; use the paging cursor instead. If the page cursor value is provided, then the page number value is ignored.'
                        )
                        .label('PageNumber'),

                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
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
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
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
                    account: accountIdSchema.required()
                }),

                query: Joi.object({
                    path: Joi.string()
                        .when('documentStore', {
                            is: true,
                            then: Joi.optional(),
                            otherwise: Joi.required()
                        })
                        .example('INBOX')
                        .description(listMessageFolderPathDescription)
                        .label('Path'),

                    cursor: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024 * 1024)
                        .example('imap_kcQIji3UobDDTxc')
                        .description('Paging cursor from `nextPageCursor` or `prevPageCursor` value')
                        .label('PageCursor'),
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description(
                            'Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts. Deprecated; use the paging cursor instead. If the page cursor value is provided, then the page number value is ignored.'
                        )
                        .label('PageNumber'),

                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page'),
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
                    documentQuery: Joi.object()
                        .min(1)
                        .description('Document Store query. Only allowed with `documentStore`.')
                        .label('DocumentQuery')
                        .unknown()
                        .meta({ swaggerHidden: true })
                })
                    .label('SearchQuery')
                    .example({
                        search: {
                            unseen: true,
                            flagged: true,
                            from: 'nyan.cat@example.com',
                            body: 'Hello world',
                            subject: 'Hello world',
                            sentBefore: '2024-08-09',
                            sentSince: '2022-08-09',
                            emailId: '1278455344230334865',
                            threadId: '1266894439832287888',
                            header: {
                                'Message-ID': '<12345@example.com>'
                            },
                            gmailRaw: 'has:attachment in:unread'
                        }
                    })
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/unified/search',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            let extraValidationErrors = [];

            for (let key of ['seq', 'modseq']) {
                if (request.payload.search && key in request.payload.search) {
                    extraValidationErrors.push({ message: 'Not allowed with documentStore', context: { key } });
                }
            }

            if (extraValidationErrors.length) {
                let error = new Error('Input validation failed');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            let documentStoreEnabled = await settings.get('documentStoreEnabled');
            if (!documentStoreEnabled) {
                let error = new Error('Document store not enabled');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            try {
                return await accountObject.searchMessages(Object.assign({ documentStore: true }, request.query, request.payload), { unified: true });
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
            description: 'Unified search for messages',
            notes: 'Filter messages from the Document Store for multiple accounts or paths. Document Store must be enabled for the unified search to work.',
            tags: ['Deprecated endpoints (Document Store)'],

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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page'),
                    exposeQuery: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If enabled then returns the ElasticSearch query for debugging as part of the response')
                        .label('exposeQuery')
                        .optional()
                }),

                payload: Joi.object({
                    accounts: Joi.array()
                        .items(Joi.string().empty('').trim().max(256).example('example'))
                        .single()
                        .description('Optional list of account ID values')
                        .label('UnifiedSearchAccounts'),
                    paths: Joi.array()
                        .items(Joi.string().optional().example('INBOX'))
                        .single()
                        .description('Optional list of mailbox folder paths or specialUse flags')
                        .label('UnifiedSearchPaths'),
                    search: searchSchema,
                    documentQuery: Joi.object().min(1).description('Document Store query').label('DocumentQuery').unknown().meta({ swaggerHidden: true })
                }).label('UnifiedSearchQuery')
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
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

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
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
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
                    account: accountIdSchema.required()
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
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'Base64 encoded email message in rfc822 format. If you provide other keys as well then these will override the values in the raw message.'
                        )
                        .label('RFC822Raw')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    from: fromAddressSchema,

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
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    cc: Joi.array()
                        .items(addressSchema.label('CcAddress'))
                        .single()
                        .description('List of CC addresses')
                        .label('CcAddressList')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    bcc: Joi.array()
                        .items(addressSchema.label('BccAddress'))
                        .single()
                        .description('List of BCC addresses')
                        .label('BccAddressList')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    subject: templateSchemas.subject,
                    text: templateSchemas.text,
                    html: templateSchemas.html,
                    previewText: templateSchemas.previewText,

                    template: Joi.string().max(256).example('example').description('Stored template ID to load the email content from'),

                    render: Joi.object({
                        format: Joi.string().valid('html', 'markdown').default('html').description('Markup language for HTML ("html" or "markdown")'),
                        params: Joi.object().label('RenderValues').description('An object of variables for the template renderer')
                    })
                        .allow(false)
                        .description('Template rendering options')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
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
                                    .description('Base64 formatted attachment file')
                                    .when('reference', {
                                        is: Joi.exist().not(false, null),
                                        then: Joi.forbidden(),
                                        otherwise: Joi.required()
                                    }),

                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64'),

                                reference: Joi.string()
                                    .base64({ paddingRequired: false, urlSafe: true })
                                    .max(256)
                                    .allow(false, null)
                                    .example('AAAAAQAACnAcde')
                                    .description(
                                        'Reference an existing attachment ID instead of providing attachment content. If set, then `content` option is not allowed. Otherwise `content` is required.'
                                    )
                            }).label('UploadAttachment')
                        )
                        .description('List of attachments')
                        .label('UploadAttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().label('CustomHeaders').description('Custom Headers').unknown(),

                    trackingEnabled: Joi.boolean().example(false).description('Should EmailEngine track clicks and opens for this message'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
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
                        .integer()
                        .example(10)
                        .description('How many delivery attempts to make until message is considered as failed'),
                    gateway: Joi.string().max(256).example('example').description('Optional SMTP gateway ID for message routing'),

                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description(
                            'List ID for Mail Merge. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.'
                        )
                        .label('ListID')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.optional(),
                            otherwise: Joi.forbidden()
                        }),

                    dsn: Joi.object({
                        id: Joi.string().trim().empty('').max(256).description('The envelope identifier that would be included in the response (ENVID)'),
                        return: Joi.string()
                            .trim()
                            .empty('')
                            .valid('headers', 'full')
                            .required()
                            .description('Specifies if only headers or the entire body of the message should be included in the response (RET)'),
                        notify: Joi.array()
                            .single()
                            .items(Joi.string().valid('never', 'success', 'failure', 'delay').label('NotifyEntry'))
                            .description('Defines the conditions under which a DSN response should be sent'),
                        recipient: Joi.string().trim().empty('').email().description('The email address the DSN should be sent (ORCPT)')
                    })
                        .description('Request DNS notifications')
                        .label('DSN'),

                    baseUrl: Joi.string()
                        .trim()
                        .empty('')
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://customer123.myservice.com')
                        .description('Optional base URL for trackers. This URL must point to your EmailEngine instance.'),

                    proxy: settingsSchema.proxyUrl.description('Optional proxy URL to use when connecting to the SMTP server'),
                    localAddress: ipSchema.description('Optional local IP address to bind to when connecting to the SMTP server'),

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
                            .label('ResponseDocumentStore')
                            .meta({ swaggerHidden: true }),
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

                    mailMerge: Joi.array()
                        .items(
                            Joi.object({
                                success: Joi.boolean()
                                    .example(true)
                                    .description('Was the referenced message processed successfully')
                                    .label('ResponseReferenceSuccess'),
                                to: addressSchema.label('ToAddressSingle'),
                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                queueId: Joi.string()
                                    .example('d41f0423195f271f')
                                    .description('Queue identifier for scheduled email. Not present for bulk messages.'),
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
                                        .label('ResponseDocumentStore')
                                        .meta({ swaggerHidden: true }),
                                    success: Joi.boolean()
                                        .example(true)
                                        .description('Was the referenced message processed successfully')
                                        .label('ResponseReferenceSuccess'),
                                    error: Joi.string()
                                        .example('Referenced message was not found')
                                        .description('An error message if referenced message processing failed')
                                })
                                    .description('Reference info if referencing was requested')
                                    .label('ResponseReference'),
                                sendAt: Joi.date()
                                    .iso()
                                    .example('2021-07-08T07:06:34.336Z')
                                    .description('Send message at specified time. Overrides message level `sendAt` value.'),
                                skipped: Joi.object({
                                    reason: Joi.string().example('unsubscribe').description('Why this message was skipped'),
                                    listId: Joi.string().example('test-list')
                                }).description('Info about skipped message. If this value is set, then the message was not sent')
                            })
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

                    case 'webhooksEnabled':
                        if (!request.payload.webhooksEnabled) {
                            // clear error message (if exists)
                            await settings.clear('webhookErrorFlag');
                        }
                        break;
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
                schema: Joi.object({
                    updated: Joi.array().items(Joi.string().example('notifyHeaders')).description('List of updated setting keys').label('UpdatedSettings')
                }).label('SettingsUpdatedResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/settings/queue/{queue}',

        async handler(request) {
            try {
                let queue = request.params.queue;
                let values = {
                    queue
                };

                const [resActive, resDelayed, resPaused, resWaiting, resMeta] = await redis
                    .multi()
                    .llen(`${REDIS_PREFIX}bull:${queue}:active`)
                    .zcard(`${REDIS_PREFIX}bull:${queue}:delayed`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:paused`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:wait`)
                    .hget(`${REDIS_PREFIX}bull:${queue}:meta`, 'paused')
                    .exec();

                if (resActive[0] || resDelayed[0] || resPaused[0] || resWaiting[0]) {
                    // counting failed
                    let err = new Error('Failed to count queue lengtho');
                    err.statusCode = 500;
                    throw err;
                }

                values.jobs = {
                    active: Number(resActive[1]) || 0,
                    delayed: Number(resDelayed[1]) || 0,
                    paused: Number(resPaused[1]) || 0,
                    waiting: Number(resWaiting[1]) || 0
                };

                values.paused = !!Number(resMeta[1]) || false;

                return values;
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
            description: 'Show queue information',
            notes: 'Show queue status and current state',
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

                params: Joi.object({
                    queue: Joi.string().empty('').trim().valid('notify', 'submit', 'documents').required().example('notify').description('Queue ID')
                })
            },

            response: {
                schema: Joi.object({
                    queue: Joi.string().empty('').trim().valid('notify', 'submit', 'documents').required().example('notify').description('Queue ID'),
                    jobs: Joi.object({
                        active: Joi.number().integer().example(123).description('Jobs that are currently being processed'),
                        delayed: Joi.number().integer().example(123).description('Jobs that are processed in the future'),
                        paused: Joi.number().integer().example(123).description('Jobs that would be processed once queue processing is resumed'),
                        waiting: Joi.number()
                            .integer()
                            .example(123)
                            .description('Jobs that should be processed, but are waiting until there are any free handlers')
                    }).label('QueueJobs'),
                    paused: Joi.boolean().example(false).description('Is the queue paused or not')
                }).label('SettingsQueueResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/settings/queue/{queue}',

        async handler(request) {
            try {
                let queue = request.params.queue;

                let queueObj = {
                    documents: documentsQueue,
                    notify: notifyQueue,
                    submit: submitQueue
                }[queue];

                let values = {
                    queue
                };

                for (let key of Object.keys(request.payload)) {
                    switch (key) {
                        case 'paused':
                            if (request.payload[key]) {
                                await queueObj.pause();
                            } else {
                                await queueObj.resume();
                            }
                            break;
                    }
                }

                values.paused = await queueObj.isPaused();

                return values;
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
            description: 'Set queue settings',
            notes: 'Set queue settings',
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

                params: Joi.object({
                    queue: Joi.string().empty('').trim().valid('notify', 'submit', 'documents').required().example('notify').description('Queue ID')
                }),

                payload: Joi.object({
                    paused: Joi.boolean().empty('').example(false).description('Set queue state to paused')
                }).label('SettingsPutQueuePayload')
            },

            response: {
                schema: Joi.object({
                    queue: Joi.string().empty('').trim().valid('notify', 'submit', 'documents').required().example('notify').description('Queue ID'),
                    paused: Joi.boolean().example(false).description('Is the queue paused or not')
                }).label('SettingsPutQueueResponse'),
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
                    account: accountIdSchema.required()
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
                        .integer()
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
                    accounts: Joi.number().integer().example(26).description('Number of registered accounts'),
                    node: Joi.string().example('16.10.0').description('Node.js Version'),
                    redis: Joi.string().example('6.2.4').description('Redis Version'),
                    connections: Joi.object({
                        init: Joi.number().integer().example(2).description('Accounts not yet initialized'),
                        connected: Joi.number().integer().example(8).description('Successfully connected accounts'),
                        connecting: Joi.number().integer().example(7).description('Connection is being established'),
                        authenticationError: Joi.number().integer().example(3).description('Authentication failed'),
                        connectError: Joi.number().integer().example(5).description('Connection failed due to technical error'),
                        unset: Joi.number().integer().example(0).description('Accounts without valid IMAP settings'),
                        disconnected: Joi.number().integer().example(1).description('IMAP connection was closed')
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
                return await verifyAccountInfo(redis, request.payload, request.logger.child({ action: 'verify-account' }));
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
                    imap: Joi.object(imapSchema).allow(false).description('IMAP configuration').label('ImapConfiguration'),
                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SmtpConfiguration'),
                    proxy: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName
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
                const licenseInfo = await call({ cmd: 'license', timeout: request.headers['x-ee-timeout'] });
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
                const licenseInfo = await call({ cmd: 'removeLicense', timeout: request.headers['x-ee-timeout'] });
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
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license, timeout: request.headers['x-ee-timeout'] });
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
                            .integer()
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
                            .integer()
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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('OutbixListFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    messages: Joi.array().items(outboxEntrySchema).label('OutboxListEntries')
                }).label('OutboxListResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/outbox/{queueId}',

        async handler(request) {
            try {
                let outboxEntry = await outbox.get({ queueId: request.params.queueId, logger });
                if (!outboxEntry) {
                    let message = 'Requested queue entry was not found';
                    let error = Boom.boomify(new Error(message), { statusCode: 404 });
                    throw error;
                }
                return outboxEntry;
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
            description: 'Get queued message',
            notes: 'Gets a queued message in the Outbox',
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
                }).label('OutboxEntryParams')
            },

            response: {
                schema: outboxEntrySchema,
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
                }).label('OutboxEntryParams')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the message deleted')
                }).label('DeleteOutboxEntryResponse'),
                failAction: 'log'
            }
        }
    });

    // setup template routes
    await templateRoutes({ server, call, CORS_CONFIG });

    // setup "chat with email" routes
    await chatRoutes({ server, call, CORS_CONFIG });

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes',

        async handler(request) {
            try {
                return await Webhooks.list(request.query.page, request.query.pageSize);
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
            description: 'List webhook routes',
            notes: 'List custom webhook routes',
            tags: ['api', 'Webhooks'],

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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('WebhookRoutesListRequest')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    webhooks: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Webhook ID'),
                                name: Joi.string().max(256).example('Send to Slack').description('Name of the route').label('WebhookRouteName').required(),
                                description: Joi.string()
                                    .allow('')
                                    .max(1024)
                                    .example('Something about the route')
                                    .description('Optional description of the webhook route')
                                    .label('WebhookRouteDescription'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was created'),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was last updated'),
                                enabled: Joi.boolean().example(true).description('Is the route enabled').label('WebhookRouteEnabled'),
                                targetUrl: settingsSchema.webhooks,
                                tcount: Joi.number().integer().example(123).description('How many times this route has been applied')
                            }).label('WebhookRoutesListEntry')
                        )
                        .label('WebhookRoutesList')
                }).label('WebhookRoutesListResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/webhookRoutes/webhookRoute/{webhookRoute}',

        async handler(request) {
            try {
                return await Webhooks.get(request.params.webhookRoute);
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
            description: 'Get webhook route information',
            notes: 'Retrieve webhook route content and information',
            tags: ['api', 'Webhooks'],

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
                    webhookRoute: Joi.string().max(256).required().example('example').description('Webhook ID')
                }).label('GetWebhookRouteRequest')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Webhook ID'),
                    name: Joi.string().max(256).example('Send to Slack').description('Name of the route').label('WebhookRouteName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the route')
                        .description('Optional description of the webhook route')
                        .label('WebhookRouteDescription'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was created'),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this route was last updated'),
                    enabled: Joi.boolean().example(true).description('Is the route enabled').label('WebhookRouteEnabled'),
                    targetUrl: settingsSchema.webhooks,
                    tcount: Joi.number().integer().example(123).description('How many times this route has been applied'),
                    content: Joi.object({
                        fn: Joi.string().example('return true;').description('Filter function'),
                        map: Joi.string().example('payload.ts = Date.now(); return payload;').description('Mapping function')
                    }).label('WebhookRouteContent')
                }).label('WebhookRouteResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/oauth2',

        async handler(request) {
            try {
                let response = await oauth2Apps.list(request.query.page, request.query.pageSize);

                for (let app of response.apps) {
                    for (let secretKey of ['clientSecret', 'serviceKey', 'accessToken']) {
                        if (app[secretKey]) {
                            app[secretKey] = '******';
                        }
                    }

                    if (app.extraScopes && !app.extraScopes.length) {
                        delete app.extraScopes;
                    }

                    if (app.app) {
                        delete app.app;
                    }

                    if (app.meta) {
                        let authFlag = app.meta.authFlag;
                        delete app.meta;
                        if (authFlag && authFlag.message) {
                            app.lastError = { response: authFlag.message };
                        }
                    }
                }

                return response;
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
            description: 'List OAuth2 applications',
            notes: 'Lists registered OAuth2 applications',
            tags: ['api', 'OAuth2 Applications'],

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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('GatewaysFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    apps: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                                name: Joi.string().max(256).example('My OAuth2 App').description('Display name for the app'),
                                description: Joi.string().empty('').trim().max(1024).example('App description').description('OAuth2 application description'),
                                title: Joi.string().empty('').trim().max(256).example('App title').description('Title for the application button'),
                                provider: OAuth2ProviderSchema,
                                enabled: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('Is the application enabled')
                                    .label('AppEnabled'),
                                legacy: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('`true` for older OAuth2 apps set via the settings endpoint'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was added').required(),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was updated'),
                                includeInListing: Joi.boolean()
                                    .truthy('Y', 'true', '1', 'on')
                                    .falsy('N', 'false', 0, '')
                                    .example(true)
                                    .description('Is the application listed in the hosted authentication form'),

                                clientId: Joi.string()
                                    .example('4f05f488-d858-4f2c-bd12-1039062612fe')
                                    .description('Client or Application ID for 3-legged OAuth2 applications'),
                                clientSecret: Joi.string()
                                    .example('******')
                                    .description('Client secret for 3-legged OAuth2 applications. Actual value is not revealed.'),
                                authority: Joi.string().example('common').description('Authorization tenant value for Outlook OAuth2 applications'),
                                redirectUrl: Joi.string()
                                    .uri({
                                        scheme: ['http', 'https'],
                                        allowRelative: false
                                    })
                                    .example('https://myservice.com/oauth')
                                    .description('Redirect URL for 3-legged OAuth2 applications'),

                                serviceClient: Joi.string().example('9103965568215821627203').description('Service client ID for 2-legged OAuth2 applications'),

                                googleProjectId: googleProjectIdSchema,

                                serviceClientEmail: Joi.string()
                                    .email()
                                    .example('name@project-123.iam.gserviceaccount.com')
                                    .description('Service Client Email for 2-legged OAuth2 applications'),

                                serviceKey: Joi.string()
                                    .example('******')
                                    .description('PEM formatted service secret for 2-legged OAuth2 applications. Actual value is not revealed.'),

                                lastError: lastErrorSchema.allow(null)
                            }).label('OAuth2ResponseItem')
                        )
                        .label('OAuth2Entries')
                }).label('OAuth2FilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                let app = await oauth2Apps.get(request.params.app);

                // remove secrets
                for (let secretKey of ['clientSecret', 'serviceKey', 'accessToken']) {
                    if (app[secretKey]) {
                        app[secretKey] = '******';
                    }
                }

                if (app.extraScopes && !app.extraScopes.length) {
                    delete app.extraScopes;
                }

                if (app.app) {
                    delete app.app;
                }

                if (app.meta) {
                    let authFlag = app.meta.authFlag;
                    delete app.meta;
                    if (authFlag && authFlag.message) {
                        app.lastError = { response: authFlag.message };
                    }
                }

                return app;
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
            description: 'Get application info',
            notes: 'Returns stored information about an OAuth2 application. Secrets are not included.',
            tags: ['api', 'OAuth2 Applications'],

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
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                })
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    name: Joi.string().max(256).example('My OAuth2 App').description('Display name for the app'),
                    description: Joi.string().empty('').trim().max(1024).example('App description').description('OAuth2 application description'),
                    title: Joi.string().empty('').trim().max(256).example('App title').description('Title for the application button'),
                    provider: OAuth2ProviderSchema,
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Is the application enabled')
                        .label('AppEnabled'),
                    legacy: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('`true` for older OAuth2 apps set via the settings endpoint'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was added').required(),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was updated'),
                    includeInListing: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .example(true)
                        .description('Is the application listed in the hosted authentication form'),

                    clientId: Joi.string()
                        .example('4f05f488-d858-4f2c-bd12-1039062612fe')
                        .description('Client or Application ID for 3-legged OAuth2 applications'),
                    clientSecret: Joi.string().example('******').description('Client secret for 3-legged OAuth2 applications. Actual value is not revealed.'),
                    authority: Joi.string().example('common').description('Authorization tenant value for Outlook OAuth2 applications'),
                    redirectUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://myservice.com/oauth')
                        .description('Redirect URL for 3-legged OAuth2 applications'),

                    googleProjectId: googleProjectIdSchema,

                    serviceClientEmail: Joi.string()
                        .email()
                        .example('name@project-123.iam.gserviceaccount.com')
                        .description('Service Client Email for 2-legged OAuth2 applications'),

                    serviceClient: Joi.string().example('9103965568215821627203').description('Service client ID for 2-legged OAuth2 applications'),

                    serviceKey: Joi.string()
                        .example('******')
                        .description('PEM formatted service secret for 2-legged OAuth2 applications. Actual value is not revealed.'),

                    accounts: Joi.number()
                        .integer()
                        .example(12)
                        .description('The number of accounts registered with this application. Not available for legacy apps.'),

                    lastError: lastErrorSchema.allow(null)
                }).label('ApplicationResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/oauth2',

        async handler(request) {
            try {
                let result = await oauth2Apps.create(request.payload);

                if (result && result.pubsubUpdates && result.pubsubUpdates.pubSubSubscription) {
                    await call({ cmd: 'googlePubSub', app: result.id });
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
            description: 'Register OAuth2 application',
            notes: 'Registers a new OAuth2 application for a specific provider',
            tags: ['api', 'OAuth2 Applications'],

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

                payload: Joi.object(oauthCreateSchema).tailor('api').label('CreateOAuth2App')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    created: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the app created')
                }).label('CreateAppResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                let result = await oauth2Apps.update(request.params.app, request.payload);

                if (result && result.pubsubUpdates && result.pubsubUpdates.pubSubSubscription) {
                    await call({ cmd: 'googlePubSub', app: result.id });
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
            description: 'Update OAuth2 application',
            notes: 'Updates OAuth2 application information',
            tags: ['api', 'OAuth2 Applications'],

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
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                }),

                payload: Joi.object({
                    name: Joi.string().trim().empty('').max(256).example('My Gmail App').description('Application name'),
                    description: Joi.string().trim().allow('').max(1024).example('My cool app').description('Application description'),
                    title: Joi.string().allow('').trim().max(256).example('App title').description('Title for the application button'),

                    enabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').example(true).description('Enable this app'),

                    clientId: Joi.string()
                        .trim()
                        .allow('', null, false)
                        .max(256)
                        .example('52422112755-3uov8bjwlrullq122rdm6l8ui25ho7qf.apps.googleusercontent.com')
                        .description('Client or Application ID for 3-legged OAuth2 applications'),

                    clientSecret: Joi.string()
                        .trim()
                        .empty('')
                        .max(256)
                        .example('boT7Q~dUljnfFdVuqpC11g8nGMjO8kpRAv-ZB')
                        .description('Client secret for 3-legged OAuth2 applications'),

                    pubSubApp: Joi.string()
                        .empty('')
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .description('Cloud Pub/Sub app for Gmail API webhooks'),

                    extraScopes: Joi.array().items(Joi.string().trim().max(255).example('User.Read')).description('OAuth2 Extra Scopes'),

                    skipScopes: Joi.array().items(Joi.string().trim().max(255).example('SMTP.Send')).description('OAuth2 scopes to skip from the base set'),

                    serviceClient: Joi.string()
                        .trim()
                        .allow('', null, false)
                        .max(256)
                        .example('7103296518315821565203')
                        .description('Service client ID for 2-legged OAuth2 applications'),

                    googleProjectId: googleProjectIdSchema,

                    serviceClientEmail: Joi.string()
                        .email()
                        .example('name@project-123.iam.gserviceaccount.com')
                        .description('Service Client Email for 2-legged OAuth2 applications'),

                    serviceKey: Joi.string()
                        .trim()
                        .empty('')
                        .max(100 * 1024)
                        .example('-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...')
                        .description('PEM formatted service secret for 2-legged OAuth2 applications'),

                    authority: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024)
                        .example('common')
                        .description('Authorization tenant value for Outlook OAuth2 applications')
                        .label('SupportedAccountTypes'),

                    redirectUrl: Joi.string()
                        .allow('', null, false)
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .example('https://myservice.com/oauth')
                        .description('Redirect URL for 3-legged OAuth2 applications')
                }).label('UpdateOAuthApp')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('example').description('OAuth2 app ID')
                }).label('UpdateOAuthAppResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/oauth2/{app}',

        async handler(request) {
            try {
                return await oauth2Apps.del(request.params.app);
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
            description: 'Remove OAuth2 application',
            notes: 'Delete OAuth2 application data',
            tags: ['api', 'OAuth2 Applications'],

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
                    app: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID')
                }).label('DeleteAppRequest')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the gateway deleted'),
                    accounts: Joi.number()
                        .integer()
                        .example(12)
                        .description('The number of accounts registered with this application. Not available for legacy apps.')
                }).label('DeleteAppRequestResponse'),
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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('GatewaysFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    gateways: Joi.array()
                        .items(
                            Joi.object({
                                gateway: Joi.string().max(256).required().example('example').description('Gateway ID'),
                                name: Joi.string().max(256).example('My Email Gateway').description('Display name for the gateway'),
                                deliveries: Joi.number().integer().empty('').example(100).description('Count of email deliveries using this gateway'),
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
                    deliveries: Joi.number().integer().empty('').example(100).description('Count of email deliveries using this gateway'),
                    lastUse: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('Last delivery time'),

                    user: Joi.string().empty('').trim().max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .integer()
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
                        .integer()
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
                    state: Joi.string()
                        .required()
                        .valid('existing', 'new')
                        .example('new')
                        .description('Is the gateway new or updated existing')
                        .label('CreateGatewayState')
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
                        .integer()
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

            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.getActiveAccessTokenData();
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
                    account: accountIdSchema.required()
                })
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    user: Joi.string().max(256).required().example('user@example.com').description('Username'),
                    accessToken: Joi.string().max(256).required().example('aGVsbG8gd29ybGQ=').description('Access Token'),
                    provider: OAuth2ProviderSchema
                }).label('AccountTokenResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/delivery-test/account/{account}',
        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // throws if account does not exist
                let accountData = await accountObject.loadAccountData();

                request.logger.info({ msg: 'Requested SMTP delivery test', account: request.params.account });

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        requestor: '@postalsys/emailengine-app'
                    }),
                    headers,
                    dispatcher: fetchAgent
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.details = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testAccount = await res.json();
                if (!testAccount || !testAccount.user) {
                    let err = new Error(`Invalid test account`);
                    err.statusCode = 500;

                    try {
                        err.details = testAccount;
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                if (request.payload.gateway) {
                    // try to load the gateway, throws if not set
                    let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, call, secret: await getSecret() });
                    await gatewayObject.loadGatewayData();
                }

                try {
                    let now = new Date().toISOString();
                    let queueResponse = await accountObject.queueMessage(
                        {
                            account: accountData.account,
                            subject: `Delivery test ${now}`,
                            text: `Hello

This is an automated email to test deliverability settings. If you see this email, you can safely delete it.

${now}`,
                            html: `<p>Hello</p>
<p>This is an automated email to test deliverability settings. If you see this email, you can safely delete it.</p>
<p>${now}</p>`,
                            from: {
                                name: accountData.name,
                                address: accountData.email
                            },
                            to: [{ name: 'Delivery Test Server', address: testAccount.address }],
                            copy: false,
                            gateway: request.payload.gateway,
                            feedbackKey: `${REDIS_PREFIX}test-send:${testAccount.user}`,
                            deliveryAttempts: 1
                        },
                        { source: 'test' }
                    );

                    return {
                        success: !!queueResponse.queueId,
                        deliveryTest: testAccount.user
                    };
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.details) {
                    error.output.payload.details = err.details;
                }
                throw error;
            }
        },
        options: {
            description: 'Create delivery test',
            notes: 'Initiate a delivery test',
            tags: ['api', 'Delivery Test'],

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
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    gateway: Joi.string().allow(false, null).empty('').max(256).example(false).description('Optional gateway ID')
                }).label('DeliveryStartRequest')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Was the test started').label('ResponseDeliveryStartSuccess'),
                    deliveryTest: Joi.string()
                        .guid({
                            version: ['uuidv4', 'uuidv5']
                        })
                        .example('6420a6ad-7f82-4e4f-8112-82a9dad1f34d')
                        .description('Test ID')
                }).label('DeliveryStartResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/delivery-test/check/{deliveryTest}',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Requested SMTP delivery test check', deliveryTest: request.params.deliveryTest });

                let deliveryStatus = (await redis.hgetall(`${REDIS_PREFIX}test-send:${request.params.deliveryTest}`)) || {};
                if (deliveryStatus.success === 'false') {
                    let err = new Error(`Failed to deliver email`);
                    err.statusCode = 500;
                    err.details = deliveryStatus;
                    throw err;
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address/${request.params.deliveryTest}`, {
                    method: 'get',
                    headers,
                    dispatcher: fetchAgent
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.details = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testResponse = await res.json();

                let success = testResponse && testResponse.status === 'success'; //Default

                if (testResponse && success) {
                    let mainSig =
                        testResponse.dkim &&
                        testResponse.dkim.results &&
                        testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass' && entry.status.aligned);

                    if (!mainSig) {
                        mainSig =
                            testResponse.dkim &&
                            testResponse.dkim.results &&
                            testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass');
                    }

                    if (!mainSig) {
                        mainSig = testResponse.dkim && testResponse.dkim.results && testResponse.dkim.results[0];
                    }

                    testResponse.mainSig = mainSig || {
                        status: {
                            result: 'none'
                        }
                    };

                    if (testResponse.spf && testResponse.spf.status && testResponse.spf.status.comment) {
                        testResponse.spf.status.comment = testResponse.spf.status.comment.replace(/^[^:\s]+:s*/, '');
                    }
                }

                if (testResponse) {
                    if (testResponse.status === 'success') {
                        delete testResponse.status;
                    }
                    delete testResponse.user;
                }

                return Object.assign({ success }, testResponse || {});
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.details) {
                    error.output.payload.details = err.details;
                }
                throw error;
            }
        },
        options: {
            description: 'Check test status',
            notes: 'Check delivery test status',
            tags: ['api', 'Delivery Test'],

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
                    deliveryTest: Joi.string()
                        .guid({
                            version: ['uuidv4', 'uuidv5']
                        })
                        .example('6420a6ad-7f82-4e4f-8112-82a9dad1f34d')
                        .required()
                        .description('Test ID')
                }).label('DeliveryCheckParams')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Was the test completed').label('ResponseDeliveryCheckSuccess'),
                    dkim: Joi.object().unknown().description('DKIM results'),
                    spf: Joi.object().unknown().description('SPF results'),
                    dmarc: Joi.object().unknown().description('DMARC results'),
                    bimi: Joi.object().unknown().description('BIMI results'),
                    arc: Joi.object().unknown().description('ARC results'),
                    mainSig: Joi.object()
                        .unknown()
                        .description('Primary DKIM signature. `status.aligned` should be set, otherwise DKIM check should not be considered as passed.')
                }).label('DeliveryCheckResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/blocklists',

        async handler(request) {
            try {
                return await lists.list(request.query.page, request.query.pageSize);
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
            description: 'List blocklists',
            notes: 'List blocklists with blocked addresses',
            tags: ['api', 'Blocklists'],

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
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('PageListsRequest')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    blocklists: Joi.array()
                        .items(
                            Joi.object({
                                listId: Joi.string().max(256).required().example('example').description('List ID'),
                                count: Joi.number().integer().example(12).description('Count of blocked addresses in this list')
                            }).label('BlocklistsResponseItem')
                        )
                        .label('BlocklistsEntries')
                }).label('BlocklistsResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/blocklist/{listId}',

        async handler(request) {
            try {
                return await lists.listContent(request.params.listId, request.query.page, request.query.pageSize);
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
            description: 'List blocklist entries',
            notes: 'List blocked addresses for a list',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('PageListsRequest')
            },

            response: {
                schema: Joi.object({
                    listId: Joi.string().max(256).required().example('example').description('List ID'),
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),
                    addresses: Joi.array()
                        .items(
                            Joi.object({
                                recipient: Joi.string().email().example('user@example.com').description('Listed email address').required(),
                                account: accountIdSchema.required().required(),
                                messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
                                source: Joi.string().example('api').description('Which mechanism was used to add the entry'),
                                reason: Joi.string().example('api').description('Why this entry was added'),
                                remoteAddress: Joi.string()
                                    .ip({
                                        version: ['ipv4', 'ipv6'],
                                        cidr: 'optional'
                                    })
                                    .description('Which IP address triggered the entry'),
                                userAgent: Joi.string().example('Mozilla/5.0 (Macintosh)').description('Which user agent triggered the entry'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this entry was added or updated').required()
                            }).label('BlocklistListResponseItem')
                        )
                        .label('BlocklistListEntries')
                }).label('BlocklistListResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/blocklist/{listId}',
        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.payload.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();

                let added = await redis.eeListAdd(
                    `${REDIS_PREFIX}lists:unsub:lists`,
                    `${REDIS_PREFIX}lists:unsub:entries:${request.params.listId}`,
                    request.params.listId,
                    request.payload.recipient.toLowerCase().trim(),
                    JSON.stringify({
                        recipient: request.payload.recipient,
                        account: request.payload.account,
                        source: 'api',
                        reason: request.payload.reason,
                        remoteAddress: request.app.ip,
                        userAgent: request.headers['user-agent'],
                        created: new Date().toISOString()
                    })
                );

                return {
                    success: true,
                    added: !!added
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
                if (err.details) {
                    error.output.payload.details = err.details;
                }
                throw error;
            }
        },
        options: {
            description: 'Add to blocklist',
            notes: 'Add an email address to a blocklist',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

                payload: Joi.object({
                    account: accountIdSchema.required(),
                    recipient: Joi.string().empty('').email().example('user@example.com').description('Email address to add to the list').required(),
                    reason: Joi.string().empty('').default('block').description('Identifier for the blocking reason')
                }).label('BlocklistListAddPayload')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Was the request successful').label('BlocklistListAddSuccess'),
                    added: Joi.boolean().example(true).description('Was the address added to the list')
                }).label('BlocklistListAddResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/blocklist/{listId}',

        async handler(request) {
            try {
                let exists = await redis.hexists(`${REDIS_PREFIX}lists:unsub:lists`, request.params.listId);
                if (!exists) {
                    let message = 'Requested blocklist was not found';
                    let error = Boom.boomify(new Error(message), { statusCode: 404 });
                    throw error;
                }

                let deleted = await redis.eeListRemove(
                    `${REDIS_PREFIX}lists:unsub:lists`,
                    `${REDIS_PREFIX}lists:unsub:entries:${request.params.listId}`,
                    request.params.listId,
                    request.query.recipient.toLowerCase().trim()
                );

                return {
                    deleted: !!deleted
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
            description: 'Remove from blocklist',
            notes: 'Delete a blocked email address from a list',
            tags: ['api', 'Blocklists'],

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
                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description('List ID. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.')
                        .label('ListID')
                        .required()
                }).label('BlocklistListRequest'),

                query: Joi.object({
                    recipient: Joi.string().empty('').email().example('user@example.com').description('Email address to remove from the list').required()
                }).label('RecipientQuery')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the address removed from the list')
                }).label('DeleteBlocklistResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/changes',

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
        },

        options: {
            description: 'Stream state changes',
            notes: 'Stream account state changes as an EventSource',
            tags: ['api', 'Account'],

            plugins: {},

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG
        }
    });

    // Web UI routes

    await server.register({
        plugin: Crumb,

        options: {
            cookieOptions: {
                isSecure: secureCookie
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
        compileOptions: {
            preventIndent: true
        },

        relativeTo: pathlib.join(__dirname, '..'),
        path: './views',
        layout: 'app',
        layoutPath: './views/layout',
        partialsPath: './views/partials',

        isCached: false,

        async context(request) {
            const pendingMessages = await flash(redis, request);
            const {
                upgrade: upgradeInfo,
                subexp,
                outlookAuthFlag,
                gmailAuthFlag,
                gmailServiceAuthFlag,
                webhookErrorFlag,
                webhooksEnabled,
                disableTokens,
                tract,
                templateHeader: embeddedTemplateHeader,
                documentStoreEnabled: showDocumentStore,
                serviceUrl,
                language,
                locale,
                timezone
            } = await settings.getMulti(
                'upgrade',
                'subexp',
                'outlookAuthFlag',
                'gmailAuthFlag',
                'gmailServiceAuthFlag',
                'webhookErrorFlag',
                'webhooksEnabled',
                'disableTokens',
                'tract',
                'templateHeader',
                'documentStoreEnabled',
                'serviceUrl',
                'language',
                'locale',
                'timezone'
            );

            const systemAlerts = [];
            let authData;

            switch (request.auth.artifacts && request.auth.artifacts.provider) {
                case 'okta': {
                    let profile = request.auth.artifacts.profile || {};
                    authData = {
                        user: profile.username,
                        name:
                            []
                                .concat(profile.firstName || [])
                                .concat(profile.lastName || [])
                                .join(' ') || profile.username,
                        enabled: !!profile.username,
                        isAdmin: false
                    };
                    break;
                }

                default:
                    authData = await settings.get('authData');
                    if (authData) {
                        authData.name = authData.user;
                        authData.enabled = true;
                        authData.isAdmin = true;
                    } else {
                        authData = {
                            name: 'admin',
                            user: 'admin',
                            enabled: false,
                            isAdmin: true
                        };
                    }
                    break;
            }

            if (upgradeInfo && upgradeInfo.canUpgrade) {
                systemAlerts.push({
                    url: '/admin/upgrade',
                    level: 'info',
                    icon: 'exclamation-triangle',
                    message: `An update is available: Emailengine v${upgradeInfo.available}`
                });
            }

            if (subexp && !(request.app.licenseInfo && request.app.licenseInfo.details && request.app.licenseInfo.details.lt)) {
                let delayMs = new Date(subexp) - Date.now();
                let expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);

                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'danger',
                    icon: 'exclamation-triangle',
                    message: `The license key needs to be renewed or replaced in ${expiresDays} day${expiresDays !== 1 ? 's' : ''}`
                });
            }

            if (outlookAuthFlag && outlookAuthFlag.message) {
                systemAlerts.push({
                    url: outlookAuthFlag.url || '/admin/config/oauth/app/outlook',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: outlookAuthFlag.message
                });
            }

            if (gmailAuthFlag && gmailAuthFlag.message) {
                systemAlerts.push({
                    url: gmailAuthFlag.url || '/admin/config/oauth/app/gmail',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: gmailAuthFlag.message
                });
            }

            if (gmailServiceAuthFlag && gmailServiceAuthFlag.message) {
                systemAlerts.push({
                    url: gmailServiceAuthFlag.url || '/admin/config/oauth/app/gmailService',
                    level: 'danger',
                    icon: 'unlock-alt',
                    message: gmailServiceAuthFlag.message
                });
            }

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

            if (disableTokens) {
                systemAlerts.push({
                    url: '/admin/config/service#security',
                    level: 'warning',
                    icon: 'key',
                    message: `Access tokens are disabled for API requests`
                });
            }

            if (consts.EE_DOCKER_LEGACY) {
                systemAlerts.push({
                    url: 'https://emailengine.app/docker',
                    level: 'info',
                    icon: 'docker',
                    brand: true,
                    message: `The Docker image you are currently using is deprecated. To ensure ongoing support, please transition to <code>postalsys/emailengine</code>.`,
                    verbatim: true
                });
            }

            return {
                values: request.payload || {},
                errors: (request.error && request.error.details) || {},
                pendingMessages,
                licenseInfo: request.app.licenseInfo,
                licenseDetails,
                trialPossible: !tract,
                authData,
                packageData,
                systemAlerts,
                embeddedTemplateHeader,
                currentYear: new Date().getFullYear(),
                showDocumentStore,
                updateBrowserInfo: !serviceUrl || !language || !timezone,

                userLocale: locale,
                userTimezone: timezone
            };
        }
    });

    const preResponse = async (request, h) => {
        let response = request.response;

        if (assertPreconditionResult && request.route && request.route.settings && request.route.settings.tags && request.route.settings.tags.includes('api')) {
            response = assertPreconditionResult;
        }

        if (!response.isBoom) {
            if (request.app.rateLimitHeaders) {
                const headers = request.response.output ? request.response.output.headers : request.response.headers;
                for (let key of Object.keys(request.app.rateLimitHeaders)) {
                    headers[key] = request.app.rateLimitHeaders[key].toString();
                }
            }

            return h.continue;
        }

        // Replace error with friendly HTML
        const error = response;
        const ctx = {
            message:
                error.output.statusCode === 404
                    ? 'page not found'
                    : (error.output && error.output.payload && error.output.payload.message) || 'something went wrong',
            details: error.output && error.output.payload && error.output.payload.details
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

            let res = h.response(request.errorInfo);
            if (error.output.headers) {
                for (let key of Object.keys(error.output.headers)) {
                    res = res.header(key, error.output.headers[key].toString());
                }
            }

            return res.code(request.errorInfo.statusCode || 500);
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

    server.ext('onPostAuth', async (request, h) => {
        if (request.requireTotp) {
            // Redirect authenticated pages to login page if TOTP is required
            let url = new URL(`admin/login`, 'http://localhost');

            let nextUrl = (request.query && request.query.next) || (request.payload && request.payload.next) || false;
            if (nextUrl) {
                url.searchParams.append('next', nextUrl);
            }

            return h.redirect(url.pathname + url.search).takeover();
        }
        return h.continue;
    });

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
            const renderedMetrics = await call({ cmd: 'metrics', timeout: request.headers['x-ee-timeout'] });
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
                await runPrechecks(redis);
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
            maxBodySize: MAX_BODY_SIZE,
            version: packageData.version
        });
        parentPort.postMessage({ cmd: 'ready' });
    })
    .catch(err => {
        logger.error({ msg: 'Failed to initialize API', err });
        logger.flush(() => process.exit(3));
    });
