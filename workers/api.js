'use strict';

const { parentPort, workerData } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');
const Path = require('path');
const Gettext = require('@postalsys/gettext');
const { loadTranslations, gt, joiLocales, locales } = require('../lib/translations');
const { accountStateLabel, formatServerState, identityErrorView } = require('../lib/ui-routes/route-helpers');
const util = require('util');
const { webhooks: Webhooks } = require('../lib/webhooks');
const { lists } = require('../lib/lists');
const Bell = require('@hapi/bell');
const marked = require('marked');

const fs = require('fs');
const eulaText = marked.parse(
    fs.readFileSync(Path.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), 'utf-8').replace(/\blicenses\.html\b/g, '[licenses.html](/licenses.html)')
);

const {
    getByteSize,
    getDuration,
    flash,
    failAction,
    isEmail,
    getWorkerCount,
    runPrechecks,
    matcher,
    readEnvValue,
    readEnvList,
    threadStats,
    hasEnvValue,
    getBoolean,
    loadTlsConfig,
    maybeReloadHttpProxyAgent,
    resolveOAuthErrorStatus,
    constantTimeEqual,
    verifyServiceSignature,
    claimFormNonce,
    releaseFormNonce,
    setAdminSession
} = require('../lib/tools');
const { matchIp, resolveClientIp, detectAutomatedRequest } = require('../lib/utils/network');

const { initSentry } = require('../lib/sentry');
initSentry('api');

const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const Cookie = require('@hapi/cookie');
const Crumb = require('@hapi/crumb');
const Joi = require('joi');
const hapiPino = require('hapi-pino');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const Accept = require('@hapi/accept');

const pathlib = require('path');

const crypto = require('crypto');
const { registeredPublishers, openChangeStream } = require('../lib/response-stream');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { decodeJwtPayload } = require('../lib/oauth/decode-jwt-payload');
const { resolveOutlookUserInfo } = require('../lib/oauth/outlook-identity');
const { buildRetrySetup } = require('../lib/oauth/retry-setup');
const { matchesExpectedIdentity, pendingSetupExpectation, resolveExpectedIdentity } = require('../lib/account/expected-identity');

const handlebars = require('handlebars');
const AuthBearer = require('hapi-auth-bearer-token');
const tokens = require('../lib/tokens');

const { redis, documentsQueue } = require('../lib/db');
const { Account } = require('../lib/account');
const settings = require('../lib/settings');

const getSecret = require('../lib/get-secret');
const { getESClient, documentStoreFeatureEnabled } = require('../lib/document-store');

const sso = require('../lib/sso');

const routesUi = require('../lib/routes-ui');
const specOptions = require('../lib/swagger-options');
const { registerOpenApiRoute } = require('../lib/openapi');
const { getModel: getApiReferenceModel, clearServiceUrlCache } = require('../lib/api-reference');

const { encrypt, decrypt } = require('../lib/encrypt');
const { Certs } = require('@postalsys/certs');
const net = require('net');

const consts = require('../lib/consts');
const {
    TRACK_OPEN_NOTIFY,
    TRACK_CLICK_NOTIFY,
    REDIS_PREFIX,
    RENEW_TLS_AFTER,
    BLOCK_TLS_RENEW,
    TLS_RENEW_CHECK_INTERVAL,
    DEFAULT_CORS_MAX_AGE,
    LIST_UNSUBSCRIBE_NOTIFY,
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_MAX_PAYLOAD_TIMEOUT,
    DEFAULT_EENGINE_TIMEOUT,
    DEFAULT_MAX_ATTACHMENT_SIZE,
    MAX_FORM_TTL,
    NONCE_BYTES
} = consts;

const registerApiRoutes = require('../lib/api-routes');
const bullBoardRoutes = require('../lib/api-routes/bull-board-routes');

const {
    imapSchema,
    smtpSchema,
    oauth2Schema,
    accountIdSchema,
    apiHeadersSchema,
    oauth2ProviderSchema: OAuth2ProviderSchema,
    accountTypeSchema: AccountTypeSchema
} = require('../lib/schemas');

const SUPPORTED_LOCALES = locales.map(locale => locale.locale);

const FLAG_SORT_ORDER = ['\\Inbox', '\\Flagged', '\\Sent', '\\Drafts', '\\All', '\\Archive', '\\Junk', '\\Trash'];

const { GMAIL_SCOPES, OPENID_SCOPES } = require('../lib/oauth/gmail');
const { MAIL_RU_SCOPES } = require('../lib/oauth/mail-ru');

const GMAIL_SCOPE_DESCRIPTIONS = {
    'https://mail.google.com/': 'Full email access (IMAP and SMTP)',
    'https://www.googleapis.com/auth/gmail.modify': 'Read, compose, send, and modify emails',
    'https://www.googleapis.com/auth/gmail.readonly': 'Read email messages and settings',
    'https://www.googleapis.com/auth/gmail.send': 'Send email on your behalf',
    'https://www.googleapis.com/auth/gmail.labels': 'Manage email labels',
    'https://www.googleapis.com/auth/pubsub': 'Cloud Pub/Sub notifications'
};

function formatScopeDescription(scope) {
    if (GMAIL_SCOPE_DESCRIPTIONS[scope]) {
        return GMAIL_SCOPE_DESCRIPTIONS[scope];
    }
    let shortName = scope;
    try {
        const url = new URL(scope);
        shortName = url.pathname.split('/').pop() || scope;
    } catch (e) {
        // Not a URL, use as-is
    }
    return shortName.replace(/\./g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

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

// Generic OIDC SSO (Keycloak, Authentik, Azure AD/Entra, Google, ...). Config lives
// in lib/sso.js; the email and group allow-lists are parsed once here and consulted
// both in the session validate() and in the /admin/login/oidc callback.
const USE_OIDC_AUTH = sso.USE_OIDC_AUTH;
const oidcAllowList = sso.parseAllowList(sso.OIDC_ALLOWED_USERS);
const oidcAllowGroups = sso.parseGroupList(sso.OIDC_ALLOWED_GROUPS);

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const MAX_ATTACHMENT_SIZE = getByteSize(readEnvValue('EENGINE_MAX_SIZE') || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

const API_PORT =
    (hasEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (hasEnvValue('PORT') && Number(readEnvValue('PORT'))) || config.api.port;
const API_HOST = readEnvValue('EENGINE_HOST') || config.api.host;

// Either an object (TLS enabled) or `false` (TLS disabled)
const API_TLS = hasEnvValue('EENGINE_API_TLS') ? getBoolean(readEnvValue('EENGINE_API_TLS')) && (config.api.tls || {}) : config.api.tls || false;

// Merge TLS settings from config params and environment
loadTlsConfig(API_TLS, 'EENGINE_API_TLS_');

// Per-worker thread metadata. With multiple API workers (EENGINE_WORKERS_API > 1) the
// main thread assigns each one an index and whether to bind with SO_REUSEPORT. Only
// worker 0 runs singleton maintenance tasks (e.g. TLS certificate renewal).
const WORKER_INDEX = (workerData && workerData.workerIndex) || 0;
const USE_REUSE_PORT = !!(workerData && workerData.reusePort);
// Worker 0 is the primary; it runs singleton maintenance tasks (e.g. TLS certificate renewal)
// that must execute exactly once across all API workers.
const IS_PRIMARY_API_WORKER = WORKER_INDEX === 0;

const ADMIN_ACCESS_ADDRESSES = readEnvList('EENGINE_ADMIN_ACCESS_ADDRESSES');

// Peers allowed to set X-Forwarded-For. Unset means the header is honored from any peer whenever
// the API proxy setting is on, which is the historical behavior; see resolveClientIp().
const API_PROXY_ADDRESSES = readEnvList('EENGINE_API_PROXY_ADDRESSES');

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
    // Nothing to do (and no reason to compute the badge label) when no SSE client is
    // subscribed - the common case whenever no admin browser has the dashboard open.
    if (!registeredPublishers.size) {
        return;
    }

    let { account, type, key, payload } = data;

    // resolve the badge descriptor server-side so the SSE repaint in app.js uses
    // the exact same mapping (and translations) as the server-rendered views
    let stateLabel = null;
    switch (type) {
        case 'state':
            stateLabel = accountStateLabel(key, { lastErrorState: payload && payload.error }, gt);
            break;
        case 'smtpServerState':
        case 'imapProxyServerState':
            stateLabel = formatServerState(key, payload);
            break;
    }

    for (let stream of registeredPublishers) {
        try {
            stream.sendMessage({ account, type, key, payload, stateLabel });
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

    if (message && message.cmd === 'settings') {
        // Keep this worker's in-memory HTTP proxy agent in sync when proxy settings change
        maybeReloadHttpProxyAgent(message.data);
        // ...and the API reference's memoized serviceUrl, which its code samples embed
        clearServiceUrlCache();
    }
});

const init = async () => {
    await loadTranslations();

    gt.setLocale((await settings.get('locale')) || 'en');

    handlebars.registerHelper('_', (...args) => {
        let params = args.slice(1, args.length - 1);

        let locale = params.shift();

        let localGt = locale ? gt.useLocale(locale) : gt;

        let translated = localGt.gettext(args[0]);
        if (params.length) {
            translated = util.format(translated, ...params);
        }

        return new handlebars.SafeString(translated);
    });

    // HTML-escape a value for safe interpolation into an otherwise-unescaped context - e.g. a
    // dynamic `%s` argument to the SafeString-returning `_` helper. Returns a plain string so
    // the surrounding markup stays live while the value itself is entity-escaped.
    handlebars.registerHelper('escapeHtml', value => handlebars.escapeExpression(value));

    // Translate Bootstrap-era color names emitted by server code (flash types,
    // systemAlerts levels) into the FlyonUI color vocabulary used by the admin
    // theme, so templates interpolate a single closed set of class suffixes
    // (which the stylesheet safelists). Single translation point - producers
    // keep using "danger" etc.
    handlebars.registerHelper('eeColor', value => (value === 'danger' ? 'error' : value || 'neutral'));

    // Join string fragments in subexpressions, e.g. building composed partial
    // hash values: text=(concat "Up to " (formatInteger n locale) " lines")
    handlebars.registerHelper('concat', (...args) => args.slice(0, -1).join(''));

    // Ternary for subexpressions: placeholder=(when hasPass "set..." "")
    handlebars.registerHelper('when', (cond, truthyValue, falsyValue) => (cond ? truthyValue : typeof falsyValue === 'string' ? falsyValue : ''));

    handlebars.registerHelper('isodate', time => new Date(Number(time)).toISOString());

    handlebars.registerHelper('ngettext', (msgid, plural, count) => util.format(gt.ngettext(msgid, plural, count), count));

    handlebars.registerHelper('equals', function (compareVal, baseVal, options) {
        if (baseVal === compareVal) {
            return options.fn(this);
        }
        return options.inverse(this);
    });

    handlebars.registerHelper('inc', (nr, inc) => Number(nr) + Number(inc));

    handlebars.registerHelper('json', payload => {
        let res;
        try {
            res = typeof payload === 'undefined' ? 'undefined' : JSON.stringify(payload, false, 2);
        } catch (err) {
            res = util.inspect(payload, false, 4, false);
        }
        // SECURITY: return a plain string (NOT a SafeString) so Handlebars HTML-escapes the
        // output. `payload` can carry attacker-controlled data (e.g. inbound email fields in
        // webhook / pre-processing error logs); wrapping it in a SafeString allowed a stored
        // XSS via a </textarea> breakout in the error-log views (security review H1). In the
        // <textarea> render contexts this is display-identical (the browser decodes entities).
        return res;
    });

    handlebars.registerHelper('lastVal', (value, separator) => {
        separator = separator || '/';

        let res = (value || '').toString().split(separator).pop();

        return new handlebars.SafeString(res);
    });

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

    // Base Hapi options shared by both the default and SO_REUSEPORT binding paths
    const serverOptions = {
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
                    convert: true,
                    errors: {
                        language: 'en' // Default language
                    }
                },
                headers: apiHeadersSchema
            }
        }
    };

    // With multiple API workers we provide our own listener and bind it ourselves with
    // SO_REUSEPORT so the kernel load-balances connections. Hapi forbids port/host when
    // autoListen is false and needs a truthy `tls` flag to treat a provided HTTPS
    // listener correctly. The single-worker path keeps Hapi's default binding unchanged.
    let reusePortListener = null;
    if (USE_REUSE_PORT) {
        const http = require('http');
        const https = require('https');
        reusePortListener = API_TLS ? https.createServer(API_TLS) : http.createServer();
        serverOptions.listener = reusePortListener;
        serverOptions.tls = !!API_TLS;
        serverOptions.autoListen = false;
    } else {
        serverOptions.port = API_PORT;
        serverOptions.host = API_HOST;
        serverOptions.tls = API_TLS;
    }

    const server = Hapi.server(serverOptions);

    let assertPreconditionResult;
    server.decorate('toolkit', 'getESClient', async (...args) => await getESClient(...args));

    let getServiceDomain = async () => {
        let serviceUrl = await settings.get('serviceUrl');
        let parsedUrl;

        try {
            parsedUrl = new URL(serviceUrl);
        } catch (err) {
            parsedUrl = {};
        }

        let hostname = (parsedUrl.hostname || '').toString().toLowerCase().trim();
        if (!hostname || net.isIP(hostname) || ['localhost'].includes(hostname) || /(\.local|\.lan)$/i.test(hostname)) {
            // empty string, not false: the value is interpolated into
            // templates, where a boolean would render as the text "false"
            return '';
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
                        type: 'error',
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

    server.ext('onPreAuth', async (request, h) => {
        const tags = (request.route && request.route.settings && request.route.settings.tags) || [];
        // Skip if it's a static file route
        if (tags.includes('static')) {
            return h.continue;
        }

        const defaultLocale = (await settings.get('locale')) || 'en';
        if (defaultLocale && gt.locale !== defaultLocale) {
            gt.setLocale(defaultLocale);
        }

        let detectedLocale = defaultLocale;
        let updateLocaleCookie;
        // Priority order:
        // 1. Query parameter (?locale=nl)
        if (request.query.locale && SUPPORTED_LOCALES.includes(request.query.locale)) {
            detectedLocale = request.query.locale;
            updateLocaleCookie = detectedLocale;
        }
        // 2. Custom header (X-EE-Locale: nl)
        else if (request.headers['x-ee-locale'] && SUPPORTED_LOCALES.includes(request.headers['x-ee-locale'])) {
            detectedLocale = request.headers['x-ee-locale'];
            updateLocaleCookie = detectedLocale;
        }
        // 3. Use the locale store in cookie
        else if (request.state && request.state.locale && request.state.locale.locale) {
            detectedLocale = request.state && request.state.locale && request.state.locale.locale;
        }
        // 4. Accept-Language header negotiation
        else if (request.headers['accept-language']) {
            try {
                detectedLocale = Accept.language(request.headers['accept-language'], SUPPORTED_LOCALES);
            } catch (err) {
                // Keep default locale on parse error
                request.logger.debug({
                    msg: 'Accept-Language parse error',
                    err,
                    header: request.headers['accept-language']
                });
            }
        }
        // 5. If still no match, keep the default

        // Save selected locale in a cookie for UI requests
        // Only use the value from query argument or custom header, not from Accept-Language header

        if (
            updateLocaleCookie &&
            (!request.state || !request.state.locale || updateLocaleCookie !== request.state.locale.locale) &&
            // skip API paths
            !request.route.path.startsWith('/v1/') &&
            !request.route.path.startsWith('/health')
        ) {
            // set locale cookie
            h.state('locale', { locale: detectedLocale });
        }

        // Set the locale for the request
        const reqLocale = detectedLocale && Gettext.getLanguageCode(detectedLocale);
        if (reqLocale && gt.catalogs.hasOwnProperty(reqLocale)) {
            request.app.gt = gt.useLocale(reqLocale);
            request.app.locale = reqLocale;
        } else {
            request.app.locale = defaultLocale;
            request.app.gt = gt;
        }

        // Make sure validation errors use selected locale
        if (request.route.settings.validate && request.route.settings.validate.options) {
            // Get user's locale
            const locale = request.app.locale || 'en';

            // Create new validation options for this request
            const validationOptions = Object.assign({}, request.route.settings.validate.options, {
                errors: {
                    language: locale
                }
            });

            // Apply to this request only
            request.route.settings.validate.options = validationOptions;
        }

        return h.continue;
    });

    server.ext('onRequest', async (request, h) => {
        // set default, will be overriden once active language is resolved
        request.app.gt = gt;

        // Both settings are needed on every request and neither depends on the other, so they are
        // read in a single HMGET rather than two serialized round trips
        let { enableApiProxy, disableTokens } = await settings.getMulti('enableApiProxy', 'disableTokens');

        // check if client IP is resolved from X-Forwarded-For or not
        request.app.ip = resolveClientIp({
            remoteAddress: request.info.remoteAddress,
            forwardedFor: request.headers['x-forwarded-for'],
            enableApiProxy: enableApiProxy || false,
            trustedProxies: API_PROXY_ADDRESSES
        });

        // check if access tokens for api requests are required
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

        if (ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length) {
            if (request.path.startsWith('/admin') && !matchIp(request.app.ip, ADMIN_ACCESS_ADDRESSES)) {
                logger.info({
                    msg: 'Blocked access from unlisted IP address',
                    remoteAddress: request.app.ip,
                    allowedAddresses: ADMIN_ACCESS_ADDRESSES,
                    component: 'api',
                    req: {
                        method: request.method,
                        url: request.path,
                        query: request.query
                    }
                });

                return h
                    .view(
                        'error',
                        {
                            pageTitle: 'Access Denied',
                            message: `You don't have permission to view this page`
                        },
                        {
                            layout: 'public'
                        }
                    )
                    .code(403)
                    .takeover();
            }
        }

        return h.continue;
    });

    const openApiOptions = {
        // Spec-shaping options (tag list and order, security scheme, external docs) live in
        // lib/swagger-options.js so the document can be reproduced outside a running server
        ...specOptions,

        // The running version is the only part of `info` this worker owns - the rest is static
        // and lives with the other document metadata in lib/swagger-options.js, so the tests
        // see the same values a real instance serves
        info: Object.assign({}, specOptions.info, { version: packageData.version }),

        cors: !!CORS_CONFIG
    };

    await server.register(AuthBearer);

    // Authentication for API calls
    server.auth.strategy('api-token', 'bearer-access-token', {
        allowQueryToken: true, // optional, false by default
        validate: async (request, token /*, h*/) => {
            let disableTokens = await settings.get('disableTokens');
            if (disableTokens && (!token || token === 'preauth')) {
                // tokens checks are disabled, allow all if token is not set.
                // `preauth` marks a caller that presented NO credential at all - routes that hand
                // out lasting privilege have to be able to tell that apart from a real token.
                return {
                    isValid: true,
                    credentials: { preauth: true },
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

            if (token.startsWith('sess_') && scope === 'api') {
                // seems like a session token
                let isValidSessionToken = await tokens.validateSessionToken(
                    request.state && request.state.ee && request.state.ee.sid,
                    token,
                    request.params.account,
                    900
                );
                if (isValidSessionToken) {
                    return {
                        isValid: true,
                        credentials: {},
                        artifacts: {}
                    };
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

            // Bind the token hash (id) to the request logger so it is included in the per-request
            // log entry, allowing API requests to be correlated to the token that made them.
            if (request.logger && typeof request.logger.setBindings === 'function') {
                request.logger.setBindings({ tokenId: tokenData.id, tokenAccount: tokenData.account || null });
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

    server.state('locale', {
        ttl: null,
        encoding: 'base64json',
        clearInvalid: true,
        path: '/'
    });

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
                case 'okta':
                case 'oidc': {
                    if (session.profile && session.profile.id) {
                        let profile = session.profile;

                        // Re-check OIDC authorization (email + group allow-lists) on every request
                        // so changes to OIDC_ALLOWED_USERS/OIDC_ALLOWED_GROUPS (after a restart)
                        // take effect without waiting out the existing session cookie. Okta has no
                        // allow-list.
                        if (session.provider === 'oidc' && !sso.isAuthorized(profile, oidcAllowList, oidcAllowGroups)) {
                            return { isValid: false };
                        }

                        return {
                            isValid: true,
                            credentials: {
                                enabled: true,
                                user: profile.username
                            },
                            // Expose the SSO provider on artifacts so the "SSO users can't manage
                            // local password/TOTP/passkeys" guards in the UI routes fire. idToken is
                            // carried for OIDC RP-initiated logout (undefined for Okta).
                            artifacts: {
                                provider: session.provider,
                                profile,
                                idToken: session.idToken
                            }
                        };
                    }
                    return { isValid: false };
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
            if (
                session.requireTotp &&
                !['/{any*}', '/admin/totp', '/admin/login', '/admin/passkey/auth/options', '/admin/passkey/auth/verify'].includes(
                    request.route && request.route.path
                )
            ) {
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

    // Shared by the SSO strategies. The redirect URL is captured at strategy registration;
    // the validators re-read it from settings so an origin change after startup (which would
    // break the registered callback URL) disables the SSO button instead of failing mid-flow.
    let getServiceRedirectUrl = async () => new URL((await settings.get('serviceUrl')) || `http://${API_HOST}${API_PORT !== 80 ? `:${API_PORT}` : ''}`);
    let serviceOriginUnchanged = async redirectUrl => (await getServiceRedirectUrl()).origin === redirectUrl.origin;
    let assertSsoAuthenticated = request => {
        if (!request.auth.isAuthenticated) {
            let error = Boom.unauthorized('Failed to authorize user');
            error.output.payload.details = [request.auth.error.message];
            throw error;
        }
    };

    if (USE_OKTA_AUTH) {
        let redirectUrl = await getServiceRedirectUrl();

        server.decorate('toolkit', 'validateOktaConfig', () => serviceOriginUnchanged(redirectUrl));

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
                assertSsoAuthenticated(request);
                setAdminSession(request, request.auth.credentials);
                let oktaUser = request.auth.credentials && request.auth.credentials.profile && request.auth.credentials.profile.username;
                request.logger.info({ msg: 'Admin login successful', user: oktaUser || 'unknown', method: 'okta', remoteAddress: request.app.ip });
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

    if (USE_OIDC_AUTH) {
        let redirectUrl = await getServiceRedirectUrl();

        // Fetch the discovery document once at startup. bell needs static auth/token
        // URLs at strategy-registration time, so this must precede registration. A
        // failure here (IdP outage/misconfig) must NOT take EmailEngine down - password
        // and passkey login plus the REST API have to keep working - so we log a
        // prominent error, leave the strategy unregistered, and disable the SSO button.
        let oidcDiscovery = null;
        try {
            oidcDiscovery = await sso.fetchOidcDiscovery();
        } catch (err) {
            logger.error({ msg: 'OIDC SSO disabled: discovery failed', issuer: sso.OIDC_ISSUER, err });
        }

        // Registered unconditionally so the login/security views can call it; returns
        // false when discovery failed or the serviceUrl origin drifted from startup.
        server.decorate('toolkit', 'validateOidcConfig', async () => !!oidcDiscovery && (await serviceOriginUnchanged(redirectUrl)));

        // RP-initiated logout URL for the /admin/logout handler. Returns null unless
        // OIDC_LOGOUT is enabled and the IdP advertised an end_session_endpoint.
        // post_logout_redirect_uri is only sent when OIDC_POST_LOGOUT_REDIRECT_URI is
        // configured (and registered at the IdP); otherwise the IdP shows its own
        // logged-out page, so logout needs no IdP-side configuration.
        server.decorate('toolkit', 'oidcLogoutUrl', idToken => {
            if (!sso.OIDC_LOGOUT || !oidcDiscovery || !oidcDiscovery.end_session_endpoint) {
                return null;
            }
            return sso.buildLogoutUrl(oidcDiscovery.end_session_endpoint, {
                idToken,
                clientId: sso.OIDC_CLIENT_ID,
                postLogoutRedirectUri: sso.OIDC_POST_LOGOUT_REDIRECT_URI || undefined
            });
        });

        if (oidcDiscovery) {
            server.auth.strategy('oidc', 'bell', {
                provider: sso.buildOidcBellProvider(oidcDiscovery),
                password: await settings.get('cookiePassword'),
                isSecure: secureCookie,
                location: redirectUrl.origin,

                clientId: sso.OIDC_CLIENT_ID,
                clientSecret: sso.OIDC_CLIENT_SECRET
            });

            server.route({
                method: ['GET', 'POST'],
                path: '/admin/login/oidc',
                async handler(request, h) {
                    assertSsoAuthenticated(request);

                    let profile = (request.auth.credentials && request.auth.credentials.profile) || {};

                    // Enforce the optional email/group allow-lists before establishing the session.
                    if (!sso.isAuthorized(profile, oidcAllowList, oidcAllowGroups)) {
                        request.logger.warn({
                            msg: 'OIDC login denied by allow-list',
                            user: profile.username || profile.email || 'unknown',
                            groups: profile.groups,
                            method: 'oidc',
                            remoteAddress: request.app.ip
                        });
                        await request.flash({ type: 'danger', message: 'Your account is not authorized to access this admin panel' });
                        // ?sso_denied=1 stops a forced instance from auto-redirecting back into the
                        // OIDC flow before the user can see the error.
                        return h.redirect('/admin/login?sso_denied=1');
                    }

                    // Store only the minimal profile - not the full bell credentials. OIDC
                    // access/refresh tokens (e.g. Keycloak JWTs) can push the iron-sealed
                    // `ee` cookie past the ~4KB browser limit and cause a silent login loop.
                    // Group names are kept so the per-request authorization re-check works;
                    // the id_token is kept only as the logout id_token_hint (RP-initiated logout).
                    setAdminSession(request, {
                        provider: 'oidc',
                        profile: {
                            id: profile.id,
                            username: profile.username,
                            displayName: profile.displayName,
                            email: profile.email,
                            // Carried so the per-request isAuthorized() re-check enforces email
                            // verification the same way the login gate above does.
                            emailVerified: profile.emailVerified,
                            groups: profile.groups
                        },
                        idToken: (request.auth.artifacts && request.auth.artifacts.id_token) || null
                    });

                    request.logger.info({ msg: 'Admin login successful', user: profile.username || 'unknown', method: 'oidc', remoteAddress: request.app.ip });
                    return h.redirect('/admin');
                },
                options: {
                    auth: {
                        mode: 'try',
                        strategy: 'oidc'
                    }
                }
            });
        }
    }

    if (await settings.isInstanceSecured()) {
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

    await server.register([Inert, Vision]);

    // Position is not load-bearing: the document is generated from the finished route table on the
    // first request, not at registration time
    registerOpenApiRoute(server, openApiOptions);

    server.events.on('response', request => {
        const tags = request.route && request.route.settings && request.route.settings.tags;
        if (!tags || !tags.includes('api')) {
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
            auth: false,
            tags: ['static']
        }
    });

    server.route({
        method: 'GET',
        path: '/licenses.html',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'static', 'licenses.html'), confine: false }
        },
        options: {
            auth: false,
            tags: ['static']
        }
    });

    server.route({
        method: 'GET',
        path: '/LICENSE.txt',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), confine: false }
        },
        options: {
            auth: false,
            tags: ['static']
        }
    });

    server.route({
        method: 'GET',
        path: '/LICENSE_EMAILENGINE.txt',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), confine: false }
        },
        options: {
            auth: false,
            tags: ['static']
        }
    });

    server.route({
        method: 'GET',
        path: '/sbom.json',
        handler: {
            file: { path: pathlib.join(__dirname, '..', 'sbom.json'), confine: false }
        },
        options: {
            auth: false,
            tags: ['static']
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
            auth: false,
            tags: ['static']
        }
    });

    const staticRoot = pathlib.resolve(__dirname, '..', 'static');
    const staticRootPrefix = staticRoot + pathlib.sep;

    server.route({
        method: 'GET',
        path: '/static/{file*}',
        handler: {
            directory: {
                path: staticRoot,
                index: false
            }
        },
        options: {
            auth: false,
            tags: ['static'],
            // Prevent EISDIR crash in pkg snapshot environments.
            // Inert calls fs.open() on directory paths which triggers an uncaught exception
            // in pkg's patched fs, so we intercept directory requests before they reach Inert.
            pre: process.pkg
                ? [
                      {
                          method: async request => {
                              const filePath = request.params.file;
                              if (!filePath) {
                                  throw Boom.notFound();
                              }

                              const resolved = pathlib.resolve(staticRoot, filePath);
                              if (!resolved.startsWith(staticRootPrefix)) {
                                  throw Boom.notFound();
                              }

                              try {
                                  const stat = await fs.promises.stat(resolved);
                                  if (stat.isDirectory()) {
                                      throw Boom.notFound();
                                  }
                              } catch (err) {
                                  if (err.isBoom) {
                                      throw err;
                                  }
                                  // stat failed (ENOENT etc.) - let Inert handle it
                              }

                              return null;
                          }
                      }
                  ]
                : undefined
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
            if (!(res[1] && res[1][1] === expected && res[2] && res[2][1] === 1)) {
                let error = Boom.boomify(new Error('Database check failed'), { statusCode: 500 });
                throw error;
            }

            return { success: true };
        },
        options: {
            description: 'Health check',
            auth: false,
            tags: ['static', 'health']
        }
    });

    server.route({
        method: 'GET',
        path: '/redirect',
        async handler(request, h) {
            let data = Buffer.from(request.query.data, 'base64url').toString();
            if (!(await verifyServiceSignature(data, request.query.sig))) {
                let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                throw error;
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
                    // `sig` is intentionally OPTIONAL on the tracking endpoints (/redirect, /open.gif,
                    // /unsubscribe), unlike the hosted form's signedFormBlobFields which requires it. The
                    // handler calls verifyServiceSignature and fails closed on a missing/bad signature, so a
                    // required-sig schema would only turn that 403 into a Joi 400 - and /unsubscribe must not
                    // 400 a missing-sig one-click request (RFC 8058 wants a benign non-throwing response).
                    // Kept optional deliberately; do not "align" these with the hosted-form fragment.
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
            if (!(await verifyServiceSignature(data, request.query.sig))) {
                let error = Boom.boomify(new Error('Signature validation failed'), { statusCode: 403 });
                throw error;
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
                    // sig intentionally optional - see the note on the /redirect schema above.
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
            // This unauthenticated RFC 8058 one-click endpoint separates two failure classes:
            //   - Permanent (forged/malformed/incomplete blob, unknown account): retrying cannot help,
            //     so return a benign 2xx string and do not invite a retry.
            //   - Transient (a Redis/getSecret hiccup while recording the suppression): must surface as
            //     a retryable 5xx. An RFC 8058 client treats any 2xx as "unsubscribed" and never retries,
            //     so swallowing a transient failure to 2xx would silently drop the unsubscribe and the
            //     recipient would keep receiving mail. eeListAdd is idempotent (isNew), so a retry is safe.

            // Joi already enforces base64url on request.query.data, and Buffer.from(<string>, 'base64url')
            // never throws, so decode inline like the sibling /redirect and /open.gif handlers.
            let raw = Buffer.from(request.query.data, 'base64url').toString();

            // A false result is a forged/bad signature (permanent -> benign); a THROWN error is a
            // transient failure reading the service secret and is intentionally left to surface as 5xx.
            if (!(await verifyServiceSignature(raw, request.query.sig))) {
                return 'data validation failed';
            }

            let data;
            try {
                data = JSON.parse(raw);
            } catch (err) {
                // Malformed JSON inside a validly-signed blob - permanent.
                return 'not ok';
            }

            if (!data || typeof data !== 'object' || data.act !== 'unsub' || !data.acc || !data.list || !data.rcpt) {
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
                // A genuine "account does not exist" is a permanent 404 -> benign 2xx (retrying cannot
                // help). Any other error (e.g. a transient Redis/decrypt failure) must NOT be swallowed
                // to a 2xx: an RFC 8058 client treats any 2xx as "unsubscribed" and never retries, so
                // dropping the unsubscribe would leave the recipient subscribed. Let it surface as 5xx.
                if (err.output && err.output.statusCode === 404) {
                    return 'unknown account';
                }
                throw err;
            }

            // Record the suppression. A transient backend failure here is intentionally NOT swallowed to
            // a 2xx: it propagates as a 5xx so the client retries rather than dropping the unsubscribe.
            let isNew = await lists.add(data.list, data.rcpt, {
                account: data.acc,
                source: 'one-click',
                reason: 'unsubscribe',
                messageId: data.msg,
                remoteAddress: request.app.ip,
                userAgent: request.headers['user-agent']
            });

            if (isNew) {
                // The suppression is already stored; a webhook delivery hiccup must not fail (and thus
                // trigger a client retry of) an unsubscribe that already succeeded. Log and move on.
                try {
                    await sendWebhook(data.acc, LIST_UNSUBSCRIBE_NOTIFY, {
                        recipient: data.rcpt,
                        messageId: data.msg,
                        listId: data.list,
                        remoteAddress: request.app.ip,
                        userAgent: request.headers['user-agent']
                    });
                } catch (err) {
                    request.logger.error({ msg: 'Failed to send one-click unsubscribe webhook', err });
                }
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
                    // sig intentionally optional - see the note on the /redirect schema above. Especially
                    // here: making sig required would 400 a missing-sig one-click POST, but RFC 8058 wants a
                    // benign non-throwing response (the handler returns 'data validation failed' instead).
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

            let accountData;
            try {
                accountData = await accountObject.loadAccountData();
            } catch (err) {
                if (err.output && err.output.statusCode === 404) {
                    //ignore, this subscription will expire after a while anyway
                    return h.response(Buffer.alloc(0)).code(202);
                }
                throw err;
            }

            if (!accountData.outlookSubscription) {
                request.logger.error({ msg: 'Subscription not found for account', account: request.query.account, payload: request.payload });
                return h.response(Buffer.alloc(0)).code(202);
            }

            const outlookSubscription = accountData.outlookSubscription;

            for (let entry of (request.payload && request.payload.value) || []) {
                // enumerate and queue all entries
                const subscriptionIdMatch = entry.subscriptionId === outlookSubscription.id;
                const clientStateMatch = constantTimeEqual(entry.clientState, outlookSubscription.clientState);
                if (!subscriptionIdMatch || !clientStateMatch) {
                    // Security: Log webhook validation failures - could indicate spoofed notifications
                    request.logger.warn({
                        msg: 'Webhook validation failed - potential security issue',
                        securityEvent: 'webhook_validation_failure',
                        account: request.query.account,
                        subscriptionIdMatch,
                        clientStateMatch,
                        receivedSubscriptionId: entry.subscriptionId,
                        changeType: entry.changeType,
                        resource: entry.resource
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

            let accountData;
            try {
                accountData = await accountObject.loadAccountData();
            } catch (err) {
                if (err.output && err.output.statusCode === 404) {
                    //ignore, this subscription will expire after a while anyway
                    return h.response(Buffer.alloc(0)).code(202);
                }
                throw err;
            }

            if (!accountData.outlookSubscription) {
                request.logger.error({ msg: 'Subscription not found for account', account: request.query.account, payload: request.payload });
                return h.response(Buffer.alloc(0)).code(202);
            }

            const outlookSubscription = accountData.outlookSubscription;

            // Deduplicate lifecycle events within the same batch to prevent
            // concurrent handlers racing (e.g., two subscriptionRemoved entries)
            const seenLifecycleEvents = new Set();

            for (let entry of (request.payload && request.payload.value) || []) {
                request.logger.debug({
                    msg: 'MS Graph subscription event',
                    type: 'lifecycle',
                    account: request.query.account,
                    lifecycleEvent: entry.lifecycleEvent,
                    subscriptionId: entry.subscriptionId
                });

                // enumerate and queue all entries
                const subscriptionIdMatch = entry.subscriptionId === outlookSubscription.id;
                const clientStateMatch = constantTimeEqual(entry.clientState, outlookSubscription.clientState);
                if (!subscriptionIdMatch || !clientStateMatch) {
                    // Security: Log lifecycle webhook validation failures - could indicate spoofed notifications
                    request.logger.warn({
                        msg: 'Lifecycle webhook validation failed - potential security issue',
                        securityEvent: 'lifecycle_webhook_validation_failure',
                        account: request.query.account,
                        subscriptionIdMatch,
                        clientStateMatch,
                        receivedSubscriptionId: entry.subscriptionId,
                        lifecycleEvent: entry.lifecycleEvent
                    });
                    continue;
                }

                // Route recognized lifecycle events to the IMAP worker
                // so the live client with its OAuth state handles them
                if (entry.lifecycleEvent === 'reauthorizationRequired' || entry.lifecycleEvent === 'subscriptionRemoved' || entry.lifecycleEvent === 'missed') {
                    const dedupeKey = `${entry.lifecycleEvent}:${entry.subscriptionId}`;
                    if (seenLifecycleEvents.has(dedupeKey)) {
                        request.logger.debug({
                            msg: 'Skipping duplicate lifecycle event in batch',
                            lifecycleEvent: entry.lifecycleEvent,
                            subscriptionId: entry.subscriptionId,
                            account: request.query.account
                        });
                        continue;
                    }
                    seenLifecycleEvents.add(dedupeKey);

                    request.logger.info({
                        msg: 'Received lifecycle event',
                        lifecycleEvent: entry.lifecycleEvent,
                        subscriptionId: outlookSubscription.id,
                        account: request.query.account
                    });

                    // Fire-and-forget: return HTTP 202 immediately so Microsoft
                    // does not time out the lifecycle webhook delivery
                    call({
                        cmd: 'subscriptionLifecycle',
                        account: request.query.account,
                        event: entry.lifecycleEvent,
                        timeout: consts.OUTLOOK_SUBSCRIPTION_LOCK_TTL
                    }).catch(err => {
                        request.logger.error({
                            msg: 'Failed to handle lifecycle event via worker',
                            account: request.query.account,
                            lifecycleEvent: entry.lifecycleEvent,
                            err
                        });
                    });
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
                let error = Boom.boomify(new Error(`Oauth failed: no code received`), { statusCode: 400 });
                throw error;
            }

            if (!/^account:add:/.test(request.query.state)) {
                let error = Boom.boomify(new Error(`Oauth failed: invalid state received`), { statusCode: 400 });
                throw error;
            }

            // Validate nonce format: 16 bytes base64url encoded = 21-22 characters
            // Also accept base64 encoding (+, /, =) for backward compatibility with old cached nonces
            const stateNonce = request.query.state.slice('account:add:'.length);
            if (!/^[A-Za-z0-9_\-+/]{21,22}={0,2}$/.test(stateNonce)) {
                throw Boom.badRequest('Oauth failed: invalid state format');
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

            // What the caller originally asked for, captured before the provider branches below rewrite
            // accountData from whoever signed in. A retry has to start from this rather than from the
            // rejected attempt: `email` may name a shared mailbox to bind (and is otherwise overwritten
            // with the authenticated address), `name` gets filled in from the rejected user's profile when
            // the caller supplied none, and `oauth2.auth.delegatedUser` names the mailbox rather than a
            // credential, so it must survive while the tokens do not.
            const requestedSetup = {
                email: accountData.email,
                name: accountData.name,
                delegatedUser: accountData.oauth2.auth && accountData.oauth2.auth.delegatedUser
            };

            const oauth2App = await oauth2Apps.get(provider);
            if (!oauth2App) {
                let error = Boom.boomify(new Error('Missing or disabled OAuth2 app'), { statusCode: 404 });
                throw error;
            }

            const oAuth2Client = await oauth2Apps.getClient(oauth2App.id);

            // have to use HTML redirect, otherwise samesite=strict cookies are not passed on
            const renderRedirect = httpRedirectUrl =>
                h.view(
                    'redirect',
                    {
                        pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                        httpRedirectUrl
                    },
                    {
                        layout: 'public'
                    }
                );

            // Hands the user back to the provider after a failure they can correct themselves, as a fresh
            // single-use setup. The token-bearing oauth2 object is dropped so the retry starts clean, and
            // _meta rides along so the redirect URL, the expected identity and the form nonce all survive
            // it - that nonce is claimed only on success, so it is still unspent here.
            const startOAuthRetry = async (loginHint, prompt) => {
                const reAuthState = `account:add:${crypto.randomBytes(NONCE_BYTES).toString('base64url')}`;
                const reAuthAccountData = buildRetrySetup(accountData, requestedSetup, provider, accountMeta);

                await redis.set(`${REDIS_PREFIX}${reAuthState}`, JSON.stringify(reAuthAccountData), 'EX', Math.floor(MAX_FORM_TTL / 1000));

                // The address to steer the user towards rides on the authorize URL only - persisting it
                // would overwrite a shared mailbox with the principal that is signing in to reach it.
                return oAuth2Client.generateAuthUrl({ state: reAuthState, email: loginHint, prompt });
            };

            // Addresses the provider itself returned over a back channel, the only values allowed to
            // satisfy an expected identity (see lib/account/expected-identity.js). Every provider case
            // fills this in; one that does not leaves it empty, and an empty list fails the check closed.
            const providerIdentities = [];

            // The token to revoke if the setup is rejected after the code was already exchanged, set by
            // each provider case because the token response is scoped to the switch. Prefer the refresh
            // token: revoking either invalidates the grant, but the access token may already be expired.
            let grantToken;

            // `app.provider` is for example "gmail", `provider` is oauth2 app id
            switch (oauth2App.provider) {
                case 'gmail': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    const grantedScopes = r.scope ? r.scope.split(/\s+/) : [];

                    request.logger.info({ msg: 'OAuth token received', grantedScopes, hasIdToken: !!r.id_token });

                    // Check if user deselected required scopes in Google's granular consent
                    const requiredFunctionalScopes = oAuth2Client.scopes.filter(s => !OPENID_SCOPES.includes(s));
                    const missingScopes = requiredFunctionalScopes.filter(s => !grantedScopes.includes(s));

                    if (missingScopes.length > 0) {
                        request.logger.warn({
                            msg: 'OAuth2 grant missing required scopes',
                            requested: requiredFunctionalScopes,
                            granted: grantedScopes,
                            missing: missingScopes
                        });

                        // Best-effort revocation of the partial token
                        oAuth2Client.revokeToken(r.refresh_token || r.access_token).catch(err => {
                            request.logger.error({ msg: 'Failed to revoke partial OAuth2 token', err });
                        });

                        const retryUrl = await startOAuthRetry(accountData.email);

                        const missingScopesList = missingScopes.map(formatScopeDescription);

                        return h.view(
                            'oauth-scope-error',
                            {
                                pageTitleFull: request.app.gt.gettext('Email Account Setup'),
                                templateLocale: request.app.locale,
                                retryUrl,
                                missingScopesList
                            },
                            {
                                layout: 'public'
                            }
                        );
                    }

                    let profileRes;
                    let userEmail;
                    let userName;

                    // With OpenID Connect scopes (openid, email, profile), the ID token contains user info
                    // This works for all account types including send-only accounts
                    const idTokenPayload = decodeJwtPayload(r.id_token);
                    if (r.id_token && !idTokenPayload) {
                        request.logger.error({ msg: 'Failed to decode Gmail ID token' });
                    }
                    if (idTokenPayload && typeof idTokenPayload.email === 'string' && isEmail(idTokenPayload.email)) {
                        userEmail = idTokenPayload.email;
                        userName = idTokenPayload.name || null;
                        request.logger.info({ msg: 'Extracted user info from ID token', userEmail, userName });
                    }

                    // If ID token didn't provide email, fall back to Gmail API profile endpoint
                    // This should rarely happen since we now request openid/email/profile scopes
                    if (!userEmail) {
                        // Check if we have scopes that allow accessing the profile endpoint
                        const hasProfileScope =
                            grantedScopes.includes('https://mail.google.com/') ||
                            grantedScopes.includes('https://www.googleapis.com/auth/gmail.readonly') ||
                            grantedScopes.includes('https://www.googleapis.com/auth/gmail.modify') ||
                            grantedScopes.includes('https://www.googleapis.com/auth/gmail.metadata');

                        if (hasProfileScope) {
                            try {
                                request.logger.info({ msg: 'Attempting Gmail profile endpoint as fallback' });
                                profileRes = await oAuth2Client.request(r.access_token, 'https://gmail.googleapis.com/gmail/v1/users/me/profile');
                                if (profileRes && profileRes.emailAddress) {
                                    userEmail = profileRes.emailAddress;
                                }
                            } catch (err) {
                                request.logger.error({ msg: 'Failed to fetch user info from Gmail API', err: err.message });
                                let response = err.oauthRequest && err.oauthRequest.response;
                                if (response && response.error) {
                                    let message;
                                    if (/Gmail API has not been used in project/.test(response.error.message)) {
                                        message =
                                            'Can not perform requests against Gmail API as the project has not been enabled. If you are the admin, check notifications on the dashboard.';
                                    } else {
                                        message = response.error.message;
                                    }

                                    let error = Boom.boomify(new Error(message), { statusCode: resolveOAuthErrorStatus(response.error, err) });
                                    throw error;
                                }
                                throw err;
                            }
                        }
                    }

                    if (!userEmail) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    // Back-channel only: either the id_token from the token endpoint or the Gmail profile
                    // API response, never a value that travelled through the browser.
                    providerIdentities.push(userEmail);
                    grantToken = r.refresh_token || r.access_token;

                    accountData.email = isEmail(userEmail) ? userEmail : accountData.email;

                    const defaultScopes = (oauth2App.baseScopes && GMAIL_SCOPES[oauth2App.baseScopes]) || GMAIL_SCOPES.imap;

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: grantedScopes.length ? grantedScopes : defaultScopes,
                            tokenType: r.token_type
                        },
                        {
                            auth: {
                                user: userEmail
                            }
                        }
                    );

                    accountData.googleHistoryId = profileRes ? Number(profileRes.historyId) || null : null;

                    request.logger.info({ msg: 'Provisioned OAuth2 tokens', user: userEmail, provider: oauth2App.provider });
                    break;
                }

                case 'outlook': {
                    const r = await oAuth2Client.getToken(request.query.code);
                    if (!r || !r.access_token) {
                        let error = Boom.boomify(new Error(`Oauth failed: did not get token`), { statusCode: 400 });
                        throw error;
                    }

                    let userInfo;

                    if (!oauth2App.baseScopes || oauth2App.baseScopes === 'imap') {
                        // Read account info from the id_token, falling back to the client_info GET argument.
                        // The fallback is needed because previously EmailEngine did not request for the
                        // User.Read scope - but client_info arrives through the browser, so it is a display
                        // fallback only and never counts as identity evidence. See lib/oauth/outlook-identity.js.

                        let clientInfo = false;
                        if (request.query.client_info) {
                            try {
                                clientInfo = JSON.parse(Buffer.from(request.query.client_info, 'base64url').toString());
                            } catch (err) {
                                // Base64-shaped but not JSON. It is an optional display hint, so log and continue
                                // rather than failing the whole setup on a value we do not trust anyway.
                                request.logger.warn({ msg: 'Failed to decode Outlook client_info argument', err });
                            }
                        }

                        const idTokenPayload = decodeJwtPayload(r.id_token);
                        if (r.id_token && !idTokenPayload) {
                            request.logger.error({ msg: 'Failed to decode JWT payload' });
                        }

                        userInfo = resolveOutlookUserInfo({ clientInfo, idTokenPayload });
                    } else {
                        // Request profile info from API

                        let profileRes;
                        try {
                            profileRes = await oAuth2Client.request(r.access_token, `${oAuth2Client.apiBase}/v1.0/me`);
                        } catch (err) {
                            let response = err.oauthRequest && err.oauthRequest.response;
                            if (response && response.error) {
                                let message = response.error.message;
                                let error = Boom.boomify(new Error(message), { statusCode: resolveOAuthErrorStatus(response.error, err) });
                                throw error;
                            }
                            throw err;
                        }

                        userInfo = resolveOutlookUserInfo({ profile: profileRes });

                        request.logger.info({
                            msg: 'User profile returned by MS Graph API',
                            user: userInfo.email,
                            provider: oauth2App.provider,
                            profile: profileRes
                        });
                    }

                    const authData = {
                        user: userInfo.username || userInfo.email
                    };

                    if (!authData.user) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    // Only the back-channel addresses, so a forged client_info cannot satisfy an expectation.
                    providerIdentities.push(...userInfo.verifiedIdentities);
                    grantToken = r.refresh_token || r.access_token;

                    if (accountData.oauth2 && accountData.oauth2.auth && accountData.oauth2.auth.delegatedUser) {
                        // Delegated user (shared mailbox) specified in oauth2.auth.delegatedUser
                        authData.delegatedUser = accountData.oauth2.auth.delegatedUser;
                        // Ensure email is set to the delegated user if not already provided
                        if (!accountData.email) {
                            accountData.email = accountData.oauth2.auth.delegatedUser;
                        }
                    } else if (accountData.delegated && accountData.email && accountData.email !== userInfo.email) {
                        // Legacy: Shared mailbox specified via delegated flag
                        authData.delegatedUser = accountData.email;
                    } else {
                        // Not a delegated account, use the authenticated user's email
                        accountData.email = userInfo.email;
                    }

                    accountData.name = accountData.name || userInfo.name || '';

                    accountData.oauth2 = Object.assign(
                        accountData.oauth2 || {},
                        {
                            provider,
                            accessToken: r.access_token,
                            refreshToken: r.refresh_token,
                            expires: new Date(Date.now() + r.expires_in * 1000),
                            scope: r.scope ? r.scope.split(/\s+/) : oAuth2Client.scopes,
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
                            let error = Boom.boomify(new Error(message), { statusCode: resolveOAuthErrorStatus(response.error, err) });
                            throw error;
                        }
                        throw err;
                    }

                    if (!profileRes || !profileRes || !profileRes.email) {
                        let error = Boom.boomify(new Error(`Oauth failed: failed to retrieve account email address`), { statusCode: 400 });
                        throw error;
                    }

                    // Back-channel only: the Mail.ru userinfo endpoint response.
                    providerIdentities.push(profileRes.email);
                    grantToken = r.refresh_token || r.access_token;

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

            // Expected identity check. Runs before the nonce claim and before create(), so a rejected
            // setup neither consumes the signed link nor overwrites the credentials already on the
            // account. The expectation can come from the signed form blob or from the account itself -
            // persisting it is what makes the constraint outlive the link that introduced it, and it is
            // why a later link issued without expectedEmail cannot quietly drop the pin.
            const expectedEmail = await resolveExpectedIdentity(redis, {
                account: accountData.account,
                blobExpectation: pendingSetupExpectation(accountData, accountMeta)
            });

            if (expectedEmail && !matchesExpectedIdentity(expectedEmail, providerIdentities)) {
                // Neither address is logged: the expectation and the authenticated identity both belong to
                // the end user, and this line is the one record of a failed attempt. Note the provider
                // identity was already logged by the "Provisioned OAuth2 tokens" line above.
                request.logger.warn({
                    msg: 'OAuth2 identity did not match the expected email address',
                    account: accountData.account,
                    provider: oauth2App.provider
                });

                // The code was already exchanged, so we are holding a refresh token we will never use.
                // Best effort, and the same duck-typing guard Account.delete({ revoke }) uses: only
                // GmailOauth implements revokeToken, and a rejected setup must not become a 500.
                if (grantToken && typeof oAuth2Client.revokeToken === 'function') {
                    try {
                        await oAuth2Client.revokeToken(grantToken);
                    } catch (err) {
                        request.logger.error({ msg: 'Failed to revoke the OAuth2 grant after an identity mismatch', err });
                    }
                }

                // Stop here with a way back rather than redirecting to the calling application: signing in
                // as the wrong account is a correctable mistake, and the hosted flow only ever redirects on
                // success. Hint the address they were supposed to use, and force the account picker:
                // they are already signed in to the one that just failed, so without select_account Google
                // would hand back the same account and the retry would loop. Microsoft always shows the
                // picker and Mail.ru ignores the hint, so this only changes Google's behavior.
                const retryUrl = await startOAuthRetry(expectedEmail, 'select_account consent');

                return identityErrorView(request, h, {
                    expectedEmail,
                    // The primary address the provider reported. Microsoft can return both a mailbox
                    // address and a user principal name, and either would have satisfied the pin, so
                    // naming the first is enough to show which account actually signed in.
                    actualEmail: providerIdentities[0],
                    retryUrl
                });
            }

            if (expectedEmail) {
                // Pin the account so every later setup is checked, including one driven by a link that
                // carries no expectation of its own.
                accountData.expectedEmail = expectedEmail;
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

            // Claim the single-use nonce BEFORE create (SET NX), mirroring the IMAP arm in
            // lib/ui-routes/account-routes.js, so one signed link cannot be double-spent across the two
            // arms (initiate OAuth -> submit the same blob to /accounts/new/imap/server -> complete this
            // callback) and a replayed callback cannot create a second account.
            //
            // Backward-compat, BY DESIGN: this only engages when accountMeta.n is present. Legacy /
            // pre-upgrade re-auth blobs carry no nonce (accountMeta.n is undefined), so the claim is
            // skipped and those links keep working - the OAuth entry (accountFormHandler) intentionally
            // does NOT require a nonce for exactly that reason.
            // claimFormNonce/releaseFormNonce (lib/tools.js) are the same primitives the IMAP arm uses, so
            // the double-spend semantics stay in one place.
            let nonceClaimed = false;
            if (accountMeta.n) {
                let claimed;
                try {
                    claimed = await claimFormNonce(redis, accountMeta.n, accountMeta.t);
                } catch (err) {
                    // A Redis failure is not a consumed nonce - surface a retryable error rather than
                    // misreporting a valid setup URL as invalid.
                    request.logger.error({ msg: 'Failed to claim nonce for an account form request', err });
                    throw Boom.boomify(new Error('Temporary error, please try again'), { statusCode: 500 });
                }
                if (!claimed) {
                    // The nonce key already exists: this signed URL was already used.
                    throw Boom.boomify(new Error('Invalid or expired account setup URL'), { statusCode: 403 });
                }
                nonceClaimed = true;
            }

            let result;
            try {
                result = await accountObject.create(accountData);
            } catch (err) {
                // Release the nonce so the user can retry (same accepted residual as the IMAP arm: if
                // Redis also fails here the nonce stays consumed for its TTL and a fresh link is needed -
                // the price of claim-before-create being atomic).
                if (nonceClaimed) {
                    await releaseFormNonce(redis, accountMeta.n, request.logger);
                }
                throw err;
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

            return renderRedirect(httpRedirectUrl);
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
                        // A few hundred bytes of JSON in practice. Bounded tightly because this is an
                        // unauthenticated route and the value is JSON.parse-d.
                        .max(4 * 1024)
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

    // setup every /v1 route module (wiring lives in lib/api-routes/index.js so the route table
    // can be captured without booting this worker - see test/api-routes-table-test.js)
    await registerApiRoutes({
        server,
        call,
        notify,
        documentsQueue,
        metrics,
        CORS_CONFIG,
        FLAG_SORT_ORDER,
        SMTP_TEST_HOST,
        MAX_ATTACHMENT_SIZE,
        MAX_BODY_SIZE,
        MAX_PAYLOAD_TIMEOUT,
        documentStoreFeatureEnabled,
        oauth2Schema,
        imapSchema,
        smtpSchema,
        AccountTypeSchema,
        OAuth2ProviderSchema
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

                if (tags.includes('api') || tags.includes('scope:metrics') || tags.includes('static') || tags.includes('external')) {
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
                templateHtmlHead: embeddedTemplateHtmlHead,
                documentStoreEnabled: showDocumentStore,
                serviceUrl,
                language,
                locale,
                timezone,
                pageBrandName,
                notificationBaseUrl
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
                'templateHtmlHead',
                'documentStoreEnabled',
                'serviceUrl',
                'language',
                'locale',
                'timezone',
                'pageBrandName',
                'notificationBaseUrl'
            );

            let systemAlerts = [];
            let authData;

            // Deprecated Document Store: enabled in settings but unavailable because EmailEngine
            // was not started with the document store gate (--documentStore.enabled / EENGINE_DOCUMENT_STORE_ENABLED).
            let documentStoreUnavailable = !documentStoreFeatureEnabled && !!showDocumentStore;

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

                case 'oidc': {
                    let profile = request.auth.artifacts.profile || {};
                    authData = {
                        user: profile.username,
                        name: profile.displayName || profile.username,
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
                    icon: 'icon-[tabler--alert-triangle]',
                    message: `An update is available: Emailengine v${upgradeInfo.available}`
                });
            }

            if (subexp && !(request.app.licenseInfo && request.app.licenseInfo.details && request.app.licenseInfo.details.lt)) {
                let delayMs = new Date(subexp) - Date.now();
                let expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);

                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'danger',
                    icon: 'icon-[tabler--alert-triangle]',
                    message: `The license key needs to be renewed or replaced in ${expiresDays} day${expiresDays !== 1 ? 's' : ''}`
                });
            }

            if (outlookAuthFlag && outlookAuthFlag.message) {
                systemAlerts.push({
                    url: outlookAuthFlag.url || '/admin/config/oauth/app/outlook',
                    level: 'danger',
                    icon: 'icon-[tabler--lock-open]',
                    message: outlookAuthFlag.message
                });
            }

            if (gmailAuthFlag && gmailAuthFlag.message) {
                systemAlerts.push({
                    url: gmailAuthFlag.url || '/admin/config/oauth/app/gmail',
                    level: 'danger',
                    icon: 'icon-[tabler--lock-open]',
                    message: gmailAuthFlag.message
                });
            }

            if (gmailServiceAuthFlag && gmailServiceAuthFlag.message) {
                systemAlerts.push({
                    url: gmailServiceAuthFlag.url || '/admin/config/oauth/app/gmailService',
                    level: 'danger',
                    icon: 'icon-[tabler--lock-open]',
                    message: gmailServiceAuthFlag.message
                });
            }

            if (webhooksEnabled && webhookErrorFlag && webhookErrorFlag.message) {
                systemAlerts.push({
                    url: '/admin/config/webhooks',
                    level: 'danger',
                    icon: 'icon-[tabler--link]',
                    message: 'Webhook delivery is failing'
                });
            }

            if (!request.app.licenseInfo || !request.app.licenseInfo.active) {
                systemAlerts.push({
                    url: '/admin/config/license',
                    level: 'warning',
                    icon: 'icon-[tabler--key]',
                    message: 'No license key registered'
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
                    icon: 'icon-[tabler--key]',
                    message: `Your ${licenseDetails.trial ? `trial ` : ''}license key will expire in ${licenseDetails.expiresDays} day${
                        licenseDetails.expiresDays !== 1 ? 's' : ''
                    }`
                });
            }

            if (disableTokens) {
                systemAlerts.push({
                    url: '/admin/config/security',
                    level: 'warning',
                    icon: 'icon-[tabler--key]',
                    message: `Access tokens are disabled for API requests`
                });
            }

            if (documentStoreUnavailable) {
                systemAlerts.push({
                    url: '/admin',
                    level: 'danger',
                    icon: 'icon-[tabler--database]',
                    message: `The Document Store is enabled in settings but unavailable. Start EmailEngine with the document store gate to use it, or disable the setting.`
                });
            }

            // Check if setup warnings should be disabled (for documentation screenshots, CI, etc.)
            const disableSetupWarnings = hasEnvValue('EENGINE_DISABLE_SETUP_WARNINGS') ? getBoolean(readEnvValue('EENGINE_DISABLE_SETUP_WARNINGS')) : false;

            if (disableSetupWarnings) {
                // Keep only critical (danger) alerts, suppress info/warning level
                systemAlerts = systemAlerts.filter(alert => alert.level === 'danger');
            }

            return {
                pageBrandName: pageBrandName || 'EmailEngine',
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
                embeddedTemplateHtmlHead,
                currentYear: new Date().getFullYear(),
                showDocumentStore: documentStoreFeatureEnabled && showDocumentStore,
                documentStoreUnavailable,
                updateBrowserInfo: !serviceUrl || !language || !timezone,

                // Suppress large banner warnings when EENGINE_DISABLE_SETUP_WARNINGS is set
                hideLicenseWarning: disableSetupWarnings,
                disableAuthWarning: disableSetupWarnings,

                mainServiceUrl: serviceUrl,
                notificationBaseUrl,

                userLocale: locale,
                userTimezone: timezone,

                templateLocale: request.app.locale
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
            statusCode: error.output.statusCode,
            message:
                error.output.statusCode === 404
                    ? request.app.gt.gettext('Requested page not found')
                    : (error.output && error.output.payload && error.output.payload.message) || request.app.gt.gettext('Something went wrong'),
            details: error.output && error.output.payload && error.output.payload.details,
            templateLocale: request.app.locale
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

        const tags = (request.route && request.route.settings && request.route.settings.tags) || [];
        const isApiRoute = tags.includes('api') || tags.includes('test');

        if (isApiRoute) {
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

        // Same feed as /v1/changes (lib/api-routes/changes-routes.js), opened through the shared
        // helper so the two can not drift apart on framing or on stream cleanup.
        handler: openChangeStream
    });

    // setup web UI
    routesUi(server, call);

    // setup "Bull board" routes
    await bullBoardRoutes({ server });

    server.route({
        method: 'GET',
        path: '/metrics',

        async handler(request, h) {
            const renderedMetrics = await call({ cmd: 'metrics', timeout: request.headers['x-ee-timeout'] });
            return h.response(renderedMetrics).type('text/plain');
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
        async handler(request) {
            throw Boom.notFound(request.app.gt.gettext('Requested page not found')); // 404
        }
    });

    await server.start();

    if (USE_REUSE_PORT) {
        // Hapi (autoListen:false) wired its request dispatcher to our listener but did not
        // bind it. Bind now with SO_REUSEPORT so the kernel distributes connections across
        // all API workers. listen() can throw synchronously (bad args) or emit 'error'
        // asynchronously (EADDRINUSE/EACCES/ENOTSUP); handle both, mirroring probeReusePort().
        await new Promise((resolve, reject) => {
            const onError = err => {
                let wrapped = new Error(
                    `Failed to bind API worker ${WORKER_INDEX} to ${API_HOST}:${API_PORT} with SO_REUSEPORT` + (err && err.code ? ` (${err.code})` : '')
                );
                wrapped.code = err && err.code;
                wrapped.workerIndex = WORKER_INDEX;
                wrapped.host = API_HOST;
                wrapped.port = API_PORT;
                reject(wrapped);
            };
            reusePortListener.once('error', onError);
            try {
                reusePortListener.listen({ port: API_PORT, host: API_HOST, reusePort: true }, () => {
                    reusePortListener.removeListener('error', onError);
                    resolve();
                });
            } catch (err) {
                reusePortListener.removeListener('error', onError);
                onError(err);
            }
        });
    }

    // An IP allowlist is only as trustworthy as the address it matches against. If the deployment
    // takes the client address from X-Forwarded-For but does not say which peers may set it, any
    // client that can reach this port can present whatever address the allowlist expects.
    // Length-checked, not just null-checked: readEnvList returns [] for a variable that is present
    // but empty (an unset shell interpolation, an empty secret), which is truthy. resolveClientIp
    // treats that as no proxies configured, so the warning has to agree or it goes quiet in
    // exactly the deployment it exists to warn.
    if (ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length && !API_PROXY_ADDRESSES?.length && (await settings.get('enableApiProxy'))) {
        logger.warn({
            msg: 'Admin IP allowlist is spoofable because X-Forwarded-For is trusted from any peer. Set EENGINE_API_PROXY_ADDRESSES to the addresses of your proxies, or disable the API proxy setting.',
            component: 'api',
            allowedAddresses: ADMIN_ACCESS_ADDRESSES
        });
    }

    // Warm the swagger.json cache, and with it the /admin/reference render model - which
    // reads the same document back and costs ~12ms to build. Doing both here keeps that
    // work off the first visitor's request.
    setImmediate(() => {
        getApiReferenceModel(server)
            .then(model => {
                logger.debug({ msg: 'Built the API reference model', operations: model.operationCount });
            })
            .catch(err => {
                logger.debug({ msg: 'Failed to build the API reference model', err });
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
                IS_PRIMARY_API_WORKER &&
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

        // Start sending heartbeats to main thread
        setInterval(() => {
            try {
                parentPort.postMessage({ cmd: 'heartbeat' });
            } catch (err) {
                // Ignore errors, parent might be shutting down
            }
        }, 10 * 1000).unref();
    })
    .catch(err => {
        logger.error({ msg: 'Failed to initialize API', err });
        logger.flush(() => process.exit(3));
    });
