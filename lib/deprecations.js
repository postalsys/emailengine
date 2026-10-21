'use strict';

// Interfaces that are scheduled for removal, and how their callers are told. Dependency-free, so
// the route modules and server.js can both use it and a test needs nothing running.
//
// - The pre-2.79 token endpoints (POST /v1/token, DELETE /v1/token/{token},
//   GET /v1/tokens/account/{account}) answer with the Deprecation (RFC 9745), Sunset (RFC 8594)
//   and Link rel="successor-version" headers, and each use is logged at warn, at most once an hour
//   per endpoint and worker, so a busy integration does not flood the log. A route opts in with a
//   `plugins.deprecation` block ({ since, successor, link }), which the one server-level
//   onPreResponse extension from deprecationExt() reads, the way lib/security-headers.js reads
//   `plugins.securityHeaders`.
// - The /admin/bull-board redirects to the queue browser, through the same plugins.deprecation
//   block as the token endpoints.
// - The legacy SMTP server options (EENGINE_SMTP_ENABLED/_SECRET/_PORT/_HOST/_PROXY and the matching
//   [smtp] config keys) only seed the SMTP server settings on a first start. Their use is logged at
//   startup. The EENGINE_SMTP_TLS_* variables and [smtp] maxMessageSize / maxClients are current
//   and not affected.
// - Request fields that are still accepted although what they controlled is gone or replaced
//   (DEPRECATED_FIELDS). Their schema carries a custom rule from deprecatedField(), so a request
//   that sends one is logged at warn, at most once an hour per field and worker, from whichever
//   route and location it arrives through. The rule is on the schema rather than on the routes
//   because most of these fields are shared by several routes and nested in their payloads.

const REMOVAL_DATE = '2027-01-01';

// HTTP-date form of REMOVAL_DATE, for the Sunset header
const SUNSET_HTTP_DATE = new Date(`${REMOVAL_DATE}T00:00:00Z`).toUTCString();

// When the token endpoints were deprecated: the 2.79.0 release, which renamed them
const TOKEN_ROUTES_DEPRECATED_AT = Date.parse('2026-08-18T07:47:01Z');

// When the /admin/bull-board redirects were deprecated: the 2.84.0 release, which replaced
// bull-board with the queue browser at /admin/queues
const BULL_BOARD_REDIRECTS_DEPRECATED_AT = Date.parse('2026-10-15T07:35:26Z');

const LOG_INTERVAL = 60 * 60 * 1000;

const LEGACY_SMTP_ENV = ['EENGINE_SMTP_ENABLED', 'EENGINE_SMTP_SECRET', 'EENGINE_SMTP_PORT', 'EENGINE_SMTP_HOST', 'EENGINE_SMTP_PROXY'];

// The built-in values of the legacy [smtp] keys (config/default.toml); only a different value
// means an operator set one
const LEGACY_SMTP_CONFIG_DEFAULTS = { enabled: false, port: 2525, host: '127.0.0.1', secret: '', proxy: false };

/**
 * Response headers that announce a deprecated endpoint
 * @param {number} deprecatedAt - When it was deprecated, in milliseconds
 * @param {string} [link] - Path of the endpoint to use instead, for the Link header. Left out where
 *     the successor path would have to carry a request parameter, such as a token
 * @returns {Object} Header name to value
 */
function deprecationHeaders(deprecatedAt, link) {
    const headers = {
        Deprecation: `@${Math.floor(deprecatedAt / 1000)}`,
        Sunset: SUNSET_HTTP_DATE
    };
    if (link) {
        headers.Link = `<${link}>; rel="successor-version"`;
    }
    return headers;
}

/**
 * Server-level onPreResponse extension for deprecated endpoints. A route declares itself with
 * `options.plugins.deprecation`:
 *   - `since` - when it was deprecated, in milliseconds
 *   - `successor` - the endpoint to use instead, as logged, e.g. "POST /v1/tokens"
 *   - `link` - optional, its path for the Link header, see deprecationHeaders()
 * Every response of such a route, errors included, carries the headers, and its use is logged
 * @param {Object} opts
 * @param {Object} opts.logger - pino logger
 * @param {Function} [opts.now] - Clock, for tests
 * @returns {Function} The extension method
 */
function deprecationExt(opts) {
    const { logger, now = Date.now } = opts;
    // per method and path, so every deprecated endpoint in use is reported
    const lastLogged = new Map();

    return function deprecationResponse(request, h) {
        const deprecation = request.route && request.route.settings.plugins && request.route.settings.plugins.deprecation;
        if (!deprecation) {
            return h.continue;
        }

        const response = request.response;
        const target = response && response.isBoom ? response.output.headers : response && response.headers;
        if (target) {
            Object.assign(target, deprecationHeaders(deprecation.since, deprecation.link));
        }

        const method = request.method.toUpperCase();
        const key = `${method} ${request.route.path}`;
        const time = now();
        if (!lastLogged.has(key) || time - lastLogged.get(key) >= LOG_INTERVAL) {
            lastLogged.set(key, time);
            logger.warn({
                msg: 'Deprecated API endpoint called',
                method,
                path: request.route.path,
                successor: deprecation.successor,
                removal: REMOVAL_DATE,
                // the token's id (its hash), as the rate limiter logs it, never the token itself
                token: (request.auth && request.auth.artifacts && request.auth.artifacts.id) || undefined
            });
        }

        return h.continue;
    };
}

/**
 * The legacy SMTP server options an operator set
 * @param {Object} opts
 * @param {Function} opts.hasEnvValue - Whether an environment value is set (lib/read-env-value)
 * @param {Object} [opts.smtpConfig] - The [smtp] section of the loaded config
 * @returns {string[]} Option names, environment variables first
 */
function legacySmtpOptionsInUse({ hasEnvValue, smtpConfig }) {
    const used = LEGACY_SMTP_ENV.filter(name => hasEnvValue(name));
    for (const [key, defaultValue] of Object.entries(LEGACY_SMTP_CONFIG_DEFAULTS)) {
        const value = smtpConfig && smtpConfig[key];
        if (value === undefined || value === null) {
            continue;
        }
        // config values can arrive as strings from --smtp.port=2525 style arguments
        if (String(value) !== String(defaultValue)) {
            used.push(`[smtp] ${key}`);
        }
    }
    return used;
}

// The request fields deprecatedField() reports, with what to use instead. Removed after REMOVAL_DATE
const DEPRECATED_FIELDS = {
    documentStore: 'nothing, the Document Store was removed in 2.82.0',
    syncFrom: 'nothing, the Document Store was removed in 2.82.0',
    documentStoreEnabled: 'nothing, the Document Store was removed in 2.82.0',
    generateRiskAssessment: 'nothing, the risk assessment was removed',
    openAiGenerateEmbeddings: 'nothing, embeddings generation was removed in 2.82.0',
    trackSentMessages: 'the trackClicks and trackOpens settings',
    'oauth2.authority': 'the authority setting of the OAuth2 application',
    tenant: 'the tenant ID as the authority of the OAuth2 application'
};

/**
 * Reports uses of deprecated request fields, at most once per LOG_INTERVAL per field
 * @param {Object} opts
 * @param {Function} opts.getLogger - Returns the logger, resolved on the first report
 * @param {Function} [opts.now] - Clock, for tests
 * @returns {Function} (field) => void
 */
function createFieldReporter(opts) {
    const { getLogger, now = Date.now } = opts;
    const lastLogged = new Map();

    return function reportDeprecatedField(field) {
        const time = now();
        if (lastLogged.has(field) && time - lastLogged.get(field) < LOG_INTERVAL) {
            return;
        }
        lastLogged.set(field, time);
        getLogger().warn({
            msg: 'Deprecated request field used',
            field,
            successor: DEPRECATED_FIELDS[field],
            removal: REMOVAL_DATE
        });
    };
}

// Resolved lazily: lib/schemas.js requires this module, and the logger has no business loading
// before something is actually reported
let defaultReporter = createFieldReporter({ getLogger: () => require('./logger') });

/**
 * A joi custom rule that reports the use of a deprecated field and passes its value on unchanged.
 * Joi runs it only for a value that is present, after `.empty()`, so an empty string sent by a form
 * is not a use.
 * @param {string} field - DEPRECATED_FIELDS key
 * @returns {Array} Arguments for joi's `.custom()`
 */
function deprecatedField(field) {
    if (!Object.hasOwn(DEPRECATED_FIELDS, field)) {
        throw new Error(`${field} is not a deprecated field`);
    }
    return [
        value => {
            defaultReporter(field);
            return value;
        },
        `deprecated field ${field}`
    ];
}

/**
 * Replaces the reporter deprecatedField() rules call, for tests
 * @param {Function} reporter - (field) => void
 * @returns {Function} The previous reporter
 */
function setFieldReporter(reporter) {
    const previous = defaultReporter;
    defaultReporter = reporter;
    return previous;
}

module.exports = {
    REMOVAL_DATE,
    DEPRECATED_FIELDS,
    createFieldReporter,
    deprecatedField,
    setFieldReporter,
    SUNSET_HTTP_DATE,
    TOKEN_ROUTES_DEPRECATED_AT,
    BULL_BOARD_REDIRECTS_DEPRECATED_AT,
    LOG_INTERVAL,
    deprecationHeaders,
    deprecationExt,
    legacySmtpOptionsInUse
};
