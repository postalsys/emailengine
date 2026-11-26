'use strict';

// The constants lib/logger.js needs, in a module that requires nothing. lib/consts.js reads its
// own environment variables through lib/read-env-value.js, which logs through lib/logger.js, so a
// logger that required lib/consts.js was a require cycle, and read-env-value had to defer every
// log line by a tick to get around it. lib/consts.js re-exports both, so other callers are unchanged.

// Transient network error codes that indicate a retry-worthy connection failure
const TRANSIENT_NETWORK_CODES = new Set([
    'ENOTFOUND',
    'EAI_AGAIN',
    'ETIMEDOUT',
    'ECONNRESET',
    'ECONNREFUSED',
    // no route to the host, such as an IPv6 address on a host without IPv6 connectivity
    'ENETUNREACH',
    'EHOSTUNREACH',
    'UND_ERR_SOCKET',
    'UND_ERR_CONNECT_TIMEOUT',
    'UND_ERR_HEADERS_TIMEOUT',
    // a response body that stalled mid-transfer
    'UND_ERR_BODY_TIMEOUT'
]);

// Applied by lib/logger.js to the root logger, so every worker inherits it. A logged joi
// ValidationError carries the full submitted payload in `_original` and the offending value in
// each detail context, and `rawPacket` is a TLS-error field that can carry an unparsed
// credential frame - without these a failed validation writes plaintext passwords, OAuth2
// client secrets and access tokens into the log, the per-account log store and Sentry.
// `req.query.access_token` is here because the api-token scheme accepts the credential as a
// query argument, and the request logger (lib/hapi-request-logger.js) logs the parsed query
// object with every request - so a client using that form wrote a live token into this
// instance's own request log. The serialized `req.url` is the pathname only
// (pino-std-serializers reports `req.path`), so the credential reaches the log through the
// query object and nowhere else.
const REDACTED_LOG_KEYS = [
    'req.headers.authorization',
    'req.headers.cookie',
    'req.query.access_token',
    'err.rawPacket',
    'err._original',
    'err.details[*].context.value',
    // the WHATWG URL parser attaches the string it rejected, and a stored proxy or webhook URL
    // carries its credentials inline
    'err.input'
];

// An RFC 9110 field name (token). Anything else, such as an entry written as "Name: value", is
// refused rather than turned into a redaction path that never matches.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;

/**
 * Turns the EENGINE_LOG_REDACT_HEADERS value into redaction paths for the request headers it lists.
 * Node lowercases incoming header names, so the names are matched lowercase.
 *
 * @param {string} [value] - Comma-separated header names
 * @returns {string[]} pino redaction paths, one per distinct name
 * @throws {Error} code `EnvValueInvalid` for an entry that is not a header name. The message names
 *   the position of the entry, never its text: an entry written as "Name: value" carries the very
 *   secret the variable exists to keep out of the log.
 */
function parseRedactHeaders(value) {
    const names = new Set();
    const entries = (value || '').split(',').map(entry => entry.trim().toLowerCase());
    entries.forEach((name, i) => {
        if (!name) {
            return;
        }
        if (!HEADER_NAME.test(name)) {
            const error = new Error(`EENGINE_LOG_REDACT_HEADERS: entry ${i + 1} is not a valid header name`);
            error.code = 'EnvValueInvalid';
            throw error;
        }
        names.add(name);
    });
    return [...names].map(name => `req.headers["${name}"]`);
}

// Read from process.env directly, not through readEnvValue(), because that helper logs through
// lib/logger.js, which loads this module. The main process resolves the _FILE form into
// process.env before anything loads the logger (see resolveEnvFiles()), and worker threads inherit it.
REDACTED_LOG_KEYS.push(...parseRedactHeaders(process.env.EENGINE_LOG_REDACT_HEADERS));

module.exports = { REDACTED_LOG_KEYS, TRANSIENT_NETWORK_CODES, parseRedactHeaders };
