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

module.exports = { REDACTED_LOG_KEYS, TRANSIENT_NETWORK_CODES };
