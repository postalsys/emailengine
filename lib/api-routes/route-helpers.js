'use strict';

const Boom = require('@hapi/boom');

// Shared helpers for the extracted API route modules under lib/api-routes/.

// Derives the failure's HTTP status and logs it under the shared level policy. Kept separate from
// handleError for the few catch blocks that need a custom response shape but must not fork the
// logging policy. Unlike handleError this only logs: it RETURNS the derived statusCode instead of
// throwing, so a caller that uses it must still produce a response of its own.
function logApiError(request, err) {
    // Lower-level libraries (e.g. ImapFlow) flag "this server lacks the required capability" with a
    // machine code but no HTTP status. Surface it as a 422 client error instead of a generic 500 - the
    // request is well-formed, the account just cannot satisfy it (e.g. label search on non-Gmail IMAP).
    let statusCode = Boom.isBoom(err) ? err.output.statusCode : err.statusCode || (err.code === 'MissingServerExtension' ? 422 : 500);

    // Log expected client errors (4xx, e.g. a 404 from an existence-check probe) at warn so they do not
    // flood the error stream, while genuine server faults (5xx) stay at error.
    let logLevel = statusCode >= 400 && statusCode < 500 ? 'warn' : 'error';
    request.logger[logLevel]({ msg: 'API request failed', statusCode, err });
    return statusCode;
}

// Standard API error handler. Logs the failure, passes Boom errors through unchanged, and converts
// plain errors into a Boom error while preserving the original statusCode and an optional
// machine-readable err.code. This function ALWAYS throws and never returns a value, so callers use it
// as the final statement inside a catch block: `catch (err) { handleError(request, err); }`.
function handleError(request, err) {
    let statusCode = logApiError(request, err);

    if (Boom.isBoom(err)) {
        throw err;
    }
    const error = Boom.boomify(err, { statusCode });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    if (err.details) {
        error.output.payload.details = err.details;
    }
    if (err.info) {
        error.output.payload.info = err.info;
    }
    throw error;
}

// Throws the canonical 404 error used when an entity getter returns a falsy value. Matches the
// error shape that the lib-level update() methods (templates, webhooks, oauth2-apps) already throw
// for missing documents, so API clients see the same error for both code paths.
function throwNotFound(message = 'Document was not found') {
    let err = new Error(message);
    err.code = 'NotFound';
    err.statusCode = 404;
    throw err;
}

// Strips the internal `meta` field from an OAuth2 application object before returning it to the API
// client, surfacing any authentication or Pub/Sub error messages as `lastError`/`pubSubError`.
// Pure function: it mutates the passed object and closes over no module state.
function flattenOAuthAppMeta(app) {
    if (!app.meta) {
        return;
    }
    let authFlag = app.meta.authFlag;
    let pubSubFlag = app.meta.pubSubFlag;
    delete app.meta;
    if (authFlag && authFlag.message) {
        app.lastError = { response: authFlag.message };
    }
    if (pubSubFlag && pubSubFlag.message) {
        app.pubSubError = { message: pubSubFlag.message, description: pubSubFlag.description || null };
    }
}

// What a masked secret reads as in an API response. Same marker the account, gateway and OAuth2-app
// getters already use for stored passwords, so a client sees one convention.
const MASKED = '******';

// One sentence for every endpoint that returns a masked entity, so the document says what a reader
// will actually get back. The convention predates this - the gateway getter already documented its
// masked password - but the wording lived in each route.
const MASK_NOTE =
    'Credentials are masked: stored passwords, the password in any proxy or webhook URL, and the values of custom webhook headers all read back as "%s".'.replace(
        '%s',
        MASKED
    );

// Masks the VALUES of a custom-header list, keeping the keys.
//
// These carry credentials for someone else's system - the documented example is
// `Authorization: Bearer <token>` - and they were returned in full by the account and webhook-route
// getters while the passwords next to them were masked. Reading one back is enough to post forged,
// correctly authenticated webhooks into the customer's receiver.
//
// The keys stay visible because they carry no secret and are what makes the response useful: a
// reader can see THAT an Authorization header is configured without being handed its value.
function maskCustomHeaders(headers) {
    if (!Array.isArray(headers)) {
        return headers;
    }

    // A header with no value has no secret to hide, and masking it would advertise one that is not
    // there - the schema defaults `value` to an empty string, so this is a real stored shape.
    return headers.map(header => (header && typeof header === 'object' && header.value ? Object.assign({}, header, { value: MASKED }) : header));
}

// Masks the password in a URL, keeping everything that identifies where it points.
//
// Several stored URLs accept inline credentials - `proxyUrl` as `socks5://user:pass@host:1080`, and
// webhook targets as `https://user:pass@receiver.example.com/hook` - so returning them verbatim
// published a working credential. Host, port and path stay: they are operational information a
// client legitimately reads back, and blanking them would break anything that displays the value.
//
// Distinct from redactUrlCredentials() in lib/tools.js, which serves the log stream: that one blanks
// the username too and may return a placeholder that is not a URL at all. This one has to come back
// schema-valid and still identify the destination, because it lands in an API response.
function maskUrlPassword(url) {
    if (!url || typeof url !== 'string') {
        return url;
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch (err) {
        // An unparseable value could itself be the credential that made it unparseable, so it is
        // replaced rather than echoed - the same call lib/tools.js makes for the log stream. Empty
        // rather than a placeholder because every schema here allows it, and a value that cannot be
        // parsed was never a usable destination anyway.
        return '';
    }

    // Gated on either half: commercial proxies commonly key on a token in the USERNAME with no
    // password at all, and lib/tools.js reads that shape (userId with an empty password).
    if (!parsed.username && !parsed.password) {
        return url;
    }

    parsed.password = MASKED;
    return parsed.href;
}

// Stored values that are URLs which may embed a password.
const URL_SECRET_KEYS = ['proxy', 'proxyUrl', 'httpProxyUrl', 'webhooks', 'targetUrl'];

// Stored values that are {key, value} header lists whose values are credentials.
const HEADER_SECRET_KEYS = ['customHeaders', 'webhooksCustomHeaders'];

// A failed submission records the route it took, including the proxy it used, and that record is
// then persisted onto the account, the gateway and the queue entry. So the same proxy URL reappears
// nested inside a status or error object, one field over from where it was masked.
function maskNetworkRouting(container) {
    if (!container || typeof container !== 'object') {
        return;
    }

    if (container.networkRouting && typeof container.networkRouting === 'object' && container.networkRouting.proxy) {
        container.networkRouting.proxy = maskUrlPassword(container.networkRouting.proxy);
    }
}

/**
 * Masks every credential-bearing field of an entity about to be returned from the API.
 *
 * One function rather than a mask call per field per handler, because the leak this closes was
 * exactly the failure mode of doing it per field: `proxy` was masked in the account getter while the
 * same URL came back through `smtpStatus.networkRouting.proxy` in the same response body, and
 * `customHeaders` was masked in the webhook getter while `targetUrl` beside it carried basic auth.
 * With the field set in one place, a newly added handler gets all of them and a newly added secret
 * field reaches every handler at once.
 *
 * Containers are enumerated rather than walked recursively on purpose: an outbox entry carries the
 * submitted message, and a recursive scan would read through mail content to find nothing.
 *
 * Mutates and returns the entity. Safe because every caller passes a per-request object it just
 * deserialized from Redis or built from a queue job, never shared state.
 *
 * @param {Object} entry - the entity about to be serialized into a response
 * @returns {Object} the same object, with credentials masked
 */
function maskSecrets(entry) {
    if (!entry || typeof entry !== 'object') {
        return entry;
    }

    for (const key of URL_SECRET_KEYS) {
        if (entry[key]) {
            entry[key] = maskUrlPassword(entry[key]);
        }
    }

    for (const key of HEADER_SECRET_KEYS) {
        if (entry[key]) {
            entry[key] = maskCustomHeaders(entry[key]);
        }
    }

    // smtpStatus on an account, lastError on an account or a gateway, progress.error on a queue entry
    for (const container of ['smtpStatus', 'lastError', 'error', 'progress']) {
        maskNetworkRouting(entry[container]);
        if (entry[container] && typeof entry[container] === 'object') {
            maskNetworkRouting(entry[container].error);
        }
    }

    return entry;
}

module.exports = {
    handleError,
    logApiError,
    throwNotFound,
    flattenOAuthAppMeta,
    maskCustomHeaders,
    maskUrlPassword,
    maskSecrets,
    MASKED,
    MASK_NOTE
};
