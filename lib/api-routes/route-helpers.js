'use strict';

const Boom = require('@hapi/boom');
const { isDeepStrictEqual } = require('node:util');
const tokenPermissions = require('../token-permissions');

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
    'Credentials are masked: stored passwords, the credentials in any proxy or webhook URL, and the values of custom webhook headers all read back as "%s". A masked value is not the stored one - leave the field out of an update rather than writing it back, otherwise the mask replaces the credential.'.replace(
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

// Masks the credentials in a URL, keeping everything that identifies where it points.
//
// Several stored URLs accept inline credentials - `proxyUrl` as `socks5://user:pass@host:1080`, and
// webhook targets as `https://user:pass@receiver.example.com/hook` - so returning them verbatim
// published a working credential. Host, port and path stay: they are operational information a
// client legitimately reads back, and blanking them would break anything that displays the value.
//
// Distinct from redactUrlCredentials() in lib/tools.js, which serves the log stream: that one may
// return a placeholder that is not a URL at all. This one has to come back schema-valid and still
// identify the destination, because it lands in an API response - which is also why it replaces the
// credentials in place rather than dropping the userinfo section.
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

    // Each half is masked only where there is one. Rewriting only the password published the
    // username in full, which for the shape above IS the credential - and writing a password into a
    // URL that never had one reports a secret that does not exist, showing the account as more
    // configured than it is.
    if (parsed.username) {
        parsed.username = MASKED;
    }

    if (parsed.password) {
        parsed.password = MASKED;
    }

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

    // smtpStatus on an account, lastError on a gateway, progress.error on a queue entry.
    //
    // `lastErrorState` is the account's, and it is a separate entry rather than a rename because the
    // two really are different keys: Account.unserializeAccountData() parses the connection error
    // under `lastErrorState`, and the getter only renames it to `lastError` on the way out, well
    // after this runs. Masking one name and not the other left the account getter publishing the
    // proxy URL of the failed connection while the reviewer read a mask call that looked like it
    // covered it.
    for (const container of ['smtpStatus', 'lastError', 'lastErrorState', 'error', 'progress']) {
        maskNetworkRouting(entry[container]);
        if (entry[container] && typeof entry[container] === 'object') {
            maskNetworkRouting(entry[container].error);
        }
    }

    return entry;
}

// Compares header lists on the two fields a client round-trips, so an echo check is not thrown
// off by incidental extra properties on either side
function normalizedHeaderList(headers) {
    return [].concat(headers || []).map(header => ({ key: (header && header.key) || '', value: (header && header.value) || '' }));
}

/**
 * Whether an incoming value carries the mask maskSecrets() writes into responses where a
 * credential should be.
 *
 * A write-side guard for the masking convention: a masked value passes the joi schemas (it is a
 * well-formed URL / header list), so without this check a read-modify-write client silently
 * replaces the stored credential with the literal mask. Keys outside the two secret lists are
 * never masked on the way out, so they report false.
 *
 * Currently wired into POST /v1/settings only. The account and gateway update routes share the
 * read-side masking but still follow the documented MASK_NOTE contract on writes ("leave the
 * field out of an update rather than writing it back") - closing them the same way is an open
 * follow-up, and needs a shape this helper does not cover yet (the gateway password is a bare
 * masked string, not a URL or header list).
 *
 * @param {String} key - the setting/field name
 * @param {*} value - the incoming value
 * @returns {Boolean} true when the value carries the mask placeholder
 */
function containsMaskedSecret(key, value) {
    if (URL_SECRET_KEYS.includes(key)) {
        if (!value || typeof value !== 'string') {
            return false;
        }
        let parsed;
        try {
            parsed = new URL(value);
        } catch (err) {
            return false;
        }
        return parsed.username === MASKED || parsed.password === MASKED;
    }

    if (HEADER_SECRET_KEYS.includes(key)) {
        return Array.isArray(value) && value.some(header => header && typeof header === 'object' && header.value === MASKED);
    }

    return false;
}

/**
 * Whether an incoming masked value is exactly what a read of the stored value returns - i.e. a
 * read-modify-write client posting back what GET handed it, with this key untouched. Such an echo
 * is not an update at all, so the caller can skip the write instead of refusing it.
 *
 * @param {String} key - the setting/field name
 * @param {*} incoming - the incoming value
 * @param {*} stored - the currently stored value
 * @returns {Boolean} true when the incoming value is the masked echo of the stored one
 */
function isMaskedRoundTrip(key, incoming, stored) {
    if (URL_SECRET_KEYS.includes(key)) {
        return !!stored && typeof incoming === 'string' && maskUrlPassword(stored) === incoming;
    }

    if (HEADER_SECRET_KEYS.includes(key)) {
        return Array.isArray(incoming) && isDeepStrictEqual(normalizedHeaderList(maskCustomHeaders(stored)), normalizedHeaderList(incoming));
    }

    return false;
}

/**
 * Refuses a submission that redirects the connection, when the credential making it is narrowed.
 *
 * `proxy` in a submit payload overrides the account's own route and the instance-wide one
 * (applyProxyConfig in lib/email-client/message-builder.js takes the payload first), and the SMTP
 * session it redirects still carries the account's decrypted username and password. A SOCKS
 * endpoint therefore decides where the connection lands, can answer as the mail server, and - with
 * no STARTTLS advertised and nothing requiring it - collects AUTH in plaintext. So the field turns
 * "may send mail" into "may read the credential that sends the mail".
 *
 * That is the same reasoning that put the gateway writes in the never-grantable `admin` group:
 * reading a stored credential back is masked, sending it somewhere is not. It applies here because
 * `submit` is a grantable group, so the narrowing has to hold the line the route grant cannot.
 *
 * Only for narrowed tokens. An unnarrowed one already reaches PUT /v1/account/{account} and can
 * point the account's own proxy wherever it likes, so refusing it here would cost a documented
 * capability and buy nothing.
 *
 * The refusal is not written to the per-token audit log, deliberately. That trail records what a
 * credential was ADMITTED to attempt - it is written by the auth strategy, before payload validation
 * and the handler, so a 400 or a 404 does not appear in it either, and this is a handler-level
 * refusal of one field. It does reach the application log: handleError() logs the 403 through
 * `request.logger`, which the strategy has already bound the token id to.
 *
 * @param {Object} request - the Hapi request
 */
function assertNoNetworkOverride(request) {
    if (!request.payload || !request.payload.proxy) {
        return;
    }

    // Asked of the module that enforces the narrowing rather than by testing `permissions` for
    // truthiness, so `{}` and an unreadable record are read here exactly as they are at the
    // strategy. `artifacts` is the token record the api-token strategy resolved.
    if (!tokenPermissions.inspect(request.auth && request.auth.artifacts).narrowed) {
        return;
    }

    throw Boom.forbidden('A token with restricted permissions can not override the connection route');
}

module.exports = {
    handleError,
    logApiError,
    throwNotFound,
    flattenOAuthAppMeta,
    maskCustomHeaders,
    maskUrlPassword,
    maskSecrets,
    containsMaskedSecret,
    isMaskedRoundTrip,
    assertNoNetworkOverride,
    MASKED,
    MASK_NOTE
};
