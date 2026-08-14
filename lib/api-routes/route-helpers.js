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

module.exports = { handleError, logApiError, throwNotFound, flattenOAuthAppMeta };
