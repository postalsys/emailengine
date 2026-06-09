'use strict';

const Boom = require('@hapi/boom');

// Shared helpers for the extracted API route modules under lib/api-routes/.

// Standard API error handler. Logs the failure, passes Boom errors through unchanged, and converts
// plain errors into a Boom error while preserving the original statusCode and an optional
// machine-readable err.code. This function ALWAYS throws and never returns a value, so callers use it
// as the final statement inside a catch block: `catch (err) { handleError(request, err); }`.
function handleError(request, err) {
    request.logger.error({ msg: 'API request failed', err });
    if (Boom.isBoom(err)) {
        throw err;
    }
    // Lower-level libraries (e.g. ImapFlow) flag "this server lacks the required capability" with a
    // machine code but no HTTP status. Surface it as a 422 client error instead of a generic 500 - the
    // request is well-formed, the account just cannot satisfy it (e.g. label search on non-Gmail IMAP).
    let statusCode = err.statusCode || (err.code === 'MissingServerExtension' ? 422 : 500);
    const error = Boom.boomify(err, { statusCode });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
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

module.exports = { handleError, flattenOAuthAppMeta };
