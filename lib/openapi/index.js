'use strict';

// Serves the generated OpenAPI document at /swagger.json.
//
// The endpoint is deliberately unauthenticated, as it has been since it was served by hapi-swagger:
// it is a published product surface (the README points at it, emailengine.dev mirrors it, Postman
// and code generators consume it), and it describes the shape of the API rather than exposing any
// instance data. The API reference at /admin/reference reads it back through server.inject(), which
// also depends on it not requiring a session.

const { buildOpenApiDocument, NOTES_SEPARATOR } = require('./build-document');
const { SCHEMA_REF_PREFIX } = require('./joi-schema');

const JSON_PATH = '/swagger.json';

// Stands in for the real address while the document body is built, so `servers` already has its
// place in the key order and the per-request value can be dropped in without rebuilding anything
const PLACEHOLDER_SERVERS = [{ url: '' }];

function firstHeaderValue(request, name) {
    const value = request.headers[name];
    return value ? value.split(',')[0].trim() : undefined;
}

/**
 * The base address to publish as the API's server.
 *
 * Derived from the request rather than from configuration, so an instance reachable under several
 * names describes itself correctly to whoever asked. Forwarded headers win, because behind a reverse
 * proxy they are the only source of the address the client actually used.
 *
 * Those headers are attacker-controlled on a directly reachable port, so two things keep that
 * harmless: the value is computed per request and never cached, so it can only ever appear in the
 * response to the client that sent the header; and it is parsed as a URL, so a malformed header
 * falls back to the request's own address instead of being pasted into the document.
 */
function serverUrl(request) {
    const forwarded = (firstHeaderValue(request, 'x-forwarded-proto') || '').toLowerCase();

    // Only the two schemes this server speaks. Without the check the header is not just a scheme but
    // the front of the URL, so `https://elsewhere/#` would compose into an origin of its own.
    const protocol = ['http', 'https'].includes(forwarded) ? forwarded : (request.url.protocol || 'http:').replace(/:$/, '');
    const host = firstHeaderValue(request, 'x-forwarded-host') || request.headers['disguised-host'] || request.info.host;

    try {
        return new URL(`${protocol}://${host}`).origin;
    } catch (err) {
        return `http://${request.info.host}`;
    }
}

/**
 * Registers the OpenAPI document route.
 *
 * Can be registered at any point: the document is built from server.table() on first request, not
 * here, so it sees every route however late it was added, and the builder sorts the table itself so
 * the result does not depend on registration order.
 *
 * @param {Object} server - the Hapi server
 * @param {Object} options - document-level options, see lib/swagger-options.js
 */
function registerOpenApiRoute(server, options) {
    // Built once and then held for the life of the worker - route definitions cannot change while it
    // is running, so there is nothing to invalidate
    let document;
    let builtAt;

    const getDocument = () => {
        if (!document) {
            document = buildOpenApiDocument(server.table(), Object.assign({}, options, { servers: PLACEHOLDER_SERVERS }));
            builtAt = new Date();
        }

        return document;
    };

    server.route({
        method: 'GET',
        path: JSON_PATH,
        options: {
            auth: false,
            cors: options.cors,
            // A machine-facing document: JSON errors, no CSRF check, the API response headers.
            // Not `api`, which would list this route in the document it serves
            tags: ['external'],

            handler(request, h) {
                // Shallow copy: `servers` already exists in the built document, so replacing it here
                // keeps its position in the key order and leaves the rest untouched
                const spec = Object.assign({}, getDocument(), { servers: [{ url: serverUrl(request) }] });

                return h.response(spec).header('last-modified', builtAt.toUTCString());
            }
        }
    });
}

// serverUrl is shared with the MCP config page, which needs the same "address the client
// actually used" answer for its connection snippets when no serviceUrl is configured
module.exports = { registerOpenApiRoute, buildOpenApiDocument, serverUrl, JSON_PATH, NOTES_SEPARATOR, SCHEMA_REF_PREFIX };
