'use strict';

// Builds the OpenAPI 3.0 document from the Hapi route table.
//
// This is the route-walking half of what hapi-swagger used to do (see lib/openapi/joi-schema.js for
// the schema half). It is a pure function of the route table plus the document-level options in
// lib/swagger-options.js, so the same document can be produced inside a test without a listening
// server - test/fixtures/openapi-golden.json is recorded that way.
//
// What each route contributes:
//   description          -> summary            (the one-line title)
//   notes                -> description        (paragraphs, joined with <br/><br/>)
//   tags                 -> tags               (minus the internal `api` marker used to select routes)
//   validate.params      -> path parameters
//   validate.query       -> query parameters
//   validate.headers     -> header parameters
//   validate.payload     -> requestBody
//   response.schema      -> the 200 response body
//   plugins.openapi.responses  -> the documented status codes (see apiResponses in lib/schemas.js)
//   plugins.openapi.produces   -> the media type for routes that do not return JSON
//   plugins.openapi.deprecated -> the operation's deprecated marker (compatibility alias routes)
//   plugins.openapi['x-*']     -> vendor extensions on the operation, notably x-ee-behavior

const { STATUS_CODES } = require('node:http');

const Joi = require('joi');

const { SchemaConverter, deleteEmptyProperties } = require('./joi-schema');
const { pluginOptions } = require('../api-routes/route-metadata');
const { routeGrant } = require('../api-routes/permission-map');

// Routes opt into the document by carrying this tag. It is an internal marker rather than a
// documentation tag, so it is filtered back out of the published tag list.
const API_ROUTE_TAG = 'api';

const DEFAULT_MEDIA_TYPE = 'application/json';

// Operations of one path are documented in the order a reader expects to meet them
const METHOD_ORDER = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

// hapi-swagger joined a route's `notes` array with this separator, and lib/api-reference/model.js
// splits the description back on it to separate behavior notes from the operation's own prose.
const NOTES_SEPARATOR = '<br/><br/>';

const OPENAPI_VERSION = '3.0.0';

/**
 * Operation id for a route, e.g. GET /v1/account/{account} -> getV1AccountAccount.
 *
 * Generated client libraries turn these into method names, so the algorithm is fixed by
 * compatibility rather than taste: every path segment is stripped of non-word characters and
 * title-cased, then appended to the lowercased method.
 */
function operationId(method, path) {
    const titleCase = word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();

    return (
        method.toLowerCase() +
        path
            .split('/')
            .map(segment => titleCase(segment.replace(/[^\w\s]/gi, '')))
            .join('')
    );
}

function statusText(code) {
    // "OK" reads oddly as a response description next to "Bad Request", and this is the wording the
    // published document has always used
    return (STATUS_CODES[code] || 'Successful').replace('OK', 'Successful');
}

// Copies x-* keys onto the target. Anything a route declares under a vendor extension is published
// verbatim, which is how x-ee-behavior reaches the API reference.
function assignVendorExtensions(target, source) {
    for (const key of Object.keys(source)) {
        if (key.startsWith('x-') && key.length > 2) {
            target[key] = source[key];
        }
    }
}

class DocumentBuilder {
    constructor() {
        this.converter = new SchemaConverter();
    }

    /**
     * Turns one Hapi route into an OpenAPI Operation Object.
     *
     * @param {Object} route - an entry from server.table()
     * @returns {Object} { path, method, operation }
     */
    buildOperation(route) {
        const settings = route.settings;
        const options = pluginOptions(route);
        const validate = settings.validate || {};

        // Non-JSON routes (raw message source, gzip export, event streams) declare the media type
        // their success response carries
        const produces = options.produces || [DEFAULT_MEDIA_TYPE];

        // Assembled in one literal because the key order is what gets published, and a document that
        // reorders itself between builds is a diff for everyone tracking the hosted copy
        const operation = {
            summary: settings.description,
            operationId: operationId(route.method, route.path),
            description: Array.isArray(settings.notes) ? settings.notes.join(NOTES_SEPARATOR) : settings.notes,
            parameters: [
                ...this.buildParameters(validate.headers, 'header', route.path),
                ...this.buildParameters(validate.params, 'path', route.path),
                ...this.buildParameters(validate.query, 'query', route.path)
            ],
            tags: (settings.tags || []).filter(tag => tag !== API_ROUTE_TAG)
        };

        // Alias routes kept for compatibility declare `plugins.openapi.deprecated` so generated
        // clients and reference renderers steer readers to the current path
        if (options.deprecated) {
            operation.deprecated = true;
        }

        if (validate.payload) {
            const schema = this.converter.convert(validate.payload);
            if (schema && Object.keys(schema).length) {
                operation.requestBody = { content: { [DEFAULT_MEDIA_TYPE]: { schema } } };
            }
        }

        operation.responses = this.buildResponses(options.responses, settings.response && settings.response.schema, produces);

        assignVendorExtensions(operation, options);

        // What a narrowed access token needs to call this operation. Published so a customer can
        // read the requirement off the document instead of inferring it, and so anything deriving a
        // tool list from /swagger.json (an MCP layer, say) gets the permission with it rather than
        // hardcoding a second copy.
        //
        // Derived rather than declared, so it cannot disagree with what the auth strategy enforces -
        // both call routeGrant(). An unresolved half is null, which deleteEmptyProperties drops
        // below; that only happens when the route table and permission-map.js have diverged, which
        // test/api-routes-table-test.js fails on.
        const grant = routeGrant(route);
        operation['x-ee-action'] = grant.action;
        operation['x-ee-group'] = grant.group;

        return { path: route.path, method: route.method.toLowerCase(), operation: deleteEmptyProperties(operation) };
    }

    /**
     * Converts one of the request-side joi objects into Parameter Objects.
     *
     * Parameter schemas are inlined rather than referenced: a $ref in a parameter hides the type from
     * a reader scanning the operation, and these schemas are small.
     */
    buildParameters(schema, location, path) {
        if (!schema) {
            return [];
        }

        const converted = this.converter.convert(schema, { parameterType: location, useDefinitions: false });
        if (!converted || !converted.properties) {
            return [];
        }

        const required = converted.required || [];

        return Object.keys(converted.properties).map(name => {
            const propertySchema = converted.properties[name];

            const parameter = { name, in: location, schema: propertySchema };

            // Repeated on the parameter itself: tooling shows the parameter-level description, while
            // the schema-level one survives in generated models
            if (propertySchema.description) {
                parameter.description = propertySchema.description;
            }

            if (propertySchema.type === 'array') {
                parameter.style = 'form';
                parameter.explode = true;
            }

            // A path parameter is required by definition unless the path itself marks it optional
            if (required.includes(name) || (location === 'path' && path.includes(`{${name}}`))) {
                parameter.required = true;
            }

            return parameter;
        });
    }

    /**
     * Builds the Responses Object: the success case discovered from the route's response schema,
     * merged with the status codes the route documents explicitly.
     */
    buildResponses(documented, responseSchema, produces) {
        const responses = {};

        if (responseSchema) {
            responses[200] = this.buildResponse(200, responseSchema);
        }

        for (const code of Object.keys(documented || {})) {
            const entry = documented[code];

            let response;
            if (Joi.isSchema(entry.schema)) {
                response = this.buildResponse(code, entry.schema);
                // The route says what this status means for this operation; the schema's own
                // description is the generic name of the error shape
                response.description = entry.description;
            } else {
                response = Object.assign({}, entry);
                if (!response.description) {
                    response.description = statusText(code);
                }
            }

            responses[code] = Object.assign(responses[code] || {}, response);
            deleteEmptyProperties(responses[code]);
        }

        // A 2xx with no schema still has a body - a stream, a raw message, an archive - and a
        // response with no content at all reads as "returns nothing"
        if (responses[200] && responses[200].schema === undefined) {
            responses[200].schema = { type: 'string' };
        }

        return Object.fromEntries(
            Object.entries(responses).map(([code, response]) => {
                const { schema, ...rest } = response;

                if (!schema) {
                    return [code, rest];
                }

                // `produces` describes what the operation returns when it succeeds. Failures are
                // always the JSON error envelope, whatever the success body is.
                const mediaTypes = Number(code) < 300 ? produces : [DEFAULT_MEDIA_TYPE];

                return [code, Object.assign(rest, { content: Object.fromEntries(mediaTypes.map(mediaType => [mediaType, { schema }])) })];
            })
        );
    }

    buildResponse(code, schema) {
        // Described once and passed on, rather than letting convert() describe the same schema again
        const description = this.converter.describe(schema);

        const response = {
            description: description.flags && description.flags.description,
            schema: this.converter.convert(description)
        };

        deleteEmptyProperties(response);

        if (!response.description) {
            response.description = statusText(code);
        }

        return response;
    }
}

// Hapi's route table comes back grouped by HTTP method in the order each method was first registered
// anywhere on the server, which makes the emitted order a property of the whole registration sequence
// rather than of the routes themselves. That is mostly cosmetic, but not entirely: schemas are named
// from their joi label, and where two different shapes share a label the numeric suffix that
// separates them (`AddressList1`) follows first-seen order. Sorting here makes the document a
// function of the route set alone, so the same routes always produce the same document - which is
// also what lets test/fixtures/openapi-golden.json guard the document the server actually serves.
function sortRoutes(routes) {
    return [...routes].sort(
        (a, b) => a.path.localeCompare(b.path) || METHOD_ORDER.indexOf(a.method.toLowerCase()) - METHOD_ORDER.indexOf(b.method.toLowerCase())
    );
}

/**
 * Builds the OpenAPI document.
 *
 * @param {Array} routes - the Hapi route table (server.table()), unfiltered
 * @param {Object} options - document-level options, see lib/swagger-options.js
 * @param {Object} options.info - the Info Object; title and version are required
 * @param {Array} [options.servers] - Server Objects; omitted from the document when not given
 * @returns {Object} the OpenAPI document
 */
function buildOpenApiDocument(routes, options) {
    const builder = new DocumentBuilder();

    const paths = {};

    for (const route of sortRoutes(routes.filter(route => (route.settings.tags || []).includes(API_ROUTE_TAG)))) {
        const { path, method, operation } = builder.buildOperation(route);

        if (!paths[path]) {
            paths[path] = {};
        }

        paths[path][method] = operation;
    }

    const document = {
        externalDocs: options.externalDocs,
        security: options.security,
        tags: options.tags || []
    };

    // Document-level vendor extensions (x-logo and anything added later) sit with the metadata they
    // extend, before the generated sections
    assignVendorExtensions(document, options);

    // title and version first: they are the two fields OpenAPI requires, and every other info field
    // is prose that follows them
    document.info = Object.assign({ title: 'API documentation', version: '0.0.1' }, options.info);

    document.openapi = OPENAPI_VERSION;

    if (options.servers) {
        document.servers = options.servers;
    }

    document.components = {};
    if (options.securityDefinitions) {
        document.components.securitySchemes = options.securityDefinitions;
    }
    document.components.schemas = builder.converter.definitions;

    document.paths = paths;

    return deleteEmptyProperties(document);
}

module.exports = { buildOpenApiDocument, operationId, API_ROUTE_TAG, NOTES_SEPARATOR };
