'use strict';

// Unit tests for the OpenAPI generator (lib/openapi/).
//
// These use hand-written joi schemas and a bare Hapi server, so they say what the converter does
// with one construct at a time. The complementary tests are test/openapi-golden-test.js, which
// checks the whole real document against a recorded copy, and test/api-reference-test.js, which
// checks that the document renders.
//
// Deliberately free of lib/db and lib/schemas, so this file needs neither Redis nor a teardown hook.

const { test, describe } = require('node:test');
const assert = require('node:assert').strict;

const Joi = require('joi');
const Hapi = require('@hapi/hapi');

const { SchemaConverter } = require('../lib/openapi/joi-schema');
const { buildOpenApiDocument, operationId } = require('../lib/openapi/build-document');
const { registerOpenApiRoute, JSON_PATH } = require('../lib/openapi');

// Converts one schema in isolation and hands back both the result and anything it registered
function convert(schema, context) {
    const converter = new SchemaConverter();
    const result = converter.convert(schema, Object.assign({ useDefinitions: false }, context));

    return { result, definitions: converter.definitions };
}

describe('joi to OpenAPI schema conversion', () => {
    test('maps the scalar types', () => {
        const { result } = convert(
            Joi.object({
                text: Joi.string(),
                count: Joi.number(),
                whole: Joi.number().integer(),
                flag: Joi.boolean(),
                when: Joi.date(),
                stamp: Joi.date().iso(),
                anything: Joi.any()
            })
        );

        assert.deepEqual(result.properties.text, { type: 'string' });
        assert.deepEqual(result.properties.count, { type: 'number' });
        assert.deepEqual(result.properties.whole, { type: 'integer' });
        assert.deepEqual(result.properties.flag, { type: 'boolean' });
        // A joi date accepts a full timestamp whether or not .iso() is used, so both are date-time.
        // OpenAPI's `date` means a bare YYYY-MM-DD, which is not what any of these accept.
        assert.deepEqual(result.properties.when, { type: 'string', format: 'date-time' });
        assert.deepEqual(result.properties.stamp, { type: 'string', format: 'date-time' });
        assert.deepEqual(result.properties.anything, { type: 'string' });
    });

    test('carries documentation across', () => {
        const { result } = convert(
            Joi.object({
                name: Joi.string().description('Account name').example('example').default('unnamed')
            })
        );

        assert.deepEqual(result.properties.name, {
            type: 'string',
            description: 'Account name',
            example: 'example',
            default: 'unnamed'
        });
    });

    test('maps length and range rules to their OpenAPI keywords', () => {
        const { result } = convert(
            Joi.object({
                text: Joi.string().min(2).max(10),
                count: Joi.number().min(1).max(5),
                list: Joi.array().items(Joi.string()).min(1).max(3)
            })
        );

        assert.equal(result.properties.text.minLength, 2);
        assert.equal(result.properties.text.maxLength, 10);
        assert.equal(result.properties.count.minimum, 1);
        assert.equal(result.properties.count.maximum, 5);
        assert.equal(result.properties.list.minItems, 1);
        assert.equal(result.properties.list.maxItems, 3);
    });

    test('publishes joi rules that OpenAPI cannot express as x- extensions', () => {
        const { result } = convert(
            Joi.object({
                url: Joi.string().uri({ scheme: ['http', 'https'] }),
                mail: Joi.string().email(),
                code: Joi.string().trim().case('lower'),
                list: Joi.array().items(Joi.string()).single()
            })
        );

        assert.deepEqual(result.properties.url['x-format'].uri, { scheme: ['http', 'https'] });
        assert.equal(result.properties.mail['x-format'].email, true);
        assert.deepEqual(result.properties.code['x-convert'], { case: 'lower', trim: true });
        assert.deepEqual(result.properties.list['x-constraint'], { single: true });
    });

    test('emits a regex pattern without the delimiters joi describes it with', () => {
        const { result } = convert(Joi.object({ id: Joi.string().pattern(/^[a-f0-9]+$/i) }));

        assert.equal(result.properties.id.pattern, '^[a-f0-9]+$');
    });

    test('turns allowed values into an enum and a null into nullable', () => {
        const { result } = convert(
            Joi.object({
                state: Joi.string().valid('on', 'off'),
                note: Joi.string().allow(null),
                // An empty string is a joi idiom for "unset", not a documented value
                blank: Joi.string().allow('')
            })
        );

        assert.deepEqual(result.properties.state.enum, ['on', 'off']);
        assert.equal(result.properties.note.nullable, true);
        assert.equal(result.properties.blank.enum, undefined);
    });

    test('documents per-value enum descriptions through x-meta', () => {
        const { result } = convert(
            Joi.object({
                state: Joi.string()
                    .valid('on')
                    .meta({ enumDescriptions: { on: 'Switched on' } })
            })
        );

        assert.deepEqual(result.properties.state['x-meta'], { enumDescriptions: { on: 'Switched on' } });
    });

    test('collects required keys on the parent', () => {
        const { result } = convert(
            Joi.object({
                needed: Joi.string().required(),
                optional: Joi.string()
            })
        );

        assert.deepEqual(result.required, ['needed']);
    });

    test('treats a conditionally required key as required', () => {
        // OpenAPI cannot express the condition, and documenting the key as optional would be worse
        const { result } = convert(
            Joi.object({
                trigger: Joi.boolean(),
                dependent: Joi.string().when('trigger', { is: true, then: Joi.required() })
            })
        );

        assert.deepEqual(result.required, ['dependent']);
    });

    test('does not flatten a requirement that lives in the otherwise branch', () => {
        // Understating one field, on purpose. Reading both branches was tried: a flat `required`
        // array cannot hold two sides of an exclusive choice, so CreateOAuth2App ended up requiring
        // the 3-legged fields and the service-account fields at once - an array no request body can
        // satisfy, which is worse than the optional it replaced. Such a rule goes in the field's
        // description instead.
        const { result } = convert(
            Joi.object({
                trigger: Joi.boolean(),
                dependent: Joi.string().when('trigger', { is: true, then: Joi.optional(), otherwise: Joi.required() })
            })
        );

        assert.equal(result.required, undefined);
    });

    test('publishes the size rules of an object', () => {
        // `.min(1)` on an object is how "at least one of these" is said in joi. Without it the
        // document described `{}` as an acceptable token narrowing, which the API refuses.
        const { result } = convert(
            Joi.object({ axis: Joi.array().items(Joi.string()) })
                .min(1)
                .max(2)
        );

        assert.equal(result.minProperties, 1);
        assert.equal(result.maxProperties, 2);
    });

    test('omits hidden and forbidden keys', () => {
        const { result } = convert(
            Joi.object({
                visible: Joi.string(),
                internal: Joi.string().meta({ swaggerHidden: true }),
                banned: Joi.string().forbidden()
            })
        );

        assert.deepEqual(Object.keys(result.properties), ['visible']);
    });

    test('describes an array by its item type', () => {
        const { result } = convert(Joi.object({ list: Joi.array().items(Joi.string().max(4)) }));

        assert.deepEqual(result.properties.list, { type: 'array', items: { type: 'string', maxLength: 4 } });
    });

    test('offers every item type of a mixed array', () => {
        const { result } = convert(Joi.object({ list: Joi.array().items(Joi.string(), Joi.number()) }));

        assert.deepEqual(result.properties.list.items, { anyOf: [{ type: 'string' }, { type: 'number' }] });
    });

    test('turns alternatives into anyOf', () => {
        const { result } = convert(Joi.object({ either: Joi.alternatives().try(Joi.boolean(), Joi.string()) }));

        assert.deepEqual(result.properties.either.anyOf, [{ type: 'boolean' }, { type: 'string' }]);
        assert.equal(result.properties.either.type, undefined);
    });

    describe('named schemas', () => {
        test('a labelled schema is registered and referenced', () => {
            const { result, definitions } = convert(Joi.object({ id: Joi.string() }).label('Thing'), { useDefinitions: true });

            assert.deepEqual(result, { $ref: '#/components/schemas/Thing' });
            assert.deepEqual(definitions.Thing, { type: 'object', properties: { id: { type: 'string' } } });
        });

        test('identical schemas share one definition', () => {
            const converter = new SchemaConverter();
            const shape = () => Joi.object({ id: Joi.string() }).label('Thing');

            const first = converter.convert(shape(), { useDefinitions: true });
            const second = converter.convert(shape(), { useDefinitions: true });

            assert.deepEqual(first, second);
            assert.deepEqual(Object.keys(converter.definitions), ['Thing']);
        });

        test('a label reused for a different shape gets a numbered sibling', () => {
            const converter = new SchemaConverter();

            converter.convert(Joi.object({ id: Joi.string() }).label('Thing'), { useDefinitions: true });
            const second = converter.convert(Joi.object({ name: Joi.string() }).label('Thing'), { useDefinitions: true });

            assert.deepEqual(second, { $ref: '#/components/schemas/Thing1' });
            assert.deepEqual(Object.keys(converter.definitions), ['Thing', 'Thing1']);
        });

        test('a labelled alternatives branch is a named schema like any other', () => {
            const { result, definitions } = convert(
                Joi.object({
                    either: Joi.alternatives().try(Joi.boolean(), Joi.object({ id: Joi.string() }).label('Branch'))
                }).label('Root'),
                { useDefinitions: true }
            );

            assert.deepEqual(result, { $ref: '#/components/schemas/Root' });
            assert.deepEqual(definitions.Root.properties.either.anyOf[1], { $ref: '#/components/schemas/Branch' });
            assert.equal(definitions.Branch.type, 'object');
        });
    });
});

describe('OpenAPI document building', () => {
    const noopHandler = () => ({});

    // Minimal stand-in for a Hapi route table entry
    function route(overrides) {
        return Object.assign(
            {
                method: 'get',
                path: '/v1/thing',
                settings: { tags: ['api'], handler: noopHandler }
            },
            overrides
        );
    }

    function build(routes, options) {
        return buildOpenApiDocument(routes, Object.assign({ info: { title: 'Test', version: '1.0.0' } }, options));
    }

    test('builds operation ids from the method and path', () => {
        assert.equal(operationId('GET', '/v1/account/{account}'), 'getV1AccountAccount');
        assert.equal(operationId('POST', '/v1/account/{account}/message/{message}/move'), 'postV1AccountAccountMessageMessageMove');
    });

    test('only documents routes tagged as api', () => {
        const document = build([route(), route({ path: '/admin/page', settings: { tags: ['web'], handler: noopHandler } })]);

        assert.deepEqual(Object.keys(document.paths), ['/v1/thing']);
    });

    test('drops the internal api tag from the published tag list', () => {
        const document = build([route({ settings: { tags: ['api', 'Account'], handler: noopHandler } })]);

        assert.deepEqual(document.paths['/v1/thing'].get.tags, ['Account']);
    });

    test('joins note paragraphs into the description', () => {
        const document = build([route({ settings: { tags: ['api'], description: 'Title', notes: ['First.', 'Second.'], handler: noopHandler } })]);

        const operation = document.paths['/v1/thing'].get;
        assert.equal(operation.summary, 'Title');
        assert.equal(operation.description, 'First.<br/><br/>Second.');
    });

    test('publishes vendor extensions declared by the route', () => {
        const document = build([
            route({
                settings: { tags: ['api'], plugins: { openapi: { 'x-ee-behavior': ['Runs in the background.'] } }, handler: noopHandler }
            })
        ]);

        assert.deepEqual(document.paths['/v1/thing'].get['x-ee-behavior'], ['Runs in the background.']);
    });

    test('describes path, query and header parameters', () => {
        const document = build([
            route({
                path: '/v1/thing/{id}',
                settings: {
                    tags: ['api'],
                    handler: noopHandler,
                    validate: {
                        params: Joi.object({ id: Joi.string().description('Thing id') }),
                        query: Joi.object({ page: Joi.number().integer().default(0) }),
                        headers: Joi.object({ 'x-ee-timeout': Joi.number() }).unknown()
                    }
                }
            })
        ]);

        const parameters = document.paths['/v1/thing/{id}'].get.parameters;

        assert.deepEqual(
            parameters.map(parameter => [parameter.name, parameter.in]),
            [
                ['x-ee-timeout', 'header'],
                ['id', 'path'],
                ['page', 'query']
            ]
        );

        // A parameter named by the path template is required whether or not joi says so
        assert.equal(parameters[1].required, true);
        assert.equal(parameters[1].description, 'Thing id');
        assert.equal(parameters[2].required, undefined);
    });

    test('describes the payload as a JSON request body', () => {
        const document = build([
            route({
                method: 'post',
                settings: {
                    tags: ['api'],
                    handler: noopHandler,
                    validate: { payload: Joi.object({ name: Joi.string() }).label('Payload') }
                }
            })
        ]);

        assert.deepEqual(document.paths['/v1/thing'].post.requestBody, {
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Payload' } } }
        });
    });

    test('merges the response schema with the documented status codes', () => {
        const document = build([
            route({
                settings: {
                    tags: ['api'],
                    handler: noopHandler,
                    response: { schema: Joi.object({ ok: Joi.boolean() }).label('Result') },
                    plugins: {
                        openapi: {
                            responses: {
                                200: { description: 'Returns the thing.' },
                                404: { description: 'Not found.', schema: Joi.object({ error: Joi.string() }).label('NotFound') }
                            }
                        }
                    }
                }
            })
        ]);

        const responses = document.paths['/v1/thing'].get.responses;

        assert.equal(responses['200'].description, 'Returns the thing.');
        assert.deepEqual(responses['200'].content['application/json'].schema, { $ref: '#/components/schemas/Result' });
        assert.equal(responses['404'].description, 'Not found.');
        assert.deepEqual(responses['404'].content['application/json'].schema, { $ref: '#/components/schemas/NotFound' });
    });

    test('uses the media type a route declares for every one of its responses', () => {
        const document = build([
            route({
                settings: {
                    tags: ['api'],
                    handler: noopHandler,
                    plugins: {
                        openapi: {
                            produces: ['text/event-stream'],
                            responses: { 200: { description: 'An open stream.' } }
                        }
                    }
                }
            })
        ]);

        // A streaming route has no joi response schema, but a 200 with no body at all would read as
        // "returns nothing"
        assert.deepEqual(document.paths['/v1/thing'].get.responses['200'].content, {
            'text/event-stream': { schema: { type: 'string' } }
        });
    });

    test('assembles the document metadata', () => {
        const document = build([route()], {
            tags: [{ name: 'Account', description: 'Accounts' }],
            securityDefinitions: { bearerAuth: { type: 'http', scheme: 'bearer' } },
            security: [{ bearerAuth: [] }],
            servers: [{ url: 'https://example.com' }]
        });

        assert.equal(document.openapi, '3.0.0');
        assert.deepEqual(document.info, { title: 'Test', version: '1.0.0' });
        assert.deepEqual(document.security, [{ bearerAuth: [] }]);
        assert.deepEqual(document.components.securitySchemes, { bearerAuth: { type: 'http', scheme: 'bearer' } });
        assert.deepEqual(document.servers, [{ url: 'https://example.com' }]);
    });
});

describe('the /swagger.json route', () => {
    async function serve(options) {
        const server = Hapi.server({ port: 0, host: '127.0.0.1' });

        registerOpenApiRoute(server, Object.assign({ info: { title: 'Test', version: '1.0.0' } }, options));

        server.route({
            method: 'GET',
            path: '/v1/thing',
            options: { tags: ['api'], auth: false, handler: () => ({}) }
        });

        await server.initialize();

        return server;
    }

    test('serves the document without authentication, even when the server requires a session', async () => {
        // The API reference reads this endpoint back over server.inject() with no credentials, and it
        // is a published URL that must stay readable on a secured instance
        const server = Hapi.server({ port: 0, host: '127.0.0.1' });

        server.auth.scheme('deny', () => ({
            authenticate(request, h) {
                return h.unauthenticated(new Error('no session'));
            }
        }));
        server.auth.strategy('session', 'deny');
        server.auth.default('session');

        registerOpenApiRoute(server, { info: { title: 'Test', version: '1.0.0' } });
        await server.initialize();

        const res = await server.inject({ method: 'get', url: JSON_PATH });

        assert.equal(res.statusCode, 200);
        assert.equal(res.result.openapi, '3.0.0');

        await server.stop();
    });

    test('reports when the document was generated', async () => {
        const server = await serve();

        const res = await server.inject({ method: 'get', url: JSON_PATH });

        assert.ok(res.headers['last-modified']);
        assert.ok(!Number.isNaN(Date.parse(res.headers['last-modified'])));

        await server.stop();
    });

    test('publishes the address the client used', async () => {
        const server = await serve();

        const direct = await server.inject({ method: 'get', url: JSON_PATH, headers: { host: 'ee.example.com' } });
        assert.deepEqual(direct.result.servers, [{ url: 'http://ee.example.com' }]);

        // Behind a reverse proxy the forwarded headers are the only source of the real address.
        // The value is per response and never cached, so it cannot leak into anyone else's document.
        const proxied = await server.inject({
            method: 'get',
            url: JSON_PATH,
            headers: { host: 'internal:3000', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'api.example.com, internal' }
        });
        assert.deepEqual(proxied.result.servers, [{ url: 'https://api.example.com' }]);

        const after = await server.inject({ method: 'get', url: JSON_PATH, headers: { host: 'ee.example.com' } });
        assert.deepEqual(after.result.servers, [{ url: 'http://ee.example.com' }]);

        await server.stop();
    });

    test('does not let a forwarded header compose an address of its own', async () => {
        const server = await serve();

        // The scheme header is a scheme, not the front of a URL
        const smuggled = await server.inject({
            method: 'get',
            url: JSON_PATH,
            headers: { host: 'ee.example.com', 'x-forwarded-proto': 'https://elsewhere.example/#' }
        });
        assert.deepEqual(smuggled.result.servers, [{ url: 'http://ee.example.com' }]);

        // A host that is not a host at all leaves the request's own address in place
        const malformed = await server.inject({
            method: 'get',
            url: JSON_PATH,
            headers: { host: 'ee.example.com', 'x-forwarded-host': 'not a host' }
        });
        assert.equal(malformed.result.servers[0].url, 'http://ee.example.com');

        await server.stop();
    });

    test('is not itself part of the document', async () => {
        const server = await serve();

        const res = await server.inject({ method: 'get', url: JSON_PATH });

        assert.deepEqual(Object.keys(res.result.paths), ['/v1/thing']);

        await server.stop();
    });
});
