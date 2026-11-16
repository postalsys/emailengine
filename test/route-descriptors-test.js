'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const pathlib = require('node:path');
const Hapi = require('@hapi/hapi');
const Joi = require('joi');

const { describeRoute, describeRoutes, routePlugins } = require('../lib/route-descriptors');

async function createServer() {
    const server = Hapi.server();
    server.route({
        method: 'POST',
        path: '/v1/thing/{id}',
        handler: () => ({ ok: true }),
        options: {
            description: 'Create a thing',
            notes: ['First note', 'Second note'],
            tags: ['api', 'Thing'],
            plugins: { openapi: { 'x-ee-impact': 'write' }, mcp: { name: 'create_thing' } },
            validate: {
                params: Joi.object({ id: Joi.string() }),
                payload: Joi.object({ name: Joi.string() })
            },
            response: { schema: Joi.object({ ok: Joi.boolean() }) }
        }
    });
    server.route({ method: 'GET', path: '/plain', handler: () => 'ok' });
    server.route({
        method: 'GET',
        path: '/probe',
        handler: request => ({ plugins: routePlugins(request.route), method: describeRoute(request.route).method }),
        options: { plugins: { openapi: { deprecated: true } } }
    });
    return server;
}

test('describes what the route declares', async () => {
    const server = await createServer();
    const routes = describeRoutes(server.table());
    const plain = routes.find(route => route.path === '/plain');
    const thing = routes.find(route => route.path === '/v1/thing/{id}');

    assert.equal(thing.method, 'post');
    assert.equal(thing.path, '/v1/thing/{id}');
    assert.equal(thing.description, 'Create a thing');
    assert.deepEqual(thing.notes, ['First note', 'Second note']);
    assert.deepEqual(thing.tags, ['api', 'Thing']);
    assert.ok(Joi.isSchema(thing.validate.params));
    assert.ok(Joi.isSchema(thing.validate.payload));
    assert.ok(Joi.isSchema(thing.responseSchema));
    assert.deepEqual(thing.plugins, { openapi: { 'x-ee-impact': 'write' }, mcp: { name: 'create_thing' } });

    // a route that declares nothing still has every field a consumer reads
    assert.deepEqual(plain.tags, []);
    for (const key of ['headers', 'params', 'query', 'payload']) {
        assert.ok(!plain.validate[key], key);
    }
    assert.deepEqual(plain.plugins, {});
    assert.equal(plain.responseSchema, undefined);
});

test('a descriptor is frozen and describes itself as itself', async () => {
    const server = await createServer();
    const [descriptor] = describeRoutes(server.table());
    assert.ok(Object.isFrozen(descriptor));
    assert.equal(describeRoute(descriptor), descriptor);
});

test('routePlugins reads a descriptor and a live request.route alike', async () => {
    const server = await createServer();
    const thing = describeRoutes(server.table()).find(route => route.path === '/v1/thing/{id}');
    assert.deepEqual(routePlugins(thing), thing.plugins);
    assert.equal(routePlugins(null), undefined);

    const res = await server.inject({ method: 'GET', url: '/probe' });
    const body = JSON.parse(res.payload);
    assert.deepEqual(body.plugins, { openapi: { deprecated: true } });
    assert.equal(body.method, 'get');
});

test('the OpenAPI generator and the MCP registry read routes only through descriptors', () => {
    // hapi's route shape is known in lib/route-descriptors.js alone; see the comment there
    const files = [
        'lib/openapi/build-document.js',
        'lib/openapi/joi-schema.js',
        'lib/mcp/tools.js',
        'lib/api-routes/permission-map.js',
        'lib/api-routes/route-metadata.js'
    ];
    for (const file of files) {
        const source = fs.readFileSync(pathlib.join(__dirname, '..', file), 'utf8');
        assert.doesNotMatch(source, /\.settings\.(validate|plugins|description|notes|tags|response)\b/, file);
    }
});
