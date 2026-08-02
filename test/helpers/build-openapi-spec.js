'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): generates the OpenAPI
// document the same way the running server does, in-process.
//
// The repo's swagger.json is gitignored - `npm run swagger` writes it by booting a server
// and fetching /swagger.json - so a test may not assume it exists. Rather than checking in
// a fixture that drifts from the routes, this registers the REAL route table
// (lib/api-routes/index.js, the same entry point workers/api.js uses) on a real Hapi server
// with hapi-swagger and injects /swagger.json. Tests therefore always see the spec the
// current route definitions produce.
//
// The spec-shaping options come from lib/swagger-options.js, the same module workers/api.js
// spreads into its hapi-swagger config. That matters beyond tidiness: the curated `tags`
// array drives tag ORDER and descriptions, which lib/api-reference/model.js seeds its
// navigation from - a local copy here would leave that branch untested and free to drift.
// Only the presentation-only options (swaggerUI, templates, cache, info prose) are set
// locally, since none of them affect what the tests assert on.
//
// Requiring lib/api-routes transitively opens a Redis connection and BullMQ queues
// (lib/db.js), so a suite using this must close Redis in an after() hook, the same way
// test/ui-routes-table-test.js does.

const Hapi = require('@hapi/hapi');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');

const { buildMockArgs } = require('./capture-api-routes');
const registerApiRoutes = require('../../lib/api-routes');
const specOptions = require('../../lib/swagger-options');

async function buildOpenApiSpec(overrides) {
    const server = Hapi.server({ port: 0, host: '127.0.0.1' });

    // The api-token strategy the /v1 routes declare. Never exercised - nothing is injected
    // but /swagger.json - but every route names it, so it has to exist for registration.
    server.auth.scheme('mock-api-token', () => ({
        authenticate(request, h) {
            return h.authenticated({ credentials: {} });
        }
    }));
    server.auth.strategy('api-token', 'mock-api-token');

    await server.register([Inert, Vision]);
    await server.register({
        plugin: HapiSwagger,
        options: Object.assign({}, specOptions, {
            swaggerUI: false,
            documentationPage: false,
            jsonPath: '/swagger.json',
            // version only - the rest of `info` is prose that no assertion reads
            info: { title: 'EmailEngine API', version: '0.0.0' }
        })
    });

    await registerApiRoutes(buildMockArgs(server, overrides));
    await server.initialize();

    const res = await server.inject({ method: 'get', url: '/swagger.json' });
    if (res.statusCode !== 200) {
        throw new Error(`Failed to generate the OpenAPI document (HTTP ${res.statusCode})`);
    }

    const spec = res.result && typeof res.result === 'object' ? res.result : JSON.parse(res.payload);

    await server.stop();

    return spec;
}

module.exports = { buildOpenApiSpec };
