'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): generates the OpenAPI
// document the same way the running server does, in-process.
//
// The repo's swagger.json is gitignored - `npm run swagger` writes it by booting a server
// and fetching /swagger.json - so a test may not assume it exists. Rather than checking in
// a fixture that drifts from the routes, this registers the REAL route table
// (lib/api-routes/index.js, the same entry point workers/api.js uses) on a real Hapi server
// and asks the real document route (lib/openapi/index.js) for the spec. Tests therefore
// always see the spec the current route definitions produce.
//
// What this server has to reproduce is everything the generated document is derived from, not
// just the routes: the server-wide route defaults (every operation documents the X-EE-Timeout
// header), the real account schemas and the real size limits all end up in the document, so a
// simplified stand-in here would record a document no instance serves. That equivalence is worth
// keeping - it is what makes test/fixtures/openapi-golden.json a guard on the shipped artifact.
//
// The spec-shaping options come from lib/swagger-options.js, the same module workers/api.js
// passes in. That matters beyond tidiness: the curated `tags` array drives tag ORDER and
// descriptions, which lib/api-reference/model.js seeds its navigation from - a local copy
// here would leave that branch untested and free to drift. Only the version is set locally,
// since no assertion reads the rest of `info`.
//
// Requiring lib/api-routes transitively opens a Redis connection and BullMQ queues
// (lib/db.js), so a suite using this must close Redis in an after() hook, the same way
// test/ui-routes-table-test.js does.

const Hapi = require('@hapi/hapi');

const { buildMockArgs } = require('./capture-api-routes');
const registerApiRoutes = require('../../lib/api-routes');
const specOptions = require('../../lib/swagger-options');
const { registerOpenApiRoute, JSON_PATH } = require('../../lib/openapi');
const { apiHeadersSchema } = require('../../lib/schemas');

async function buildOpenApiSpec(overrides) {
    const server = Hapi.server({
        port: 0,
        host: '127.0.0.1',

        // The same server-wide route default workers/api.js applies. It is documentation-visible:
        // without it every operation would lose its X-EE-Timeout header parameter, and the recorded
        // document would describe an API no instance serves.
        routes: { validate: { headers: apiHeadersSchema } }
    });

    // The api-token strategy the /v1 routes declare. Never exercised - nothing is injected
    // but the document route - but every route names it, so it has to exist for registration.
    server.auth.scheme('mock-api-token', () => ({
        authenticate(request, h) {
            return h.authenticated({ credentials: {} });
        }
    }));
    server.auth.strategy('api-token', 'mock-api-token');

    registerOpenApiRoute(
        server,
        Object.assign({}, specOptions, {
            // The real `info`, with only the version pinned so the recorded golden does not
            // churn on every release. Everything else is what an instance serves - which
            // matters most for the description: the reference landing page renders it rather
            // than restating it, so its format is a contract a test has to be able to check.
            info: Object.assign({}, specOptions.info, { version: '0.0.0' })
        })
    );

    await registerApiRoutes(buildMockArgs(server, overrides));
    await server.initialize();

    const res = await server.inject({ method: 'get', url: JSON_PATH });
    if (res.statusCode !== 200) {
        throw new Error(`Failed to generate the OpenAPI document (HTTP ${res.statusCode})`);
    }

    const spec = res.result && typeof res.result === 'object' ? res.result : JSON.parse(res.payload);

    await server.stop();

    return spec;
}

module.exports = { buildOpenApiSpec };
