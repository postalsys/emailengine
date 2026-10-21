'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): a bare Hapi server for driving
// API route modules in a test. It stands in for what workers/api.js sets up around the routes: an
// `api-token` strategy that lets every request in, the request logger and translator failAction
// uses, and errorCodeExt(), so error bodies carry the same codes a client sees.

const Hapi = require('@hapi/hapi');

const { errorCodeExt } = require('../../lib/api-error-codes');
const { createMockLogger } = require('./mock-logger');

/**
 * @param {Function} registerRoutes - async server => void, registers the routes under test
 * @param {Object} [opts]
 * @param {Function} [opts.authenticate] - The test-token scheme's authenticate(request, h); the
 *   default authenticates every request with an empty token record
 * @returns {Promise<Object>} The initialized server, with `logger` holding what routes logged
 */
async function createRouteTestServer(registerRoutes, opts = {}) {
    const server = Hapi.server({});
    const logger = createMockLogger();

    server.auth.scheme('test-token', () => ({
        authenticate: opts.authenticate || ((request, h) => h.authenticated({ credentials: { token: 'test' }, artifacts: {} }))
    }));
    server.auth.strategy('api-token', 'test-token');
    server.ext('onRequest', (request, h) => {
        request.logger = logger;
        // what failAction translates validation errors with
        request.app.gt = { gettext: text => text };
        return h.continue;
    });
    server.ext('onPreResponse', errorCodeExt);

    await registerRoutes(server);
    await server.initialize();
    server.logger = logger;
    return server;
}

module.exports = { createRouteTestServer };
