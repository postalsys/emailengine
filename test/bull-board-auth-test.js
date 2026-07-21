'use strict';

// Pins the Bull Board routes to an explicit 'session' strategy instead of the ambient server
// default - see lib/api-routes/bull-board-routes.js for why the default is not enough.
//
// The auth scheme here is a stub: it proves the plugin options reach every route the adapter
// registers, not the behaviour of the real cookie strategy.

const test = require('node:test');
const assert = require('node:assert').strict;
const Hapi = require('@hapi/hapi');

// Stub lib/db before requiring the routes so no Redis/BullMQ connection is opened.
function createMockQueue(name) {
    return {
        name,
        // BullMQAdapter accepts either a real Queue instance or anything reporting a bullmq
        // version, which keeps this test free of a live Redis connection.
        metaValues: { version: 'bullmq' },
        opts: { prefix: 'bull' },
        client: Promise.resolve({}),
        getJobCounts: async () => ({ active: 0, completed: 0, delayed: 0, failed: 0, paused: 0, waiting: 0 }),
        isPaused: async () => false,
        on: () => {},
        off: () => {}
    };
}

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        notifyQueue: createMockQueue('notify'),
        submitQueue: createMockQueue('submit'),
        documentsQueue: createMockQueue('documents')
    }
};

const initBullBoard = require('../lib/api-routes/bull-board-routes');

// Builds a server wired the way workers/api.js does: the 'session' strategy always exists, but the
// default is only installed when an admin password has been configured.
async function createServer({ authConfigured }) {
    const server = Hapi.server({ port: 0 });

    server.auth.scheme('test-session', () => ({
        authenticate(request, h) {
            if (request.headers['x-test-session'] === 'valid') {
                return h.authenticated({ credentials: { user: 'admin' } });
            }
            // Mirrors @hapi/cookie's redirectTo behaviour rather than a bare 401.
            return h.response().takeover().redirect('/admin/login');
        }
    }));
    server.auth.strategy('session', 'test-session');

    if (authConfigured) {
        server.auth.default('session');
    }

    await initBullBoard({ server });
    await server.initialize();
    return server;
}

test('Bull Board requires an admin session', async t => {
    await t.test('unauthenticated request is rejected when no admin password is set', async () => {
        // The regression: with no authData there is no default strategy, so the queue browser was
        // reachable by anyone who could reach the port.
        const server = await createServer({ authConfigured: false });
        try {
            const res = await server.inject({ method: 'GET', url: '/admin/bull-board' });
            assert.strictEqual(res.statusCode, 302, 'unauthenticated access should redirect to the login page');
        } finally {
            await server.stop();
        }
    });

    await t.test('an authenticated admin still reaches the queue browser', async () => {
        // Guards against over-fixing: the route must remain usable for a logged-in admin.
        const server = await createServer({ authConfigured: true });
        try {
            const res = await server.inject({
                method: 'GET',
                url: '/admin/bull-board',
                headers: { 'x-test-session': 'valid' }
            });
            assert.strictEqual(res.statusCode, 200, 'a valid session must still be served');
        } finally {
            await server.stop();
        }
    });

    await t.test('the static asset routes are gated too', async () => {
        // HapiAdapter registers a static-file route alongside the UI and API routes; all of them
        // take the same plugin options, so none may be left open.
        const server = await createServer({ authConfigured: false });
        try {
            const res = await server.inject({ method: 'GET', url: '/admin/bull-board/static/main.js' });
            // Assert the redirect specifically: auth runs before the handler, so an ungated static
            // route would 404 on this missing file instead, and a "not 200" check would pass either
            // way without proving anything.
            assert.strictEqual(res.statusCode, 302, 'static assets must not bypass the session check');
        } finally {
            await server.stop();
        }
    });
});
