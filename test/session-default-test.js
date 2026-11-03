'use strict';

// lib/session-default.js: an API worker asks for an admin login as soon as a password exists, even
// when the password was written with no settings broadcast (the CLI writes it straight into Redis).
// Run against a real hapi server, since the fix depends on hapi resolving the default strategy for
// every request.

const test = require('node:test');
const assert = require('node:assert').strict;
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');

const { requireSessionOnceSecured } = require('../lib/session-default');
const exitWhenStandalone = require('./helpers/exit-standalone');

const logger = { info() {} };

async function buildServer(state) {
    const server = Hapi.server();
    // Stands in for the cookie strategy: no session cookie, no entry
    server.auth.scheme('fake-session', () => ({
        authenticate: (request, h) =>
            request.headers['x-session'] ? h.authenticated({ credentials: { user: 'admin' } }) : h.unauthenticated(Boom.unauthorized('login'))
    }));
    server.auth.strategy('session', 'fake-session');
    requireSessionOnceSecured({
        server,
        isInstanceSecured: async () => {
            state.asked++;
            return state.secured;
        },
        logger
    });
    // Registered before any default exists, as the admin routes are
    server.route({ method: 'GET', path: '/admin', handler: () => 'admin' });
    server.route({ method: 'GET', path: '/public', options: { auth: false }, handler: () => 'public' });
    await server.initialize();
    return server;
}

test('requireSessionOnceSecured()', async t => {
    await t.test('serves the admin pages open while no password is set', async () => {
        const state = { secured: false, asked: 0 };
        const server = await buildServer(state);
        assert.equal((await server.inject('/admin')).statusCode, 200);
        assert.equal(server.auth.settings.default, null);
        assert.equal(state.asked, 1);
    });

    await t.test('asks for a login on the first request after a password appears', async () => {
        const state = { secured: false, asked: 0 };
        const server = await buildServer(state);
        assert.equal((await server.inject('/admin')).statusCode, 200);

        // Written by the CLI: no broadcast, no restart
        state.secured = true;
        const noticed = await server.inject('/admin?tab=1');
        assert.equal(noticed.statusCode, 307, 'the request that noticed it is sent round again');
        assert.equal(noticed.headers.location, '/admin?tab=1');
        assert.equal((await server.inject('/admin?tab=1')).statusCode, 401, 'and that time it is asked to log in');
        assert.equal((await server.inject({ url: '/admin', headers: { 'x-session': '1' } })).statusCode, 200, 'a session gets in');
        assert.deepEqual(server.auth.settings.default.strategies, ['session']);
    });

    await t.test('never sends the request round to another host', async () => {
        const state = { secured: true, asked: 0 };
        const server = await buildServer(state);
        server.route({ method: 'GET', path: '/{any*}', handler: () => 'any' });
        const res = await server.inject('//evil.example/admin?x=1');
        assert.equal(res.statusCode, 307);
        assert.equal(res.headers.location, '/evil.example/admin?x=1');
    });

    await t.test('stops asking Redis once the default is set', async () => {
        const state = { secured: true, asked: 0 };
        const server = await buildServer(state);
        await server.inject('/admin');
        await server.inject('/admin');
        await server.inject({ url: '/admin', headers: { 'x-session': '1' } });
        assert.equal(state.asked, 1);
    });

    await t.test('never asks for a route with its own auth setting', async () => {
        const state = { secured: true, asked: 0 };
        const server = await buildServer(state);
        assert.equal((await server.inject('/public')).statusCode, 200);
        assert.equal(state.asked, 0);
        assert.equal(server.auth.settings.default, null);
    });

    await t.test('concurrent requests set the default once', async () => {
        const state = { secured: true, asked: 0 };
        const server = await buildServer(state);
        const results = await Promise.all(Array.from({ length: 5 }, () => server.inject('/admin')));
        // Each was already running without authentication, so each is sent round again
        assert.deepEqual(
            results.map(res => res.statusCode),
            [307, 307, 307, 307, 307]
        );
        assert.equal((await server.inject('/admin')).statusCode, 401);
    });
});

exitWhenStandalone();
