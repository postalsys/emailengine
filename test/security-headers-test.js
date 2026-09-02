'use strict';

// Response security headers (lib/security-headers.js), exercised through a real Hapi server so
// the extension is proven on the response shapes it has to handle: a plain response, a
// redirect, a Boom error, and a Boom error that an earlier extension replaced with a rendered
// page - which is what workers/api.js does, and the case where a header set on the original
// error would silently go missing.
//
// Pure: nothing here requires Redis.

const test = require('node:test');
const assert = require('node:assert').strict;
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');

const { applySecurityHeaders, securityHeadersFor, isAdminPath } = require('../lib/security-headers');

// With `errorPage`, mirrors the extension order of workers/api.js: the error-page extension
// first, which replaces a Boom with a rendered response, then the security headers
async function buildServer({ errorPage }) {
    const server = Hapi.server({ port: 0 });

    server.route({ method: 'GET', path: '/admin', handler: () => 'dashboard' });
    server.route({ method: 'GET', path: '/admin/accounts', handler: () => 'accounts' });
    server.route({ method: 'GET', path: '/admin/redirect', handler: (request, h) => h.redirect('/admin') });
    server.route({
        method: 'GET',
        path: '/admin/missing',
        handler: () => {
            throw Boom.notFound('nope');
        }
    });
    server.route({ method: 'GET', path: '/v1/thing', handler: () => ({ ok: true }) });
    server.route({
        method: 'GET',
        path: '/v1/broken',
        handler: () => {
            throw Boom.badRequest('bad');
        }
    });
    server.route({ method: 'GET', path: '/accounts/new', handler: () => 'hosted form' });

    if (errorPage) {
        server.ext('onPreResponse', (request, h) => {
            if (request.response.isBoom) {
                return h.response('<html>error page</html>').type('text/html').code(request.response.output.statusCode);
            }
            return h.continue;
        });
    }
    server.ext('onPreResponse', applySecurityHeaders);

    await server.initialize();
    return server;
}

const ADMIN_ONLY = ['x-frame-options', 'content-security-policy'];
const EVERYWHERE = ['x-content-type-options', 'referrer-policy'];

test('security headers', async t => {
    await t.test('isAdminPath covers /admin and its subtree only', () => {
        assert.equal(isAdminPath('/admin'), true);
        assert.equal(isAdminPath('/admin/accounts/x'), true);
        assert.equal(isAdminPath('/admin-ish'), false, 'a sibling path sharing the prefix is not admin');
        assert.equal(isAdminPath('/v1/account'), false);
        assert.equal(isAdminPath('/accounts/new'), false);
        assert.equal(isAdminPath(undefined), false);
    });

    await t.test('securityHeadersFor adds the framing headers on the admin surface only', () => {
        const admin = securityHeadersFor('/admin/accounts');
        const api = securityHeadersFor('/v1/account');

        assert.equal(admin['x-frame-options'], 'SAMEORIGIN');
        assert.equal(admin['content-security-policy'], "frame-ancestors 'self'");
        assert.equal(admin['x-content-type-options'], 'nosniff');
        assert.equal(api['x-content-type-options'], 'nosniff');
        assert.equal(api['referrer-policy'], 'strict-origin-when-cross-origin');
        assert.equal('x-frame-options' in api, false);
        assert.equal('content-security-policy' in api, false);
    });

    const server = await buildServer({ errorPage: true });
    t.after(() => server.stop());

    await t.test('an admin page carries the full set', async () => {
        const res = await server.inject('/admin/accounts');
        assert.equal(res.statusCode, 200);
        for (const name of [...EVERYWHERE, ...ADMIN_ONLY]) {
            assert.ok(res.headers[name], `${name} must be set`);
        }
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('the API carries the common headers and stays frameable', async () => {
        const res = await server.inject('/v1/thing');
        assert.equal(res.statusCode, 200);
        for (const name of EVERYWHERE) {
            assert.ok(res.headers[name], `${name} must be set`);
        }
        for (const name of ADMIN_ONLY) {
            assert.equal(res.headers[name], undefined, `${name} must not be set on the API`);
        }
    });

    await t.test('the public pages are left frameable', async () => {
        // The hosted form is opened from an operator's own application, which may embed it
        const res = await server.inject('/accounts/new');
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['x-frame-options'], undefined);
    });

    await t.test('a rebuilt error page carries the headers', async () => {
        // The error-page extension replaced the Boom with a new response before this ran; a
        // header stamped onto the Boom's output would have been lost with it
        const res = await server.inject('/admin/missing');
        assert.equal(res.statusCode, 404);
        assert.match(res.payload, /error page/);
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
    });

    await t.test('a redirect carries the headers', async () => {
        const res = await server.inject('/admin/redirect');
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
    });

    await t.test('a Boom error that nothing replaces gets the headers on its own output', async t => {
        const bare = await buildServer({ errorPage: false });
        t.after(() => bare.stop());

        const res = await bare.inject('/v1/broken');
        assert.equal(res.statusCode, 400);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['referrer-policy'], 'strict-origin-when-cross-origin');

        const adminErr = await bare.inject('/admin/missing');
        assert.equal(adminErr.statusCode, 404);
        assert.equal(adminErr.headers['x-frame-options'], 'SAMEORIGIN');
    });
});
