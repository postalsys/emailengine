'use strict';

// Response security headers (lib/security-headers.js). The pure policy resolver is checked
// against the whole profile matrix, and the extension is exercised through a real Hapi server
// so it is proven on the response shapes it has to handle: a plain response, a rendered view,
// a redirect, a Boom error, and a Boom error that an earlier extension replaced with a rendered
// page - which is what workers/api.js does, and the case where a header set on the original
// error would silently go missing.
//
// Pure: nothing here requires Redis.

const test = require('node:test');
const assert = require('node:assert').strict;
const pathlib = require('path');
const Hapi = require('@hapi/hapi');
const Vision = require('@hapi/vision');
const Boom = require('@hapi/boom');
const handlebars = require('handlebars');

const {
    securityHeadersExt,
    attachSecurityContext,
    policyFor,
    profileNameFor,
    isAdminPath,
    isMachineRoute,
    isSecureOrigin,
    CSP_HEADER,
    CSP_REPORT_ONLY_HEADER
} = require('../lib/security-headers');
const { NONCE_RE } = require('./helpers/inline-scripts');

// Splits a policy string into a directive name -> value map
function directives(policy) {
    let result = {};
    for (let part of policy.split(';')) {
        let [name, ...value] = part.trim().split(/\s+/);
        result[name] = value.join(' ');
    }
    return result;
}

// Mirrors the extension order of workers/api.js: with `errorPage`, an error-page extension
// first replaces a Boom with a rendered response, then the security headers extension runs
async function buildServer({ errorPage = true, cspMode = 'enforce', secureOrigin = false } = {}) {
    const server = Hapi.server({ port: 0 });
    await server.register(Vision);

    server.views({
        engines: { hbs: handlebars },
        relativeTo: pathlib.join(__dirname, 'fixtures', 'security-headers'),
        path: '.',
        layout: 'app',
        layoutPath: './layout',
        context: request => ({ cspNonce: request.app.cspNonce })
    });

    server.ext('onRequest', (request, h) => {
        attachSecurityContext(request, { secureOrigin });
        return h.continue;
    });

    server.route({ method: 'GET', path: '/admin', handler: () => 'dashboard' });
    server.route({ method: 'GET', path: '/admin/page', handler: (request, h) => h.view('page', { title: 'Accounts' }) });
    server.route({ method: 'GET', path: '/admin/error-page', handler: (request, h) => h.view('page', { title: 'Oops' }, { layout: 'public' }) });
    server.route({ method: 'GET', path: '/admin/redirect', handler: (request, h) => h.redirect('/admin') });
    server.route({
        method: 'GET',
        path: '/admin/missing',
        handler: () => {
            throw Boom.notFound('nope');
        }
    });
    server.route({
        method: 'GET',
        path: '/admin/browse',
        handler: () => 'messages',
        options: { plugins: { securityHeaders: { directives: { 'img-src': "'self' data: https:" } } } }
    });
    server.route({
        method: 'GET',
        path: '/admin/consent',
        handler: () => 'consent',
        options: { plugins: { securityHeaders: { directives: { 'form-action': null } } } }
    });
    server.route({ method: 'GET', path: '/admin/changes', handler: (request, h) => h.response('data').header('Cache-Control', 'no-cache') });
    server.route({ method: 'GET', path: '/admin/bull-board', handler: () => '<html>board</html>' });
    server.route({ method: 'GET', path: '/admin/bull-board/static/main.js', handler: () => 'js' });
    server.route({ method: 'GET', path: '/v1/thing', handler: () => ({ ok: true }) });
    server.route({
        method: 'GET',
        path: '/v1/broken',
        handler: () => {
            throw Boom.badRequest('bad');
        }
    });
    server.route({ method: 'GET', path: '/metrics', handler: () => 'metrics', options: { tags: ['scope:metrics', 'external'] } });
    server.route({ method: 'GET', path: '/accounts/new', handler: () => 'hosted form' });
    server.route({ method: 'GET', path: '/static/app.js', handler: () => 'js', options: { tags: ['static'] } });

    if (errorPage) {
        server.ext('onPreResponse', (request, h) => {
            if (request.response.isBoom) {
                return h.response('<html>error page</html>').type('text/html').code(request.response.output.statusCode);
            }
            return h.continue;
        });
    }
    server.ext('onPreResponse', securityHeadersExt({ cspMode }));

    await server.initialize();
    return server;
}

const COMMON = ['x-content-type-options', 'referrer-policy', 'x-permitted-cross-domain-policies'];
const PAGE = [...COMMON, 'permissions-policy', CSP_HEADER];
const ADMIN = [...PAGE, 'x-frame-options', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cache-control'];

test('security header helpers', async t => {
    await t.test('isAdminPath covers /admin and its subtree only', () => {
        assert.equal(isAdminPath('/admin'), true);
        assert.equal(isAdminPath('/admin/accounts/x'), true);
        assert.equal(isAdminPath('/admin-ish'), false, 'a sibling path sharing the prefix is not admin');
        assert.equal(isAdminPath('/v1/account'), false);
        assert.equal(isAdminPath('/accounts/new'), false);
        assert.equal(isAdminPath(undefined), false);
    });

    await t.test('isSecureOrigin is true for an https serviceUrl only', () => {
        assert.equal(isSecureOrigin('https://mail.example.com'), true);
        assert.equal(isSecureOrigin('http://mail.example.com'), false);
        assert.equal(isSecureOrigin('not a url'), false);
        assert.equal(isSecureOrigin(''), false);
        assert.equal(isSecureOrigin(undefined), false);
    });

    await t.test('isMachineRoute recognises every tag the CSRF check skips', () => {
        for (let tag of ['api', 'external', 'static']) {
            assert.equal(isMachineRoute([tag]), true, tag);
        }
        assert.equal(isMachineRoute(['scope:metrics']), false, 'a scope tag says what a token may reach, not who the route serves');
        assert.equal(isMachineRoute(['health']), false);
        assert.equal(isMachineRoute([]), false);
        assert.equal(isMachineRoute(), false);
    });

    await t.test('profileNameFor picks the surface from path and tags', () => {
        assert.equal(profileNameFor('/static/js/app.js', ['static']), 'static');
        assert.equal(profileNameFor('/health', ['static', 'health']), 'static');
        assert.equal(profileNameFor('/admin/bull-board/static/main.js'), 'static', 'bull-board ships its own assets');
        assert.equal(profileNameFor('/admin/bull-board'), 'bullBoard');
        assert.equal(profileNameFor('/admin/bull-board/api/queues'), 'bullBoard');
        assert.equal(profileNameFor('/admin'), 'admin');
        assert.equal(profileNameFor('/admin/accounts'), 'admin');
        assert.equal(profileNameFor('/v1/account'), 'api');
        assert.equal(profileNameFor('/v1/nowhere'), 'api', 'a 404 under /v1 is still machine-facing');
        assert.equal(profileNameFor('/swagger.json', ['external']), 'api');
        assert.equal(profileNameFor('/metrics', ['scope:metrics', 'external']), 'api');
        assert.equal(profileNameFor('/mcp', ['external']), 'api');
        assert.equal(profileNameFor('/.well-known/oauth-authorization-server', ['external']), 'api');
        assert.equal(profileNameFor('/accounts/new'), 'public');
        assert.equal(profileNameFor('/unsubscribe'), 'public');
        assert.equal(profileNameFor('/'), 'public');
        assert.equal(profileNameFor(undefined), 'public');
    });
});

test('policyFor resolves the header matrix', async t => {
    const nonce = 'abcdefghijklmnopqrstuv';

    await t.test('static: the common set only, no policy and no caching directive', () => {
        const { headers, cacheControl } = policyFor({ path: '/static/app.js', tags: ['static'], nonce });
        assert.deepEqual(Object.keys(headers).sort(), [...COMMON].sort());
        assert.equal(headers['x-content-type-options'], 'nosniff');
        assert.equal(headers['referrer-policy'], 'strict-origin-when-cross-origin');
        assert.equal(headers['x-permitted-cross-domain-policies'], 'none');
        assert.equal(cacheControl, null);
    });

    await t.test('api: nothing may render or frame the response, and nothing caches it', () => {
        const { headers, cacheControl } = policyFor({ path: '/v1/account', tags: ['api'], nonce });
        assert.equal(headers['x-frame-options'], 'DENY');
        assert.equal(headers[CSP_HEADER], "default-src 'none'; frame-ancestors 'none'");
        assert.ok(headers['permissions-policy']);
        assert.equal('cross-origin-opener-policy' in headers, false);
        assert.equal(cacheControl, 'no-store');
    });

    await t.test('admin: the nonce-based policy plus framing, isolation and no-store', () => {
        const { headers, cacheControl } = policyFor({ path: '/admin/accounts', nonce });
        const csp = directives(headers[CSP_HEADER]);

        assert.equal(csp['default-src'], "'self'");
        assert.equal(csp['script-src'], `'self' 'nonce-${nonce}'`);
        assert.equal(csp['style-src'], "'self' 'unsafe-inline'", 'the fallback for browsers without the elem/attr split');
        assert.equal(csp['style-src-elem'], `'self' 'nonce-${nonce}'`, 'a <style> element needs the nonce like a script');
        assert.equal(csp['style-src-attr'], "'unsafe-inline'", 'inlined email CSS lives in style attributes');
        assert.equal(csp['img-src'], "'self' data:");
        assert.equal(csp['worker-src'], "'self' blob:");
        assert.equal(csp['object-src'], "'none'");
        assert.equal(csp['base-uri'], "'none'");
        assert.equal(csp['form-action'], "'self'");
        assert.equal(csp['frame-ancestors'], "'self'");
        assert.doesNotMatch(headers[CSP_HEADER], /unsafe-eval/);

        assert.equal(headers['x-frame-options'], 'SAMEORIGIN');
        assert.equal(headers['cross-origin-opener-policy'], 'same-origin');
        assert.equal(headers['cross-origin-resource-policy'], 'same-origin');
        assert.equal(cacheControl, 'no-store');
    });

    await t.test('admin without a nonce fails closed: no inline script or style element runs', () => {
        const { headers } = policyFor({ path: '/admin' });
        assert.equal(directives(headers[CSP_HEADER])['script-src'], "'self'");
        assert.equal(directives(headers[CSP_HEADER])['style-src-elem'], "'self'");
        assert.doesNotMatch(headers[CSP_HEADER], /nonce/);
    });

    await t.test('bull-board: third-party markup, no nonce, its font hosts allowed', () => {
        const { headers } = policyFor({ path: '/admin/bull-board', nonce });
        const csp = directives(headers[CSP_HEADER]);

        assert.equal(csp['script-src'], "'self'");
        assert.doesNotMatch(headers[CSP_HEADER], /nonce/);
        assert.equal(csp['style-src'], "'self' 'unsafe-inline' https://fonts.googleapis.com");
        assert.equal(csp['font-src'], "'self' https://fonts.gstatic.com");
        assert.equal(csp['base-uri'], "'self'", 'the board shell carries a <base href>');
        assert.equal(csp['frame-ancestors'], "'self'");
        assert.equal(headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('public: relaxed for operator markup, no nonce, frameable', () => {
        const { headers, cacheControl } = policyFor({ path: '/accounts/new', nonce });
        const csp = directives(headers[CSP_HEADER]);

        assert.equal(csp['script-src'], "'self' https: 'unsafe-inline'");
        assert.doesNotMatch(headers[CSP_HEADER], /nonce/, 'a nonce would make browsers ignore unsafe-inline');
        assert.equal(csp['form-action'], "'self' https:", 'the hosted form redirects to the OAuth provider after its POST');
        assert.equal('frame-ancestors' in csp, false);
        assert.equal('x-frame-options' in headers, false);
        assert.equal('cross-origin-opener-policy' in headers, false);
        assert.equal(cacheControl, null);
    });

    await t.test('a view rendered with the public layout on an admin path takes the public preset but keeps admin framing', () => {
        const { headers } = policyFor({ path: '/admin/missing', layout: 'public', nonce });
        const csp = directives(headers[CSP_HEADER]);

        assert.equal(csp['script-src'], "'self' https: 'unsafe-inline'");
        assert.equal(csp['frame-ancestors'], "'self'");
        assert.equal(headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('a view with another layout on an admin path stays strict', () => {
        const { headers } = policyFor({ path: '/admin/login', layout: 'login', nonce });
        assert.equal(directives(headers[CSP_HEADER])['script-src'], `'self' 'nonce-${nonce}'`);
    });

    await t.test('a route override replaces or removes single directives', () => {
        const browse = policyFor({ path: '/admin/browse', nonce, override: { directives: { 'img-src': "'self' data: https:" } } });
        const browseCsp = directives(browse.headers[CSP_HEADER]);
        assert.equal(browseCsp['img-src'], "'self' data: https:");
        assert.equal(browseCsp['script-src'], `'self' 'nonce-${nonce}'`, 'the rest of the preset is untouched');

        const consent = policyFor({ path: '/admin/mcp/authorize', nonce, override: { directives: { 'form-action': null } } });
        assert.equal('form-action' in directives(consent.headers[CSP_HEADER]), false);

        // the nonce is appended after the override, so overriding script-src cannot drop it
        const scripts = policyFor({ path: '/admin/x', nonce, override: { directives: { 'script-src': "'self' https://cdn.example.com" } } });
        assert.equal(directives(scripts.headers[CSP_HEADER])['script-src'], `'self' https://cdn.example.com 'nonce-${nonce}'`);

        // An override that means to widen a nonced directive has to state the full source list:
        // a browser ignores 'unsafe-inline' in any directive that also carries a nonce, so
        // adding it beside one blocks what it was meant to allow
        const styles = policyFor({ path: '/admin/x', nonce, override: { directives: { 'style-src-elem': "'self' https://cdn.example.com" } } });
        assert.equal(directives(styles.headers[CSP_HEADER])['style-src-elem'], `'self' https://cdn.example.com 'nonce-${nonce}'`);
    });

    await t.test('HSTS follows the secure-origin flag on every profile', () => {
        for (let path of ['/static/app.js', '/v1/thing', '/admin', '/accounts/new']) {
            assert.equal(policyFor({ path, secureOrigin: true }).headers['strict-transport-security'], 'max-age=31536000', path);
            assert.equal('strict-transport-security' in policyFor({ path }).headers, false, path);
        }
    });

    await t.test('report-only keeps framing enforced and moves the policy to the report-only header', () => {
        const { headers } = policyFor({ path: '/admin', nonce, cspMode: 'report-only' });
        assert.equal(headers[CSP_HEADER], "frame-ancestors 'self'");
        assert.match(headers[CSP_REPORT_ONLY_HEADER], NONCE_RE);
        assert.match(headers[CSP_REPORT_ONLY_HEADER], /frame-ancestors 'self'/);

        const pub = policyFor({ path: '/accounts/new', cspMode: 'report-only' });
        assert.equal(CSP_HEADER in pub.headers, false, 'nothing to enforce on a frameable page');
        assert.ok(pub.headers[CSP_REPORT_ONLY_HEADER]);
    });

    await t.test('off leaves the framing directive only, the other headers stay', () => {
        const { headers, cacheControl } = policyFor({ path: '/admin', nonce, secureOrigin: true, cspMode: 'off' });
        assert.equal(headers[CSP_HEADER], "frame-ancestors 'self'");
        assert.equal(CSP_REPORT_ONLY_HEADER in headers, false);
        assert.equal(headers['strict-transport-security'], 'max-age=31536000');
        assert.equal(headers['cross-origin-opener-policy'], 'same-origin');
        assert.equal(cacheControl, 'no-store');

        assert.equal(CSP_HEADER in policyFor({ path: '/accounts/new', cspMode: 'off' }).headers, false);
    });
});

test('security headers extension', async t => {
    const server = await buildServer();
    t.after(() => server.stop());

    await t.test('an admin page carries the full set', async () => {
        const res = await server.inject('/admin');
        assert.equal(res.statusCode, 200);
        for (const name of ADMIN) {
            assert.ok(res.headers[name], `${name} must be set`);
        }
        assert.equal(res.headers['cache-control'], 'no-store');
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('the nonce in the header is the one the rendered view carries, and it changes per request', async () => {
        const first = await server.inject('/admin/page');
        assert.equal(first.statusCode, 200);
        const nonce = first.headers[CSP_HEADER].match(NONCE_RE)[1];
        assert.match(first.payload, new RegExp(`<script nonce="${nonce}">`));
        assert.match(first.payload, /class="app"/, 'rendered through the default layout');

        const second = await server.inject('/admin/page');
        assert.notEqual(second.headers[CSP_HEADER].match(NONCE_RE)[1], nonce);
    });

    await t.test('a public-layout view on an admin path gets the relaxed policy with admin framing', async () => {
        const res = await server.inject('/admin/error-page');
        assert.equal(res.statusCode, 200);
        const csp = directives(res.headers[CSP_HEADER]);
        assert.equal(csp['script-src'], "'self' https: 'unsafe-inline'");
        assert.equal(csp['frame-ancestors'], "'self'");
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('a route override reaches the header', async () => {
        const browse = await server.inject('/admin/browse');
        assert.equal(directives(browse.headers[CSP_HEADER])['img-src'], "'self' data: https:");

        const consent = await server.inject('/admin/consent');
        assert.equal('form-action' in directives(consent.headers[CSP_HEADER]), false);
    });

    await t.test('a Cache-Control the handler set survives', async () => {
        const res = await server.inject('/admin/changes');
        assert.equal(res.headers['cache-control'], 'no-cache');
        assert.ok(res.headers[CSP_HEADER]);
    });

    await t.test('bull-board gets its own policy and its assets get none', async () => {
        const board = await server.inject('/admin/bull-board');
        assert.match(board.headers[CSP_HEADER], /fonts\.googleapis\.com/);
        assert.doesNotMatch(board.headers[CSP_HEADER], /nonce/);

        const asset = await server.inject('/admin/bull-board/static/main.js');
        assert.equal(asset.headers[CSP_HEADER], undefined);
        assert.equal(asset.headers['x-content-type-options'], 'nosniff');
    });

    await t.test('the API carries the machine-facing set', async () => {
        const res = await server.inject('/v1/thing');
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers[CSP_HEADER], "default-src 'none'; frame-ancestors 'none'");
        assert.equal(res.headers['x-frame-options'], 'DENY');
        assert.equal(res.headers['cache-control'], 'no-store');

        const metrics = await server.inject('/metrics');
        assert.equal(metrics.headers['x-frame-options'], 'DENY', 'picked by tag, not path');
    });

    await t.test('the public pages are left frameable', async () => {
        // The hosted form is opened from an operator's own application, which may embed it
        const res = await server.inject('/accounts/new');
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['x-frame-options'], undefined);
        assert.doesNotMatch(res.headers[CSP_HEADER], /frame-ancestors/);
        assert.match(res.headers[CSP_HEADER], /'unsafe-inline'/);
        assert.notEqual(res.headers['cache-control'], 'no-store');
    });

    await t.test('static files get the common set and no policy', async () => {
        const res = await server.inject('/static/app.js');
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers[CSP_HEADER], undefined);
        assert.equal(res.headers['permissions-policy'], undefined);
        assert.equal(res.headers['strict-transport-security'], undefined);
    });

    await t.test('a rebuilt error page carries the headers', async () => {
        // The error-page extension replaced the Boom with a new response before this ran; a
        // header stamped onto the Boom's output would have been lost with it
        const res = await server.inject('/admin/missing');
        assert.equal(res.statusCode, 404);
        assert.match(res.payload, /error page/);
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
        assert.match(res.headers[CSP_HEADER], NONCE_RE);
        assert.equal(res.headers['cache-control'], 'no-store');
    });

    await t.test('a redirect carries the headers', async () => {
        const res = await server.inject('/admin/redirect');
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
        assert.ok(res.headers[CSP_HEADER]);
    });

    await t.test('a Boom error that nothing replaces gets the headers on its own output', async t => {
        const bare = await buildServer({ errorPage: false });
        t.after(() => bare.stop());

        const res = await bare.inject('/v1/broken');
        assert.equal(res.statusCode, 400);
        assert.equal(res.headers['x-content-type-options'], 'nosniff');
        assert.equal(res.headers['x-frame-options'], 'DENY');
        assert.equal(res.headers['cache-control'], 'no-store');

        const adminErr = await bare.inject('/admin/missing');
        assert.equal(adminErr.statusCode, 404);
        assert.equal(adminErr.headers['x-frame-options'], 'SAMEORIGIN');
    });

    await t.test('HSTS is sent on a secure origin', async t => {
        const secure = await buildServer({ secureOrigin: true });
        t.after(() => secure.stop());

        for (let path of ['/admin', '/v1/thing', '/accounts/new', '/static/app.js']) {
            assert.equal((await secure.inject(path)).headers['strict-transport-security'], 'max-age=31536000', path);
        }
        assert.equal((await server.inject('/admin')).headers['strict-transport-security'], undefined);
    });

    await t.test('report-only mode delivers both headers', async t => {
        const reporting = await buildServer({ cspMode: 'report-only' });
        t.after(() => reporting.stop());

        const res = await reporting.inject('/admin/page');
        assert.equal(res.headers[CSP_HEADER], "frame-ancestors 'self'");
        const nonce = res.headers[CSP_REPORT_ONLY_HEADER].match(NONCE_RE)[1];
        assert.match(res.payload, new RegExp(`<script nonce="${nonce}">`));
    });
});
