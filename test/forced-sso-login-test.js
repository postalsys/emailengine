'use strict';

// GET /admin/login on a forced-SSO instance hands off to the identity provider. It used to do that
// with an HTTP redirect, which the admin form-action policy killed whenever a session expired
// mid-form - views/account/login-redirect.hbs has the whole story.
//
// Driven through the real route handler captured from lib/routes-ui.js, with a fake request and
// toolkit - the decision reads `sso.OIDC_FORCED` and the `validateOidcConfig` decoration, both of
// which a test can supply. The rendered page is then read off disk, because the handler choosing
// the template proves nothing on its own: a template that had lost its self-navigation would leave
// every assertion here green and every forced-SSO login stuck on a page with a button.

const test = require('node:test');
const assert = require('node:assert').strict;

const fs = require('node:fs');
const path = require('node:path');

const sso = require('../lib/sso');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { captureRouteConfigs } = require('./helpers/capture-ui-routes');

registerRedisTeardown(redis);

const loginRoute = captureRouteConfigs().find(cfg => cfg.path === '/admin/login' && [].concat(cfg.method).includes('GET'));

// The toolkit decorations the handler reaches for, plus recorders for what it answered with.
function makeToolkit({ oidcUsable = true, oktaUsable = false } = {}) {
    const answers = { views: [], redirects: [] };
    const h = {
        answers,
        async validateOidcConfig() {
            return oidcUsable;
        },
        async validateOktaConfig() {
            return oktaUsable;
        },
        view(template, context, options) {
            answers.views.push({ template, context, options });
            return { template, context, options };
        },
        redirect(url) {
            answers.redirects.push(url);
            return { redirect: url };
        }
    };
    return h;
}

const makeRequest = (query = {}) => ({
    query,
    auth: { isAuthenticated: false },
    logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} },
    app: {}
});

// OIDC_FORCED and USE_OIDC_AUTH are read off the module object at call time, so a test can set them
// for the duration of one case.
async function withForcedSso(fn) {
    const before = { forced: sso.OIDC_FORCED, use: sso.USE_OIDC_AUTH };
    sso.OIDC_FORCED = true;
    sso.USE_OIDC_AUTH = true;
    try {
        return await fn();
    } finally {
        sso.OIDC_FORCED = before.forced;
        sso.USE_OIDC_AUTH = before.use;
    }
}

test('forced SSO hands off to the provider without an HTTP redirect', async t => {
    await t.test('the route under test was found', () => {
        assert.ok(loginRoute, 'GET /admin/login must be registered');
        assert.equal(typeof loginRoute.handler, 'function');
    });

    await t.test('renders the hand-off page instead of redirecting', async () => {
        await withForcedSso(async () => {
            const h = makeToolkit();
            await loginRoute.handler(makeRequest(), h);

            assert.deepEqual(h.answers.redirects, [], 'an HTTP redirect here is what form-action blocks');
            assert.equal(h.answers.views.length, 1);

            const [rendered] = h.answers.views;
            assert.equal(rendered.template, 'account/login-redirect');
            assert.equal(rendered.context.ssoRedirectUrl, '/admin/login/oidc', 'the page has to name where it is going');
            assert.equal(rendered.options.layout, 'login', 'the hand-off keeps the chrome-free login layout');
        });
    });

    await t.test('the page it renders navigates itself', async () => {
        // The point of rendering instead of redirecting is that the page moves the browser on. If
        // this ever became a page the user has to click through, every forced-SSO login would stop
        // dead on it, and no assertion about which template was chosen would notice.
        const source = fs.readFileSync(path.join(__dirname, '..', 'views', 'account', 'login-redirect.hbs'), 'utf-8');

        assert.match(source, /window\.location\.replace\(/, 'the hand-off has to start the navigation itself');
        assert.match(source, /nonce="\{\{cspNonce\}\}"/, 'and the admin CSP only runs a script carrying the nonce');
        assert.match(source, /id="sso-continue"/, 'the fallback link the script reads, and a browser without JS follows');
    });

    await t.test('a denied login still shows the local page, so the notice can be read', async () => {
        // Without this the instance would bounce straight back into the flow that just refused.
        await withForcedSso(async () => {
            const h = makeToolkit();
            await loginRoute.handler(makeRequest({ sso_denied: '1' }), h);

            assert.deepEqual(h.answers.redirects, []);
            assert.equal(h.answers.views[0].template, 'account/login');
        });
    });

    await t.test('a logout notice still shows the local page', async () => {
        await withForcedSso(async () => {
            const h = makeToolkit();
            await loginRoute.handler(makeRequest({ loggedout: '1' }), h);

            assert.equal(h.answers.views[0].template, 'account/login');
        });
    });

    await t.test('an unusable provider falls back to the local page rather than a dead hand-off', async () => {
        // Discovery failing must leave a way in, which is why forcing is gated on the provider
        // actually being usable rather than on the environment variable alone.
        await withForcedSso(async () => {
            const h = makeToolkit({ oidcUsable: false });
            await loginRoute.handler(makeRequest(), h);

            assert.deepEqual(h.answers.redirects, []);
            assert.equal(h.answers.views[0].template, 'account/login');
        });
    });

    await t.test('without forcing, the local page is served as before', async () => {
        const h = makeToolkit();
        await loginRoute.handler(makeRequest(), h);

        assert.equal(h.answers.views[0].template, 'account/login');
    });

    await t.test('an authenticated visitor is still redirected on, which no form submission reaches', async () => {
        // This redirect is same-origin, and a session that is already valid never produced the
        // login bounce in the first place.
        await withForcedSso(async () => {
            const h = makeToolkit();
            const request = makeRequest({ next: '/admin/webhooks' });
            request.auth = { isAuthenticated: true, artifacts: {} };

            await loginRoute.handler(request, h);

            assert.deepEqual(h.answers.redirects, ['/admin/webhooks']);
            assert.equal(h.answers.views.length, 0);
        });
    });
});
