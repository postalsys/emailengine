'use strict';

// Makes an API worker ask for an admin login as soon as an admin password exists.
//
// workers/api.js sets the session strategy as the server default at startup when a password is
// already stored, and the worker that serves the "set password" form sets it in-process and
// broadcasts the change to the other API workers. The CLI (`emailengine password`) writes the
// password straight into Redis, with no broadcast, so a running worker kept serving /admin with no
// login until it was restarted. Checking before authentication closes that gap from the first
// request that would have got through. Setting the default rebuilds every route's lifecycle, but the
// request already running keeps the one it started with, which has no authentication step, so that
// one request is sent back to its own URL (307, which a browser repeats with the same method and
// body) and runs again with authentication.

/**
 * Registers an onPreAuth extension that sets the session strategy as the default once a password is
 * stored. Only a request that would use the default asks Redis, and only until the default is set
 * @param {Object} opts
 * @param {Object} opts.server - hapi server, with the session strategy registered
 * @param {Function} opts.isInstanceSecured - Resolves true once an admin password is set
 * @param {Object} opts.logger
 */
function requireSessionOnceSecured({ server, isInstanceSecured, logger }) {
    server.ext('onPreAuth', async (request, h) => {
        if (server.auth.settings.default || request.route.settings.auth !== undefined) {
            return h.continue;
        }
        if (!(await isInstanceSecured())) {
            return h.continue;
        }
        // hapi refuses a second default, and a concurrent request may have set it meanwhile
        if (!server.auth.settings.default) {
            server.auth.default('session');
            logger.info({ msg: 'Admin session authentication enabled after a password was set' });
        }
        // Leading slashes collapsed, so a path like //host cannot become a protocol-relative Location
        const location = '/' + request.url.pathname.replace(/^\/+/, '') + request.url.search;
        return h.redirect(location).code(307).takeover();
    });
}

// Route paths a session that has passed the password step but not yet the second factor may reach.
// Every other route sends such a session to the TOTP prompt (registerTotpExtension() in
// workers/api.js). The login and TOTP pages have to be here or the prompt could never be answered,
// the passkey login endpoints because a passkey is a factor of its own, and the catch-all 404 so a
// mistyped URL does not bounce. The device-bound session refresh is here because the browser
// ignores a redirect there, and a session that has not passed its second factor has no binding
// for it to renew anyway (lib/dbsc answers that itself). test/admin-auth-guardrail-test.js checks
// every entry against the route table, so a renamed route cannot leave a stale entry that silently
// drops the exemption.
const TOTP_EXEMPT_PATHS = Object.freeze([
    '/{any*}',
    '/admin/totp',
    '/admin/login',
    '/admin/passkey/auth/options',
    '/admin/passkey/auth/verify',
    '/admin/dbsc/refresh'
]);

module.exports = { requireSessionOnceSecured, TOTP_EXEMPT_PATHS };
