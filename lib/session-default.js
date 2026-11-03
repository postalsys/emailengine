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

module.exports = { requireSessionOnceSecured };
