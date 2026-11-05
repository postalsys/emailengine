'use strict';

// The two endpoints of device-bound admin sessions (lib/dbsc/). The browser calls both on its own,
// not a page, which is why neither carries a crumb: what stands in for one is a signature over a
// challenge only this server issued, to this session, minutes ago.

const { REGISTRATION_PATH, REFRESH_PATH } = require('../dbsc/protocol');

/**
 * The handlers find the DBSC instance on server.app, where workers/api.js publishes it with the
 * session strategy (setupDbsc() in lib/dbsc), so registration needs nothing but the server
 * @param {Object} args
 * @param {Object} args.server - hapi server
 */
function init(args) {
    const { server } = args;

    server.route({
        method: 'POST',
        path: REGISTRATION_PATH,
        // The default session strategy: only a signed-in admin session can bind itself
        handler: (request, h) => request.server.app.dbsc.register(request, h),
        options: {
            plugins: { crumb: false }
        }
    });

    server.route({
        method: 'POST',
        path: REFRESH_PATH,
        // Reads the session without requiring it. The browser acts on the status of this answer, and
        // the redirect to the login page a required session would produce is one it ignores, so an
        // ended session has to be told so in a body it understands instead
        handler: (request, h) => request.server.app.dbsc.refresh(request, h),
        options: {
            auth: { strategy: 'session', mode: 'try' },
            // dbsc.enforce: false - a missing bound cookie is what this route renews
            plugins: { crumb: false, dbsc: { enforce: false } }
        }
    });
}

module.exports = init;
