'use strict';

// Makes an API worker start asking for an admin login once an admin password exists.
//
// The worker that served the "set password" form switches its own session default on at once, and
// tells the others through the settings broadcast, the other instances of a cluster included
// (lib/cluster/bus.js). A broadcast can be missed, though: an instance disconnected from Redis at
// that moment, and the CLI (`emailengine password`) and EENGINE_PREPARED_PASSWORD write the password
// without any broadcast. Until the default is set, the worker serves /admin with no login. This
// check runs on a timer as well, so no path leaves a worker open for longer than the interval.

const DEFAULT_INTERVAL = 5000;

/**
 * @param {Object} opts
 * @param {Function} opts.getServer - The hapi server once its auth strategies are registered, else null
 * @param {Function} opts.isInstanceSecured - Resolves true once an admin password is set
 * @param {Object} opts.logger
 * @param {number} [opts.interval]
 * @returns {{ check: Function, stop: Function }}
 */
function createAdminAuthWatch({ getServer, isInstanceSecured, logger, interval = DEFAULT_INTERVAL }) {
    const check = async () => {
        const server = getServer();
        // hapi refuses a second default, which also means there is nothing left to do
        if (!server || server.auth.settings.default) {
            return false;
        }
        if (!(await isInstanceSecured())) {
            return false;
        }
        if (server.auth.settings.default) {
            return false;
        }
        server.auth.default('session');
        logger.info({ msg: 'Admin session authentication enabled after a password was set' });
        return true;
    };

    const timer = setInterval(() => {
        check().catch(err => logger.warn({ msg: 'Failed to check whether an admin password was set', err }));
    }, interval);
    timer.unref();

    return {
        check,
        stop() {
            clearInterval(timer);
        }
    };
}

module.exports = { createAdminAuthWatch };
