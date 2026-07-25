'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('@zone-eu/wild-config');
const pino = require('pino');
const { TRANSIENT_NETWORK_CODES } = require('./consts');

config.log = config.log || {
    level: 'trace'
};

config.log.level = config.log.level || 'trace';

// undici raises every connection failure as a generic `TypeError` (e.g. "fetch failed"
// or "terminated") with the real DNS/socket error attached as err.cause. Those are
// transient, environmental blips - not code bugs - so they must not be forwarded to
// error tracking, where they pile up as useless "fetch failed" reports. Genuine
// TypeError/RangeError bugs have no network errno cause and still get reported.
function isTransientFetchError(err) {
    return err && err.name === 'TypeError' && err.cause && TRANSIENT_NETWORK_CODES.has(err.cause.code);
}

let logger = pino({
    formatters: {
        log(object) {
            if (object.err && ['TypeError', 'RangeError'].includes(object.err.name) && !isTransientFetchError(object.err)) {
                if (logger.notifyError) {
                    let meta = {};
                    for (let key of ['msg', 'path', 'cid']) {
                        if (object[key]) {
                            meta[key] = object[key];
                        }
                    }
                    logger.notifyError(object.err, { user: object.account, meta });
                }
            }
            return object;
        }
    }
});
logger.level = process.env.EENGINE_LOG_LEVEL || config.log.level;

const { threadId } = require('worker_threads');

if (threadId) {
    logger = logger.child({ tid: threadId });
}

const FATAL_EXIT_CODES = {
    uncaughtException: 1,
    unhandledRejection: 2
};

// An error that reaches the global handlers leaves the process in an unknown state,
// so the process must always exit. If error tracking is enabled, report the error
// first and allow a short flush window for the delivery. The report is tagged with
// the handler that caught it because a crash carries no call site of its own - a
// bare socket error arrives with nothing but a `node:internal` frame, so without the
// tag there is no way to tell a dead worker apart from a handled error.
function fatalShutdown(handler, err) {
    if (logger.notifyError) {
        logger.notifyError(err, { level: 'fatal', tags: { handler } });
    }

    let exit = () => process.exit(FATAL_EXIT_CODES[handler]);
    if (logger.flushNotifications) {
        logger.flushNotifications().then(exit, exit);
    } else {
        setTimeout(exit, 10);
    }
}

process.on('uncaughtException', err => {
    logger.fatal({
        msg: 'uncaughtException',
        _msg: 'uncaughtException',
        err
    });

    fatalShutdown('uncaughtException', err);
});

process.on('unhandledRejection', err => {
    logger.fatal({
        msg: 'unhandledRejection',
        _msg: 'unhandledRejection',
        err
    });

    fatalShutdown('unhandledRejection', err);
});

module.exports = logger;
