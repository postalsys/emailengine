'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('@zone-eu/wild-config');
const pino = require('pino');

config.log = config.log || {
    level: 'trace'
};

config.log.level = config.log.level || 'trace';

let logger = pino({
    formatters: {
        log(object) {
            if (object.err && ['TypeError', 'RangeError'].includes(object.err.name)) {
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

// An error that reaches the global handlers leaves the process in an unknown state,
// so the process must always exit. If error tracking is enabled, report the error
// first and allow a short flush window for the delivery.
function fatalShutdown(code, err) {
    if (logger.notifyError) {
        logger.notifyError(err);
    }

    let exit = () => process.exit(code);
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

    fatalShutdown(1, err);
});

process.on('unhandledRejection', err => {
    logger.fatal({
        msg: 'unhandledRejection',
        _msg: 'unhandledRejection',
        err
    });

    fatalShutdown(2, err);
});

module.exports = logger;
