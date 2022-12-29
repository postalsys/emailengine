'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('wild-config');
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
                    logger.notifyError(object.err, event => {
                        if (object.account) {
                            event.setUser(object.account);
                        }
                        let meta = {};
                        let hasMeta = false;
                        for (let key of ['msg', 'path', 'cid']) {
                            if (object[key]) {
                                meta[key] = object[key];
                                hasMeta = true;
                            }
                        }
                        if (hasMeta) {
                            event.addMetadata('ee', meta);
                        }
                    });
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

process.on('uncaughtException', err => {
    logger.fatal({
        msg: 'uncaughtException',
        _msg: 'uncaughtException',
        err
    });

    if (!logger.notifyError) {
        setTimeout(() => process.exit(1), 10);
    }
});

process.on('unhandledRejection', err => {
    logger.fatal({
        msg: 'unhandledRejection',
        _msg: 'unhandledRejection',
        err
    });

    if (!logger.notifyError) {
        setTimeout(() => process.exit(2), 10);
    }
});

module.exports = logger;
