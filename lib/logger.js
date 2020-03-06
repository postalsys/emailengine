'use strict';

const config = require('wild-config');
const pino = require('pino');

let logger = pino();
logger.level = config.log.level;

const { threadId } = require('worker_threads');

if (threadId) {
    logger = logger.child({ tid: threadId });
}

process.on('uncaughtException', err => {
    logger.fatal({
        msg: 'uncaughtException',
        err
    });
    process.exit(1);
});

process.on('unhandledRejection', err => {
    logger.fatal({
        msg: 'unhandledRejection',
        err
    });
    process.exit(1);
});

module.exports = logger;
