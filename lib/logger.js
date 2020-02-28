'use strict';

const config = require('wild-config');
let logger = require('pino')();
logger.level = config.log.level;

const { threadId } = require('worker_threads');

if (threadId) {
    logger = logger.child({ tid: threadId });
}

module.exports = logger;
