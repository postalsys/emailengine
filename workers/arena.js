'use strict';

const config = require('wild-config');

const arena = require('bull-arena');
const Bull = require('bull');
const express = require('express');
const logger = require('../lib/logger');
const packageData = require('../package.json');

const app = express();
const router = new express.Router();

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

config.arena = config.arena || {
    enabled: false,
    port: 3001,
    host: '127.0.0.1'
};

const REDIS_CONF_DEFAULT = process.env.EENGINE_REDIS || config.dbs.redis;

const REDIS_CONF =
    typeof REDIS_CONF_DEFAULT === 'string'
        ? {
              url: REDIS_CONF_DEFAULT
          }
        : REDIS_CONF_DEFAULT;

const ARENA_PORT = (process.env.EENGINE_ARENA_PORT && Number(process.env.EENGINE_ARENA_PORT)) || config.arena.port || 3001;
const ARENA_HOST = process.env.EENGINE_ARENA_HOST || config.arena.host || '127.0.0.1';

const bulUi = arena(
    {
        Bull,
        queues: [
            {
                name: 'submit',
                hostId: 'EmailEngine',
                redis: REDIS_CONF
            },
            {
                name: 'notify',
                hostId: 'EmailEngine',
                redis: REDIS_CONF
            }
        ]
    },
    {
        basePath: '/',
        disableListen: true
    }
);

let init = async () => {
    router.use('/', bulUi);

    app.use(router);

    return await new Promise((resolve, reject) => {
        app.once('error', err => reject(err));
        app.listen(ARENA_PORT, ARENA_HOST, () => {
            app.on('error', err => {
                logger.error({
                    msg: 'SMTP Server Error',
                    err
                });
            });
            resolve();
        });
    });
};

init()
    .then(() => {
        logger.debug({
            msg: 'Started Bull Arena server thread',
            port: ARENA_PORT,
            host: ARENA_HOST,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.error(err);
        setImmediate(() => process.exit(3));
    });
