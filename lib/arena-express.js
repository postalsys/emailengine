'use strict';

const arena = require('bull-arena');
const Bull = require('bull');
const express = require('express');
const { REDIS_PREFIX } = require('./consts');

const arenaExpress = (redisConf, basePath) => {
    basePath = (basePath || '').toString().replace(/^\/*/, '/');

    const app = express();
    const router = new express.Router();

    const bulUi = arena(
        {
            Bull,
            queues: [
                {
                    name: 'submit',
                    hostId: 'EmailEngine',
                    redis: redisConf,
                    prefix: `${REDIS_PREFIX}bull`
                },
                {
                    name: 'notify',
                    hostId: 'EmailEngine',
                    redis: redisConf,
                    prefix: `${REDIS_PREFIX}bull`
                }
            ]
        },
        {
            basePath,
            disableListen: true
        }
    );

    router.use((req, res, next) => {
        // rewrite base path
        req.url = basePath + (req.url || '').toString().replace(/^\/*/, '/');
        next();
    });

    router.use('/', bulUi);

    app.use(router);

    return { app, express };
};

module.exports.arenaExpress = arenaExpress;
