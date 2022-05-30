'use strict';

const arena = require('bull-arena');
const { Queue } = require('bullmq');
const express = require('express');
const { REDIS_PREFIX } = require('./consts');

const arenaExpress = (redisConf, basePath) => {
    basePath = (basePath || '').toString().replace(/^\/*/, '/');

    const app = express();
    const router = new express.Router();

    const bulUi = arena(
        {
            BullMQ: Queue,
            queues: [
                {
                    type: 'bullmq',
                    name: 'submit',
                    hostId: 'EmailEngine',
                    redis: redisConf,
                    prefix: `${REDIS_PREFIX}bull`
                },
                {
                    type: 'bullmq',
                    name: 'notify',
                    hostId: 'EmailEngine',
                    redis: redisConf,
                    prefix: `${REDIS_PREFIX}bull`
                },
                {
                    type: 'bullmq',
                    name: 'documents',
                    hostId: 'EmailEngine',
                    redis: redisConf,
                    prefix: `${REDIS_PREFIX}bull`
                }
            ],
            customCssPath: '/static/css/arena.css'
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
