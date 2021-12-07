'use strict';

const arena = require('bull-arena');
const Bull = require('bull');
const express = require('express');

const arenaExpress = (redisConf, basePath) => {
    basePath = (basePath || '').toString().replace(/^\/*/, '/');

    let parsedUrl;
    if (typeof redisConf === 'string') {
        parsedUrl = new URL(redisConf);
        if (parsedUrl.port) {
            parsedUrl.port = Number(parsedUrl.port);
        }
        let pathname = parsedUrl.pathname.slice(1);
        if (pathname && !isNaN(pathname)) {
            parsedUrl.db = Number(pathname);
        }
    }

    const bullRedisConf = typeof redisConf === 'string' ? parsedUrl : redisConf;

    const app = express();
    const router = new express.Router();

    const bulUi = arena(
        {
            Bull,
            queues: [
                {
                    name: 'submit',
                    hostId: 'EmailEngine',
                    redis: bullRedisConf
                },
                {
                    name: 'notify',
                    hostId: 'EmailEngine',
                    redis: bullRedisConf
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
