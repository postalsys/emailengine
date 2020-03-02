'use strict';

const Hapi = require('@hapi/hapi');
const hapiPino = require('hapi-pino');

const init = async () => {
    const server = Hapi.server({
        port: 3080,
        host: 'localhost'
    });

    await server.register({
        plugin: hapiPino,
        options: {
            level: 'trace'
        }
    });

    server.route({
        method: 'GET',
        path: '/credentials',

        async handler(request) {
            switch (request.query.account) {
                case 'example':
                    return {
                        user: 'myuser2',
                        pass: 'verysecret'
                    };
            }

            return false;
        }
    });

    await server.start();
    console.log('Authentication Server URL: %s/credentials', server.info.uri);
};

init();
