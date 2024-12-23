'use strict';

const config = require('wild-config');
const Hapi = require('@hapi/hapi');

const webhooks = new Map();

const server = Hapi.server({
    port: config.webhooksServer.port,
    host: '0.0.0.0'
});

server.route({
    method: 'POST',
    path: '/webhooks',
    handler: async (request, h) => {
        let account = request.payload.account || '';
        if (!webhooks.has(account)) {
            webhooks.set(account, []);
        }
        console.log('WEBHOOK', JSON.stringify(request.payload));
        webhooks.get(account).push(request.payload);
        return h.response('OK').code(200);
    }
});

const init = async () => {
    await server.start();
    console.log('Webhooks Server running on %s', server.info.uri);
};

module.exports = {
    init,
    webhooks,
    async quit() {
        await server.stop({ timeout: 5 * 1000 });
        console.log('Webhooks Server closed');
    }
};
