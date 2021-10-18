'use strict';

const consts = require('./consts');
const settings = require('./settings');

const notificationTypes = Object.keys(consts)
    .map(key => {
        if (/_NOTIFY$/.test(key)) {
            return key.replace(/_NOTIFY$/, '');
        }
        return false;
    })
    .filter(key => key)
    .map(key => ({
        key,
        name: consts[`${key}_NOTIFY`],
        description: consts[`${key}_DESCRIPTION`]
    }));

function applyRoutes(server) {
    server.route({
        method: 'GET',
        path: '/profile',
        async handler(request, h) {
            return h.view(
                'example',
                {
                    mainMenuProfile: true,
                    sectionProfileIndex: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/config/webhooks',
        async handler(request, h) {
            console.log(notificationTypes);

            let values = {
                webhooksEnabled: (await settings.get('webhooksDisabled')) ? false : true,
                webhooks: (await settings.get('webhooks')) || ''
            };

            console.log(values);

            return h.view(
                'config/webhooks',
                {
                    menuConfig: true,
                    menuConfigWebhooks: true,

                    notificationTypes,

                    values
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/config/webhooks',
        async handler(request, h) {
            console.log(request.body);
            return h.view(
                'config/webhooks',
                {
                    menuConfig: true,
                    menuConfigWebhooks: true,

                    notificationTypes
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/config/logs',
        async handler(request, h) {
            return h.view(
                'example',
                {
                    menuConfig: true,
                    menuConfigLogs: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });
}

module.exports = server => {
    applyRoutes(server);
};
