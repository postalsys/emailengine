'use strict';

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
}

module.exports = server => {
    applyRoutes(server);
};
