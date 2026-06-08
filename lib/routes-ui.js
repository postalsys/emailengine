'use strict';

// NB! This file is processed by gettext parser and can not use newer syntax like ?.

const adminEntitiesRoutes = require('./ui-routes/admin-entities-routes');
const smtpTestRoutes = require('./ui-routes/smtp-test-routes');
const unsubscribeRoutes = require('./ui-routes/unsubscribe-routes');
const internalsRoutes = require('./ui-routes/internals-routes');
const dashboardRoutes = require('./ui-routes/dashboard-routes');
const exportRoutes = require('./ui-routes/export-routes');
const networkConfigRoutes = require('./ui-routes/network-config-routes');
const documentStoreRoutes = require('./ui-routes/document-store-routes');
const authRoutes = require('./ui-routes/auth-routes');
const oauthConfigRoutes = require('./ui-routes/oauth-config-routes');
const adminConfigRoutes = require('./ui-routes/admin-config-routes');
const accountRoutes = require('./ui-routes/account-routes');

function applyRoutes(server, call) {
    // Initialize admin entity routes (webhooks, templates, gateways, tokens)
    adminEntitiesRoutes({ server, call });

    // SMTP deliverability test tool routes
    smtpTestRoutes({ server, call });

    // Public subscription-management (unsubscribe) routes
    unsubscribeRoutes({ server, call });

    // System internals / threads tools routes
    internalsRoutes({ server, call });

    // Dashboard and standalone informational pages (swagger, legal, upgrade)
    dashboardRoutes({ server, call });

    // Account data export routes
    exportRoutes({ server });

    // Network, SMTP server, IMAP proxy, and browser config routes
    networkConfigRoutes({ server, call });

    // Document Store (Elasticsearch) config routes
    documentStoreRoutes({ server });

    // Admin auth and user-profile routes (login, logout, TOTP, passkeys, password)
    authRoutes({ server });

    // OAuth2 application config routes
    oauthConfigRoutes({ server, call });

    // Webhooks, service, AI, logging, and license config routes
    adminConfigRoutes({ server, call });

    // Account management routes (listing, add-account wizard, per-account view/edit/logs/browse)
    accountRoutes({ server, call });

    server.route({
        method: 'GET',
        path: '/.well-known/acme-challenge/{token}',
        async handler(request, h) {
            let domain = (request.headers.host || '').toString().replace(/:.*$/g, '').trim().toLowerCase();

            let challenge;
            try {
                challenge = await h.certs.routeHandler(domain, request.params.token);
                if (!challenge) {
                    throw new Error('Challenge not found for the provided token and domain');
                }
            } catch (err) {
                return h
                    .response(
                        `Request failed: ${err.message}
Domain: ${JSON.stringify(domain)}
Token: ${JSON.stringify(request.params.token)}`
                    )
                    .type('text/plain')
                    .code(err.statusCode || 500);
            }

            const response = h.response('success');
            response.type('text/plain');

            return challenge;
        },

        options: {
            auth: false
        }
    });
}

module.exports = (...args) => {
    applyRoutes(...args);
};
