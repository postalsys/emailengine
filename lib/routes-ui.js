'use strict';

const adminEntitiesRoutes = require('./ui-routes/admin-entities-routes');
const smtpTestRoutes = require('./ui-routes/smtp-test-routes');
const unsubscribeRoutes = require('./ui-routes/unsubscribe-routes');
const suppressionListRoutes = require('./ui-routes/suppression-list-routes');
const internalsRoutes = require('./ui-routes/internals-routes');
const dashboardRoutes = require('./ui-routes/dashboard-routes');
const referenceRoutes = require('./ui-routes/reference-routes');
const exportRoutes = require('./ui-routes/export-routes');
const networkConfigRoutes = require('./ui-routes/network-config-routes');
const documentStoreRoutes = require('./ui-routes/document-store-routes');
const authRoutes = require('./ui-routes/auth-routes');
const oauthConfigRoutes = require('./ui-routes/oauth-config-routes');
const adminConfigRoutes = require('./ui-routes/admin-config-routes');
const accountRoutes = require('./ui-routes/account-routes');
const mcpConsentRoutes = require('./ui-routes/mcp-consent-routes');

function applyRoutes(server, call) {
    // Initialize admin entity routes (webhooks, templates, gateways, tokens)
    adminEntitiesRoutes({ server, call });

    // SMTP deliverability test tool routes
    smtpTestRoutes({ server, call });

    // Public subscription-management (unsubscribe) routes
    unsubscribeRoutes({ server, call });

    // Suppression list management (the store behind the Blocklists API)
    suppressionListRoutes({ server });

    // System internals / threads tools routes
    internalsRoutes({ server, call });

    // Dashboard and standalone informational pages (legal, upgrade)
    dashboardRoutes({ server, call });

    // Server-rendered API reference, plus the /admin/swagger redirect it replaced
    referenceRoutes({ server });

    // Account data export routes
    exportRoutes({ server });

    // Network, SMTP server, IMAP proxy, and browser config routes
    networkConfigRoutes({ server, call });

    // Document Store (Elasticsearch) config routes (deprecated feature; the module self-gates
    // and registers no routes unless the Document Store feature is enabled)
    documentStoreRoutes({ server });

    // Admin auth and user-profile routes (login, logout, TOTP, passkeys, password)
    authRoutes({ server });

    // OAuth2 application config routes
    oauthConfigRoutes({ server, call });

    // Webhooks, service, AI, logging, and license config routes
    adminConfigRoutes({ server, call });

    // Account management routes (listing, add-account wizard, per-account view/edit/logs/browse)
    accountRoutes({ server, call });

    // MCP OAuth consent page (self-gates on the MCP feature flag, like the Document Store module)
    mcpConsentRoutes({ server, call });

    server.route({
        method: 'GET',
        path: '/.well-known/acme-challenge/{token}',
        async handler(request, h) {
            let domain = (request.headers.host || '').toString().replace(/:.*$/g, '').trim().toLowerCase();

            let challenge;
            try {
                // Resolves to the key authorization or throws with a responseCode; it has no third
                // answer, so there is nothing to check the result for.
                challenge = await h.certs.routeHandler(domain, request.params.token);
            } catch (err) {
                // routeHandler() reports the status as responseCode, so reading statusCode turned
                // an unknown token into a 500 rather than the 404 it is
                return h
                    .response(
                        `Request failed: ${err.message}
Domain: ${JSON.stringify(domain)}
Token: ${JSON.stringify(request.params.token)}`
                    )
                    .type('text/plain')
                    .code(err.responseCode || 500);
            }

            // RFC 8555 section 8.3: the key authorization is the whole body, compared byte for byte
            return h.response(challenge).type('application/octet-stream');
        },

        options: {
            auth: false
        }
    });
}

module.exports = (...args) => {
    applyRoutes(...args);
};
