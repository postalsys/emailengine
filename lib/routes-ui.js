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
const tlsConfigRoutes = require('./ui-routes/tls-config-routes');

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

    // TLS certificates: the configuration page, and the ACME challenge route the CA calls
    tlsConfigRoutes({ server, call });

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
}

module.exports = (...args) => {
    applyRoutes(...args);
};
