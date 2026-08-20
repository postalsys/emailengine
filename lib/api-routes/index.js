'use strict';

// Single registration point for every REST API route module.
//
// workers/api.js used to inline this wiring, which meant nothing could enumerate the API surface
// without booting a Hapi server (the worker joins the worker-thread message port on require).
// The admin UI half already had this shape - lib/routes-ui.js is a plain module that
// test/helpers/capture-ui-routes.js can call against a mock server - and this brings the API half
// in line, so test/api-routes-table-test.js checks the REAL wiring instead of a hand-maintained
// mirror of it.
//
// Every module receives only the arguments it actually reads. Keep it that way: handing all of
// them the same bag hides which module depends on what, and hides it from the route-table test too.

const templateRoutes = require('./template-routes');
const chatRoutes = require('./chat-routes');
const accountRoutes = require('./account-routes');
const messageRoutes = require('./message-routes');
const exportRoutes = require('./export-routes');
const pubsubRoutes = require('./pubsub-routes');
const tokenRoutes = require('./token-routes');
const mailboxRoutes = require('./mailbox-routes');
const settingsRoutes = require('./settings-routes');
const statsRoutes = require('./stats-routes');
const licenseRoutes = require('./license-routes');
const outboxRoutes = require('./outbox-routes');
const webhookRouteRoutes = require('./webhook-route-routes');
const oauth2AppRoutes = require('./oauth2-app-routes');
const gatewayRoutes = require('./gateway-routes');
const deliveryTestRoutes = require('./delivery-test-routes');
const blocklistRoutes = require('./blocklist-routes');
const submitRoutes = require('./submit-routes');
const changesRoutes = require('./changes-routes');
const mcpRoutes = require('./mcp-routes');
const mcpOauthRoutes = require('./mcp-oauth-routes');

/**
 * Registers every /v1 route module on the supplied Hapi server.
 *
 * @param {Object} args
 * @param {Object} args.server - Hapi server (or a route-recording mock)
 * @param {Function} args.call - RPC helper for talking to the main thread
 * @param {Object} args.notify - notify (webhooks) BullMQ queue
 * @param {Object} args.documentsQueue - documents BullMQ queue
 * @param {Object} args.metrics - Prometheus metrics registry
 * @param {Object|Boolean} args.CORS_CONFIG
 * @param {Array} args.FLAG_SORT_ORDER
 * @param {String} args.SMTP_TEST_HOST
 * @param {Number} args.MAX_ATTACHMENT_SIZE
 * @param {Number} args.MAX_BODY_SIZE
 * @param {Number} args.MAX_PAYLOAD_TIMEOUT
 * @param {Boolean} args.documentStoreFeatureEnabled - gate for the deprecated Document Store
 * @param {Boolean} args.mcpFeatureEnabled - gate for the MCP endpoint
 * @param {Object} args.oauth2Schema
 * @param {Object} args.imapSchema
 * @param {Object} args.smtpSchema
 * @param {Object} args.AccountTypeSchema
 * @param {Object} args.OAuth2ProviderSchema
 */
async function registerApiRoutes(args) {
    const {
        server,
        call,
        notify,
        documentsQueue,
        metrics,
        CORS_CONFIG,
        FLAG_SORT_ORDER,
        SMTP_TEST_HOST,
        MAX_ATTACHMENT_SIZE,
        MAX_BODY_SIZE,
        MAX_PAYLOAD_TIMEOUT,
        documentStoreFeatureEnabled,
        mcpFeatureEnabled,
        oauth2Schema,
        imapSchema,
        smtpSchema,
        AccountTypeSchema,
        OAuth2ProviderSchema
    } = args;

    // setup template routes
    await templateRoutes({ server, call, CORS_CONFIG });

    // setup "chat with email" routes (deprecated Document Store feature; only when enabled)
    if (documentStoreFeatureEnabled) {
        await chatRoutes({ server, call, CORS_CONFIG });
    }

    // setup account CRUD routes
    await accountRoutes({
        server,
        call,
        documentsQueue,
        oauth2Schema,
        imapSchema,
        smtpSchema,
        CORS_CONFIG,
        AccountTypeSchema,
        OAuth2ProviderSchema,
        metrics
    });

    // setup message routes
    await messageRoutes({
        server,
        call,
        CORS_CONFIG,
        MAX_ATTACHMENT_SIZE,
        MAX_BODY_SIZE,
        MAX_PAYLOAD_TIMEOUT,
        documentStoreFeatureEnabled
    });

    // setup export routes
    await exportRoutes({
        server,
        CORS_CONFIG
    });

    // setup Pub/Sub status route
    await pubsubRoutes({ server, CORS_CONFIG });

    // setup access token routes
    await tokenRoutes({ server, call, CORS_CONFIG });

    // setup mailbox routes
    await mailboxRoutes({ server, call, CORS_CONFIG, FLAG_SORT_ORDER });

    // setup settings routes
    await settingsRoutes({ server, notify, CORS_CONFIG });

    // setup stats route
    await statsRoutes({ server, call, CORS_CONFIG });

    // setup license routes
    await licenseRoutes({ server, call, CORS_CONFIG });

    // setup outbox routes
    await outboxRoutes({ server, CORS_CONFIG });

    // setup webhook route management routes
    await webhookRouteRoutes({ server, CORS_CONFIG });

    // setup OAuth2 application routes
    await oauth2AppRoutes({ server, call, CORS_CONFIG, OAuth2ProviderSchema });

    // setup SMTP gateway routes
    await gatewayRoutes({ server, call, CORS_CONFIG });

    // setup delivery test routes
    await deliveryTestRoutes({ server, call, CORS_CONFIG, SMTP_TEST_HOST });

    // setup blocklist routes
    await blocklistRoutes({ server, call, CORS_CONFIG });

    // setup message submit route
    await submitRoutes({ server, call, CORS_CONFIG, MAX_ATTACHMENT_SIZE, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT });

    // setup the account state change stream (SSE)
    await changesRoutes({ server, CORS_CONFIG });

    // setup the MCP endpoint and its OAuth discovery/registration/token routes (only when the
    // deployment gate is on; the OAuth routes additionally answer 404 until the mcpOAuthEnabled
    // setting is turned on)
    if (mcpFeatureEnabled) {
        await mcpRoutes({ server, CORS_CONFIG, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT });
        await mcpOauthRoutes({ server });
    }
}

module.exports = registerApiRoutes;
