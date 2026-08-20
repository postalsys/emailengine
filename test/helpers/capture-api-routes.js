'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): captures every route the
// REST API registers, together with the security-relevant slice of each route's config (auth
// strategy, auth mode, tag list).
//
// This calls the REAL wiring - lib/api-routes/index.js, the same function workers/api.js invokes
// - against a bare mock Hapi server, so there is no module list to keep in sync. Route
// registration is synchronous and never touches Redis or the `call` RPC (handlers reference
// external state only inside their never-executed closures), so the mock is sufficient.
//
// Mirrors test/helpers/capture-ui-routes.js, which does the same for lib/routes-ui.js.

const { imapSchema, smtpSchema, oauth2Schema, oauth2ProviderSchema, accountTypeSchema } = require('../../lib/schemas');
const { DEFAULT_MAX_ATTACHMENT_SIZE, DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_PAYLOAD_TIMEOUT } = require('../../lib/consts');
const registerApiRoutes = require('../../lib/api-routes');
const { routeKey } = require('../../lib/api-routes/permission-map');

// Stand-ins for the values workers/api.js passes in. Only shape matters: these are read at
// registration time to build Joi schemas and payload limits, never dereferenced deeply.
function buildMockArgs(server, overrides) {
    const noopQueue = { add: async () => ({}), getJob: async () => null, on: () => {}, off: () => {} };

    return Object.assign(
        {
            server,
            call: async () => ({}),
            // A FUNCTION, matching workers/api.js: `notify` is the async postMessage helper the
            // route modules call as notify('settings', payload), not a BullMQ queue. Handing a
            // queue-shaped object to the mock invites a maintainer to "fix" production by passing
            // notifyQueue instead, which would break the settings fanout with nothing failing here.
            notify: async () => {},
            documentsQueue: noopQueue,
            metrics: {},

            CORS_CONFIG: false,
            FLAG_SORT_ORDER: ['\\Inbox', '\\Flagged', '\\Sent', '\\Drafts', '\\All', '\\Archive', '\\Junk', '\\Trash'],
            SMTP_TEST_HOST: 'https://api.nodemailer.com',
            // The shipped defaults, not round numbers: these end up as `maxLength` in the generated
            // OpenAPI document, so a made-up value here would record a document no instance serves
            MAX_ATTACHMENT_SIZE: DEFAULT_MAX_ATTACHMENT_SIZE,
            MAX_BODY_SIZE: DEFAULT_MAX_BODY_SIZE,
            MAX_PAYLOAD_TIMEOUT: DEFAULT_MAX_PAYLOAD_TIMEOUT,
            // Defaults to the deprecated Document Store gate ON, so its endpoints appear in the
            // table. The gate is a plain argument here (not an env read at module load like the
            // UI side), so the off state is captured by passing it in - no child process needed.
            documentStoreFeatureEnabled: true,
            // The MCP gate defaults on (it ships enabled in config/default.toml), so the golden
            // table includes the /mcp routes; the gate-off state is captured explicitly in
            // test/api-routes-table-test.js
            mcpFeatureEnabled: true,

            // Plain Joi key maps (not compiled schemas) - the route modules wrap them in Joi.object()
            oauth2Schema,
            imapSchema,
            smtpSchema,
            // The real schemas, not stand-ins: they carry the provider list into the generated
            // OpenAPI document, so a simplified copy here would make the recorded document differ
            // from the one the server serves
            AccountTypeSchema: accountTypeSchema,
            OAuth2ProviderSchema: oauth2ProviderSchema
        },
        overrides || {}
    );
}

// Reduces a registered route config to the fields this guardrail cares about.
function describeRoute(cfg, method) {
    const options = cfg.options || cfg.config || {};
    const auth = options.auth;

    return {
        route: routeKey(method, cfg.path),
        path: cfg.path,
        method: String(method).toLowerCase(),
        // Undefined when the route declares no auth at all - it then inherits
        // server.auth.default(), which for a /v1 route is never what you want.
        authStrategy: auth && typeof auth === 'object' ? auth.strategy : undefined,
        authMode: auth && typeof auth === 'object' ? auth.mode : undefined,
        tags: options.tags || [],
        // The request-body schema as registered, so a guardrail can ask what fields a route accepts
        // rather than reading the route modules by hand. Undefined for routes that take no payload.
        payload: options.validate && options.validate.payload,
        // Shaped the way a live request.route is, so the described route can be handed straight to
        // routeGrant() - and to buildToolRegistry() in lib/mcp/tools.js, which reads the joi
        // validation schemas and the route description the same way it does off server.table()
        settings: { plugins: options.plugins || {}, validate: options.validate || {}, description: options.description }
    };
}

/**
 * Registers the real API route table against a mock server and reports what it did.
 *
 * @param {Object} [overrides] - args passed to registerApiRoutes(), e.g. documentStoreFeatureEnabled
 * @returns {Object} { routes, registeredPlugins } - the described routes, and the names of any
 *                   plugins registered during route setup. Plugin-registered routes never reach
 *                   server.route() on this mock, so they would be invisible to the auth and tag
 *                   assertions; the caller asserts the list stays empty rather than letting a
 *                   future plugin quietly opt out of the guardrail.
 */
async function captureApiRoutes(overrides) {
    const routes = [];
    const registeredPlugins = [];

    const record = cfg => {
        if (Array.isArray(cfg)) {
            cfg.forEach(record);
            return;
        }
        const methods = Array.isArray(cfg.method) ? cfg.method : [cfg.method];
        for (const method of methods) {
            routes.push(describeRoute(cfg, method));
        }
    };

    const recordPlugin = registration => {
        for (const entry of [].concat(registration || [])) {
            const plugin = (entry && entry.plugin) || entry;
            registeredPlugins.push((plugin && (plugin.name || (plugin.pkg && plugin.pkg.name))) || 'unnamed plugin');
        }
    };

    const mockServer = new Proxy(
        {
            route: record,
            register: recordPlugin,
            auth: { settings: { default: null }, default() {} }
        },
        {
            get(target, prop) {
                if (prop in target) {
                    return target[prop];
                }
                return () => {};
            }
        }
    );

    await registerApiRoutes(buildMockArgs(mockServer, overrides));

    return { routes, registeredPlugins };
}

module.exports = { captureApiRoutes, buildMockArgs };
