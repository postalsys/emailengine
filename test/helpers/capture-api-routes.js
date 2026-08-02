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

const Joi = require('joi');
const { imapSchema, smtpSchema, oauth2Schema } = require('../../lib/schemas');
const registerApiRoutes = require('../../lib/api-routes');

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
            MAX_ATTACHMENT_SIZE: 25 * 1024 * 1024,
            MAX_BODY_SIZE: 25 * 1024 * 1024,
            MAX_PAYLOAD_TIMEOUT: 10 * 1000,
            // Defaults to the deprecated Document Store gate ON, so its endpoints appear in the
            // table. The gate is a plain argument here (not an env read at module load like the
            // UI side), so the off state is captured by passing it in - no child process needed.
            documentStoreFeatureEnabled: true,

            // Plain Joi key maps (not compiled schemas) - the route modules wrap them in Joi.object()
            oauth2Schema,
            imapSchema,
            smtpSchema,
            AccountTypeSchema: Joi.string().empty('').allow(false).default(false).example('imap').label('AccountType'),
            OAuth2ProviderSchema: Joi.string().empty('').max(256).example('gmail').label('OAuth2Provider')
        },
        overrides || {}
    );
}

// Reduces a registered route config to the fields this guardrail cares about.
function describeRoute(cfg, method) {
    const options = cfg.options || cfg.config || {};
    const auth = options.auth;

    return {
        route: `${String(method).toUpperCase()} ${cfg.path}`,
        path: cfg.path,
        // Undefined when the route declares no auth at all - it then inherits
        // server.auth.default(), which for a /v1 route is never what you want.
        authStrategy: auth && typeof auth === 'object' ? auth.strategy : undefined,
        authMode: auth && typeof auth === 'object' ? auth.mode : undefined,
        tags: options.tags || []
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
