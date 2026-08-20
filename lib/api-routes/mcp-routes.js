'use strict';

// The MCP (Model Context Protocol) endpoint: a single stateless JSON-RPC-over-POST route, per
// the Streamable HTTP transport of protocol revision 2026-07-28, plus the sessionless subset of
// the 2025-06-18/2025-11-25 revisions for clients that still open with `initialize`.
//
// Registered from lib/api-routes/index.js like every other API route so the route-table
// guardrail sees it. Tagged `external` (skips the CSRF crumb, stays out of /swagger.json - the
// endpoint speaks JSON-RPC, not REST, so it has no OpenAPI operation) plus the two scopes it
// admits (see the tags below).
//
// The api-token strategy treats this route specially in three documented ways (see the
// mcpOptions() handling in workers/api.js): the token-permission check and the audit row are
// deferred to the injected inner request, whose routeGrant() names the real operation, and an
// account-bound token is admitted at the door with its binding parked on
// request.app.mcpBoundAccount - binding enforcement too happens on the inner request, which
// actually names an account.

const Boom = require('@hapi/boom');

const settings = require('../settings');
const { isMcpEnabled } = require('../mcp');
const { processMcpRequest, isAllowedOrigin, rpcError, ERROR_CODES, SERVER_INSTRUCTIONS } = require('../mcp/protocol');
const { buildToolRegistry, callTool } = require('../mcp/tools');
const { listResources, readResource } = require('../mcp/resources');
const { acceptFilter, openListenStream } = require('../mcp/listen');

const ACCEPTS_EVENT_STREAM = /(^|[,\s])(text\/event-stream|\*\/\*)\s*(;|,|$)/i;

async function init(args) {
    const { server, CORS_CONFIG, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT } = args;

    // Derived from server.table() on first use and held for the life of the worker, like the
    // OpenAPI document: route definitions cannot change while the worker runs. Cannot be built
    // at registration time - the other route modules may not have registered yet.
    let registry;
    const getRegistry = () => {
        if (!registry) {
            registry = buildToolRegistry(server.table());
        }
        return registry;
    };

    server.route({
        method: 'POST',
        path: '/mcp',

        async handler(request, h) {
            // One read for both settings the handler needs; the deployment gate already decided
            // route registration, so only the runtime switch is checked here
            const stored = await settings.getMulti('mcpEnabled', 'serviceUrl');
            if (!stored.mcpEnabled) {
                throw Boom.notFound('MCP support is not enabled');
            }

            const origin = request.headers.origin;
            if (origin && !isAllowedOrigin(origin, { serviceUrl: stored.serviceUrl, corsOrigins: (CORS_CONFIG && CORS_CONFIG.origin) || [] })) {
                return h.response(rpcError(null, ERROR_CODES.INVALID_REQUEST, 'Origin not allowed')).code(403);
            }

            const boundAccount = request.app.mcpBoundAccount;

            const ctx = {
                // A bound credential sees the surface it can actually use: tools that take an
                // account argument. The instance-wide listings (list_accounts, get_outbox) would
                // only ever answer it with the 403 the binding enforces.
                listTools: () => {
                    const { tools, byName } = getRegistry();
                    return boundAccount ? tools.filter(tool => byName.get(tool.name).sources.has('account')) : tools;
                },

                callTool: async (name, toolArgs) => {
                    const tool = getRegistry().byName.get(name);
                    if (!tool) {
                        const err = new Error(`Unknown tool: ${name}`);
                        err.rpcCode = ERROR_CODES.INVALID_PARAMS;
                        throw err;
                    }
                    return callTool({ server, tool, args: toolArgs, request });
                },

                listResources: () => listResources({ server, request }),
                readResource: uri => readResource({ server, request, uri }),

                // An account-bound credential cannot list accounts, so tell the agent its id up
                // front instead of letting it look for a listing tool
                instructions: boundAccount
                    ? `${SERVER_INSTRUCTIONS} This credential is bound to the account '${boundAccount}' - always pass that as the account argument.`
                    : undefined,

                acceptsEventStream: ACCEPTS_EVENT_STREAM.test(request.headers.accept || '')
            };

            const outcome = await processMcpRequest({ body: request.payload, headers: request.headers, ctx });

            if (outcome.listen) {
                const accepted = await acceptFilter({ server, request, filter: outcome.listen.filter });
                return openListenStream({ h, subscriptionId: outcome.listen.id, accepted });
            }

            if (!outcome.body) {
                return h.response().code(outcome.httpStatus);
            }

            return h.response(outcome.body).code(outcome.httpStatus);
        },

        options: {
            description: 'MCP endpoint',
            notes: ['JSON-RPC endpoint implementing the Model Context Protocol Streamable HTTP transport'],

            // `external`: no CSRF crumb and no OpenAPI operation. Two scopes: `api` tokens can
            // do over MCP whatever they can do over REST, and `mcp` tokens are surface-bound
            // credentials this endpoint admits and plain REST refuses (see the scope check in
            // workers/api.js).
            tags: ['external', 'scope:api', 'scope:mcp'],

            plugins: {
                mcp: { endpoint: true }
            },

            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT,
                allow: ['application/json'],
                parse: true
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG
        }
    });

    // The modern revision removed the standalone GET notification stream and protocol sessions;
    // 405 on GET and DELETE is the spec-prescribed answer to older clients probing for them,
    // and it is also what tells a dual-era client this is not a 2024-11-05 HTTP+SSE server.
    server.route({
        method: ['GET', 'DELETE'],
        path: '/mcp',

        async handler(request, h) {
            if (!(await isMcpEnabled())) {
                throw Boom.notFound('MCP support is not enabled');
            }

            return h.response().code(405).header('Allow', 'POST');
        },

        options: {
            description: 'MCP endpoint method guard',
            tags: ['external'],
            auth: false,
            cors: CORS_CONFIG
        }
    });
}

module.exports = init;
