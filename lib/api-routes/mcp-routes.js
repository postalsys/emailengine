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
const { isMcpEnabled, MCP_DISABLED_MESSAGE } = require('../mcp');
const { processMcpRequest, isAllowedOrigin, acceptsEventStream, rpcError, ERROR_CODES, serverInstructions } = require('../mcp/protocol');
const { getToolRegistry, callTool, listToolsFor } = require('../mcp/tools');
const { listResources, readResource } = require('../mcp/resources');
const { acceptFilter, openListenStream, canOpenListenStream, MAX_STREAMS_PER_CREDENTIAL } = require('../mcp/listen');

async function init(args) {
    const { server, CORS_CONFIG, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT } = args;

    // Build the registry once the route table is complete, rather than on the first request.
    // buildToolRegistry() throws on a duplicate tool name or a colliding argument source, and
    // those are wiring bugs that should stop the worker starting - lazily, the same throw became
    // a 500 on every tools/list and an empty catalog on the admin page instead. onPreStart runs
    // after every module has registered, which is why this cannot happen inline here.
    server.ext('onPreStart', () => {
        getToolRegistry(server);
    });

    server.route({
        method: 'POST',
        path: '/mcp',

        async handler(request, h) {
            // One read for both settings the handler needs; the deployment gate already decided
            // route registration, so only the runtime switch is checked here
            const stored = await settings.getMulti('mcpEnabled', 'serviceUrl');
            if (!stored.mcpEnabled) {
                throw Boom.notFound(MCP_DISABLED_MESSAGE);
            }

            const origin = request.headers.origin;
            if (origin && !isAllowedOrigin(origin, { serviceUrl: stored.serviceUrl, corsOrigins: (CORS_CONFIG && CORS_CONFIG.origin) || [] })) {
                return h.response(rpcError(null, ERROR_CODES.INVALID_REQUEST, 'Origin not allowed')).code(403);
            }

            const boundAccount = request.app.mcpBoundAccount;

            const ctx = {
                // A credential sees the surface it can actually use, so the agent does not plan
                // around tools that would only ever answer it with a 403: a bound credential
                // loses the instance-wide listings (list_accounts, get_outbox) and the `account`
                // argument of everything else, and a permission-narrowed token loses the tools
                // whose grant its record refuses - the same check the injected inner request
                // would enforce, asked ahead of time. Advertisement only: tools/call still
                // dispatches whatever is asked, and the inner request stays the enforcement.
                //
                // Auth mode is required and every strategy success path sets artifacts (the token
                // record, or {} for the preauth caller).
                listTools: () => listToolsFor(server, { tokenData: request.auth.artifacts, boundAccount }),

                callTool: async (name, toolArgs) => {
                    const tool = getToolRegistry(server).byName.get(name);
                    if (!tool) {
                        const err = new Error(`Unknown tool: ${name}. Call tools/list for the available tools`);
                        err.rpcCode = ERROR_CODES.INVALID_PARAMS;
                        throw err;
                    }
                    return callTool({ server, tool, args: toolArgs, request });
                },

                listResources: () => listResources({ server, request }),
                readResource: uri => readResource({ server, request, uri }),

                // An account-bound credential cannot list accounts and its tools carry no
                // account argument, so the opening line of the generic instructions - call
                // list_accounts, then pass the id - describes a workflow it cannot perform
                instructions: boundAccount ? serverInstructions(boundAccount) : undefined,

                acceptsEventStream: acceptsEventStream(request.headers.accept)
            };

            const outcome = await processMcpRequest({ body: request.payload, headers: request.headers, ctx });

            if (outcome.listen) {
                // Checked before the authorization fan-out below, so a client that is already at
                // its stream budget cannot spend the instance's Redis round trips discovering it
                if (!canOpenListenStream(request)) {
                    return h.response(
                        rpcError(
                            outcome.listen.id,
                            ERROR_CODES.INVALID_REQUEST,
                            `Too many open subscription streams for this credential (limit ${MAX_STREAMS_PER_CREDENTIAL}). Close one before opening another`
                        )
                    );
                }

                const accepted = await acceptFilter({ server, request, filter: outcome.listen.filter });
                return openListenStream({ h, request, subscriptionId: outcome.listen.id, accepted });
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
                throw Boom.notFound(MCP_DISABLED_MESSAGE);
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
