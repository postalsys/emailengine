'use strict';

// The MCP wire protocol: JSON-RPC parsing, protocol version negotiation and method dispatch for
// the /mcp endpoint. Transport-independent on purpose - nothing in here touches Hapi, Redis or
// streams, so the whole state machine is unit-testable (test/mcp-protocol-test.js). The route
// handler in lib/api-routes/mcp-routes.js owns HTTP concerns: auth ran before this is called,
// and the {httpStatus, body} / {listen} descriptors returned here are rendered there.
//
// Two protocol eras are served on the same endpoint, per the dual-era server rules in the MCP
// spec (Versioning and Compatibility, revision 2026-07-28):
//
//   - Modern (2026-07-28): every request carries its protocol version in
//     params._meta['io.modelcontextprotocol/protocolVersion'], mirrored into the
//     MCP-Protocol-Version header, plus Mcp-Method / Mcp-Name routing headers that MUST match
//     the body. There is no handshake and no session. Results carry resultType: 'complete'.
//
//   - Legacy (2025-06-18, 2025-11-25): the client opens with an `initialize` request and then
//     names the negotiated version in the MCP-Protocol-Version header. This server is
//     stateless, which the legacy revisions explicitly permit: no Mcp-Session-Id is minted, and
//     the standalone GET notification stream is answered with 405 by the route.
//
// JSON-RPC batching is rejected: it only ever existed in revision 2025-03-26, which is not
// supported here.

const packageData = require('../../package.json');
const { COLLAPSE_CLASS } = require('../consts');

const MODERN_PROTOCOL_VERSION = '2026-07-28';
const LEGACY_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18'];
const SUPPORTED_PROTOCOL_VERSIONS = [MODERN_PROTOCOL_VERSION].concat(LEGACY_PROTOCOL_VERSIONS);

const META_PREFIX = 'io.modelcontextprotocol/';
const META_PROTOCOL_VERSION = `${META_PREFIX}protocolVersion`;
const META_SERVER_INFO = `${META_PREFIX}serverInfo`;

const ERROR_CODES = {
    PARSE_ERROR: -32700,
    INVALID_REQUEST: -32600,
    METHOD_NOT_FOUND: -32601,
    INVALID_PARAMS: -32602,
    INTERNAL_ERROR: -32603,
    // Reserved protocol-defined errors (2026-07-28)
    HEADER_MISMATCH: -32020,
    UNSUPPORTED_PROTOCOL_VERSION: -32022
};

const SERVER_INFO = { name: 'EmailEngine', version: packageData.version };

// Everything the instructions say that does not depend on which credential is asking. The collapse
// marker earns its line here: it is a machine-readable "show more" boundary, and an agent that
// knows the class name can read the new part of a thread without the quoted copies of everything
// before it. The send warning is the other one that matters, and having it in one place is why it
// cannot be edited in the generic set and forgotten in the bound one.
const COMMON_INSTRUCTIONS = [
    'Message ids come from list_messages or search_messages.',
    `Message bodies are returned as sanitized HTML; quoted reply and forward history is wrapped in a <details class="${COLLAPSE_CLASS}"> element, ` +
        'so what the sender actually wrote is everything outside it.',
    'send_message delivers real email to real recipients - confirm with the user before calling it.'
];

/**
 * The instructions shown to the calling model by clients that surface them.
 *
 * Only the opening differs, and it differs on the one thing that changes what the agent can do:
 * the generic set tells it to list the accounts and pass an id, which a bound credential can do
 * neither of - the listing tools are not advertised to it, and its tools carry no `account`
 * argument because the endpoint already knows which account they act on. Saying so up front is
 * what stops the agent looking for a way to supply one.
 *
 * Kept short either way: this rides along on every discover/initialize response.
 *
 * @param {String} [account] - the bound account id, for an account-bound credential
 * @returns {String} instructions
 */
function serverInstructions(account) {
    const opening = account
        ? [
              `EmailEngine gives access to the email account '${account}' on this instance.`,
              'This credential reaches that one account and no other, so the tools take no account argument - it is applied for you.'
          ]
        : [
              'EmailEngine gives access to the email accounts registered on this instance.',
              'Call list_accounts first and use the returned account id as the `account` argument of the other tools.'
          ];

    return opening.concat(COMMON_INSTRUCTIONS).join(' ');
}

const SERVER_INSTRUCTIONS = serverInstructions();

// URL hostnames that mean "this machine" for the transport policies below: the Origin check
// here and the loopback redirect-URI rule in lib/mcp/oauth.js read the same list, so the two
// cannot drift on what counts as local.
const LOOPBACK_HOSTNAMES = ['localhost', '127.0.0.1', '::1', '[::1]'];

// Cache policy of the modern era (Caching utility, revision 2026-07-28): every complete result
// of the discovery and listing methods MUST carry ttlMs and cacheScope, and strict clients
// (Claude Code among them) refuse a tools/list without them. The table is total over the
// result-bearing methods on purpose: null declares a method non-cacheable per the spec, and
// completeResult() throws on a method with no entry at all, so adding a method forces a caching
// decision instead of silently shipping a listing a strict client rejects.
//
// The scope is uniformly private because nothing this endpoint serves is caller-neutral:
// server/discover embeds a bound credential's account id in its instructions, tools/list is
// narrowed to what the caller's token permits, and the resource listings and reads are that
// caller's accounts. The templates listing is an empty constant today, but private is the value
// that stays correct if that ever changes. The TTLs are freshness hints, not contracts: the
// catalog-shaped results move only when an operator edits settings or token permissions, the
// account listing moves as accounts come and go, and a read carries connection state that flips
// on its own.
const CACHE_TTLS = {
    'server/discover': 300 * 1000,
    'tools/list': 300 * 1000,
    'resources/templates/list': 300 * 1000,
    'resources/list': 60 * 1000,
    'resources/read': 30 * 1000,
    ping: null,
    'tools/call': null
};

// Builds a modern-era complete result: the resultType marker, the declared cache hints, then
// the payload. The throw is unreachable from the wire - an unknown method is answered
// method-not-found before any result is built - so it only fires on a half-finished code change.
function completeResult(method, result) {
    if (!Object.hasOwn(CACHE_TTLS, method)) {
        throw new Error(`No cache policy declared for method: ${method}`);
    }
    const ttlMs = CACHE_TTLS[method];
    return Object.assign({ resultType: 'complete' }, ttlMs === null ? null : { ttlMs, cacheScope: 'private' }, result);
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Whether the client's Accept header admits an SSE response.
 *
 * Parses q-values rather than matching the media type alone: `text/event-stream;q=0` is the
 * standard way for a JSON-only client to say it cannot consume the stream, and handing one to it
 * anyway is exactly what the check exists to prevent.
 */
function acceptsEventStream(header) {
    for (const entry of String(header || '').split(',')) {
        const [mediaType, ...params] = entry.split(';').map(part => part.trim());

        if (!['text/event-stream', 'text/*', '*/*'].includes(mediaType.toLowerCase())) {
            continue;
        }

        const quality = params.map(param => /^q=/i.test(param) && Number.parseFloat(param.slice(2))).find(value => value !== false);

        // An unparseable q is not a refusal; only an explicit zero is
        if (quality === 0) {
            continue;
        }

        return true;
    }

    return false;
}

/**
 * Whether a browser Origin may talk to the MCP endpoint. Non-browser MCP clients send no Origin
 * header at all; a present Origin means a web page is calling, and anything that is not
 * provably this instance or an explicitly configured CORS origin is refused to keep DNS
 * rebinding out (MCP Streamable HTTP, "Security & Endpoint").
 */
function isAllowedOrigin(origin, { serviceUrl, corsOrigins }) {
    if (!origin) {
        return true;
    }

    let parsed;
    try {
        parsed = new URL(origin);
    } catch (err) {
        return false;
    }

    if (LOOPBACK_HOSTNAMES.includes(parsed.hostname)) {
        return true;
    }

    if (serviceUrl) {
        try {
            if (new URL(serviceUrl).origin === parsed.origin) {
                return true;
            }
        } catch (err) {
            // a malformed serviceUrl setting grants nothing
        }
    }

    return (corsOrigins || []).some(entry => entry === '*' || entry === parsed.origin);
}

function rpcError(id, code, message, data) {
    const error = { code, message };
    if (data !== undefined) {
        error.data = data;
    }
    return { jsonrpc: '2.0', id: id === undefined ? null : id, error };
}

function rpcResult(id, result) {
    return { jsonrpc: '2.0', id, result };
}

/**
 * Decodes the =?base64?...?= sentinel format the transport uses for header values that are not
 * plain ASCII (Streamable HTTP, "Value Encoding"). Plain values pass through untouched.
 */
function decodeHeaderValue(value) {
    if (typeof value !== 'string') {
        return value;
    }

    const match = /^=\?base64\?(.*)\?=$/.exec(value);
    if (!match) {
        return value;
    }

    try {
        return Buffer.from(match[1], 'base64').toString('utf8');
    } catch (err) {
        return value;
    }
}

function unsupportedVersionError(id, requested) {
    return rpcError(id, ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION, 'Unsupported protocol version', {
        supported: SUPPORTED_PROTOCOL_VERSIONS,
        requested: requested === undefined ? null : requested
    });
}

function capabilities(era) {
    return {
        tools: {},
        resources: era === 'legacy' ? { subscribe: false, listChanged: false } : {}
    };
}

/**
 * Processes one JSON-RPC message POSTed to the MCP endpoint.
 *
 * @param {Object} opts
 * @param {*} opts.body - the parsed request payload
 * @param {Object} opts.headers - lowercased HTTP request headers
 * @param {Object} opts.ctx - dispatch context:
 *        listTools() => [tool definitions],
 *        callTool(name, args) => tool result (throws {rpcCode, message} for protocol errors),
 *        listResources() => [resources], readResource(uri) => contents,
 *        instructions - optional per-credential replacement for SERVER_INSTRUCTIONS,
 *        acceptsEventStream - whether the request's Accept header admits text/event-stream
 * @returns {Promise<Object>} { httpStatus, body } for a JSON response (body undefined for 202),
 *          or { listen: { id, filter } } when a subscriptions/listen request was accepted and
 *          the caller should open the SSE stream
 */
async function processMcpRequest({ body, headers, ctx }) {
    if (Array.isArray(body)) {
        // Batching existed only in revision 2025-03-26, which predates every version this
        // endpoint speaks
        return { httpStatus: 200, body: rpcError(null, ERROR_CODES.INVALID_REQUEST, 'JSON-RPC batch requests are not supported') };
    }

    if (!isPlainObject(body) || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
        return { httpStatus: 200, body: rpcError(isPlainObject(body) ? body.id : null, ERROR_CODES.INVALID_REQUEST, 'Not a valid JSON-RPC 2.0 request') };
    }

    const id = Object.prototype.hasOwnProperty.call(body, 'id') ? body.id : undefined;
    const isNotification = id === undefined;
    const params = isPlainObject(body.params) ? body.params : {};
    const meta = isPlainObject(params._meta) ? params._meta : {};
    const metaVersion = typeof meta[META_PROTOCOL_VERSION] === 'string' ? meta[META_PROTOCOL_VERSION] : undefined;

    if (metaVersion !== undefined) {
        return processModern({ body, id, isNotification, params, metaVersion, headers, ctx });
    }

    return processLegacy({ body, id, isNotification, params, headers, ctx });
}

async function processModern({ body, id, isNotification, params, metaVersion, headers, ctx }) {
    const headerVersion = headers['mcp-protocol-version'];

    // The header and the body value MUST agree, so that an intermediary routing on the header
    // and this server executing on the body cannot act on different requests
    if (headerVersion !== metaVersion) {
        return {
            httpStatus: 400,
            body: rpcError(id, ERROR_CODES.HEADER_MISMATCH, 'MCP-Protocol-Version header does not match the protocol version in the request body')
        };
    }

    if (metaVersion !== MODERN_PROTOCOL_VERSION) {
        return { httpStatus: 400, body: unsupportedVersionError(id, metaVersion) };
    }

    if (!isNotification) {
        const headerMethod = decodeHeaderValue(headers['mcp-method']);
        if (headerMethod !== body.method) {
            return {
                httpStatus: 400,
                body: rpcError(
                    id,
                    ERROR_CODES.HEADER_MISMATCH,
                    headers['mcp-method'] ? 'Mcp-Method header does not match the request body' : 'Missing required Mcp-Method header'
                )
            };
        }

        // Mcp-Name mirrors the tool name or resource URI on the requests that carry one
        const namedValue = body.method === 'tools/call' ? params.name : body.method === 'resources/read' ? params.uri : undefined;
        if (namedValue !== undefined) {
            const headerName = decodeHeaderValue(headers['mcp-name']);
            if (headerName !== namedValue) {
                return {
                    httpStatus: 400,
                    body: rpcError(
                        id,
                        ERROR_CODES.HEADER_MISMATCH,
                        headers['mcp-name'] ? 'Mcp-Name header does not match the request body' : 'Missing required Mcp-Name header'
                    )
                };
            }
        }
    }

    if (isNotification) {
        // The modern revision defines no client-to-server notifications over Streamable HTTP,
        // but an accepted notification is answered 202 rather than rejected, so a conforming
        // client that sends one anyway is not punished for it
        return { httpStatus: 202 };
    }

    switch (body.method) {
        case 'server/discover': {
            const result = completeResult(body.method, {
                supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
                capabilities: capabilities('modern'),
                instructions: ctx.instructions || SERVER_INSTRUCTIONS,
                _meta: { [META_SERVER_INFO]: SERVER_INFO }
            });
            return { httpStatus: 200, body: rpcResult(id, result) };
        }

        case 'subscriptions/listen': {
            if (!ctx.acceptsEventStream) {
                return {
                    httpStatus: 400,
                    body: rpcError(id, ERROR_CODES.INVALID_REQUEST, 'subscriptions/listen requires an Accept header that includes text/event-stream')
                };
            }
            return { listen: { id, filter: isPlainObject(params.notifications) ? params.notifications : {} } };
        }

        default:
            return dispatchCommon({ era: 'modern', method: body.method, id, params, ctx });
    }
}

async function processLegacy({ body, id, isNotification, params, headers, ctx }) {
    const headerVersion = headers['mcp-protocol-version'];

    if (headerVersion !== undefined) {
        if (headerVersion === MODERN_PROTOCOL_VERSION) {
            // A modern header on a request whose body carries no modern metadata: the two
            // sources of truth disagree, which is exactly what the mirrored-header validation
            // exists to refuse
            return {
                httpStatus: 400,
                body: rpcError(
                    id,
                    ERROR_CODES.HEADER_MISMATCH,
                    'MCP-Protocol-Version header names a modern revision but the request body carries no protocol version metadata'
                )
            };
        }

        if (!LEGACY_PROTOCOL_VERSIONS.includes(headerVersion)) {
            return { httpStatus: 400, body: unsupportedVersionError(id, headerVersion) };
        }
    }

    if (isNotification) {
        // notifications/initialized and friends: acknowledged and dropped, since there is no
        // session state to arm
        return { httpStatus: 202 };
    }

    if (body.method === 'initialize') {
        const proposed = typeof params.protocolVersion === 'string' ? params.protocolVersion : undefined;

        // Echo a supported proposal; counter an unsupported one with the newest legacy version
        // this endpoint speaks, as the legacy negotiation rules prescribe. The modern version is
        // never offered here - it has no initialize handshake to arrive through.
        const negotiated = LEGACY_PROTOCOL_VERSIONS.includes(proposed) ? proposed : LEGACY_PROTOCOL_VERSIONS[0];

        const result = {
            protocolVersion: negotiated,
            capabilities: capabilities('legacy'),
            serverInfo: SERVER_INFO,
            instructions: ctx.instructions || SERVER_INSTRUCTIONS
        };
        return { httpStatus: 200, body: rpcResult(id, result) };
    }

    return dispatchCommon({ era: 'legacy', method: body.method, id, params, ctx });
}

// The methods both eras share. Results are identical apart from the modern resultType marker
// and the modern cache hints - the legacy revisions define neither.
async function dispatchCommon({ era, method, id, params, ctx }) {
    const respond = result => {
        if (era === 'modern') {
            result = completeResult(method, result);
        }
        return { httpStatus: 200, body: rpcResult(id, result) };
    };

    // Runs a dispatcher whose domain errors carry an rpcCode: those become JSON-RPC error
    // responses, anything else stays an exception for the route's own error handling
    const respondWith = async produce => {
        try {
            return respond(await produce());
        } catch (err) {
            if (err.rpcCode) {
                return { httpStatus: 200, body: rpcError(id, err.rpcCode, err.message) };
            }
            throw err;
        }
    };

    switch (method) {
        case 'ping':
            return respond({});

        case 'tools/list':
            return respond({ tools: await ctx.listTools() });

        case 'tools/call':
            if (typeof params.name !== 'string' || !params.name) {
                return { httpStatus: 200, body: rpcError(id, ERROR_CODES.INVALID_PARAMS, 'Missing tool name') };
            }
            return respondWith(() => ctx.callTool(params.name, params.arguments));

        case 'resources/list':
            return respond({ resources: await ctx.listResources() });

        case 'resources/read':
            if (typeof params.uri !== 'string' || !params.uri) {
                return { httpStatus: 200, body: rpcError(id, ERROR_CODES.INVALID_PARAMS, 'Missing resource uri') };
            }
            return respondWith(async () => ({ contents: await ctx.readResource(params.uri) }));

        case 'resources/templates/list':
            // A standard listing some clients call unprompted; empty is the truthful answer
            return respond({ resourceTemplates: [] });

        default:
            // Method not found: HTTP 404 in the modern era (so intermediaries can tell it apart
            // from a legacy server without parsing), plain JSON-RPC error in the legacy one
            return {
                httpStatus: era === 'modern' ? 404 : 200,
                body: rpcError(id, ERROR_CODES.METHOD_NOT_FOUND, `Method not found: ${method}`)
            };
    }
}

module.exports = {
    processMcpRequest,
    decodeHeaderValue,
    isAllowedOrigin,
    acceptsEventStream,
    rpcError,
    ERROR_CODES,
    CACHE_TTLS,
    LOOPBACK_HOSTNAMES,
    MODERN_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
    META_PROTOCOL_VERSION,
    SERVER_INFO,
    SERVER_INSTRUCTIONS,
    serverInstructions
};
