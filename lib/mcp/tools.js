'use strict';

// The MCP tool registry and executor.
//
// Tools are not defined here. A route opts in by carrying a `plugins.mcp` block
// ({ name, title, description, omit? }), and this module derives everything else from what the
// route already declares: the input schema from its joi validation schemas, the behavior
// annotations from routeGrant() - the same source /swagger.json publishes as x-ee-action and
// x-ee-group - and the dispatch target from its method and path. There is deliberately no second
// description of any endpoint: a tool cannot disagree with the route it wraps.
//
// Tool calls are dispatched with server.inject(), so an MCP call IS an API request: the api-token
// strategy re-runs against the caller's own credential, and scope checks, token permissions,
// account binding, IP restrictions, rate limits and the token audit log all apply exactly as they
// do over REST. This module never touches Redis and never bypasses a handler.

const { routeGrant, ACTION } = require('../api-routes/permission-map');
const { mcpOptions } = require('../api-routes/route-metadata');
const { joiToJsonSchema } = require('./json-schema');
const { apiInject } = require('./inject');

// Serialized tool results larger than this are truncated. Message text is attacker-sized input
// (a single mail can carry megabytes of text), and an oversized tool result degrades or breaks
// the calling agent, so the cap errs low. The truncation is announced in the result text.
const MAX_TOOL_RESULT_BYTES = 512 * 1024;

// Binary payloads (attachments) above this size are refused with a pointer at the REST download
// endpoint instead of being base64-inlined into the conversation.
const MAX_TOOL_BINARY_BYTES = 1024 * 1024;

const TRUNCATION_NOTICE = size => `\n\n[Result truncated by EmailEngine: the full response was ${size} bytes. Narrow the request to see the rest.]`;

// The converted schema for one source (path params, query, payload)
function convertSource(schema) {
    const converted = schema ? joiToJsonSchema(schema) : undefined;

    if (!converted || converted.type !== 'object' || !converted.properties) {
        return { properties: {}, required: [] };
    }

    return {
        properties: converted.properties,
        required: converted.required || []
    };
}

/**
 * Derives the MCP tool list from a Hapi route table.
 *
 * @param {Array} routes - server.table()
 * @returns {{tools: Array, byName: Map}} tool definitions in deterministic (name) order, plus the
 *          executor's lookup table carrying the dispatch data the wire format does not
 */
function buildToolRegistry(routes) {
    const byName = new Map();

    for (const route of routes) {
        const options = mcpOptions(route);
        if (!options.name) {
            continue;
        }

        if (byName.has(options.name)) {
            // Two routes claiming one tool name is a wiring bug, and last-write-wins would pick
            // the tool by iteration order. Same rule as the ROUTE_GROUPS inversion.
            throw new Error(`MCP tool ${options.name} is declared by two routes`);
        }

        const validate = (route.settings && route.settings.validate) || {};
        const omit = new Set(options.omit || []);

        const params = convertSource(validate.params);
        const query = convertSource(validate.query);
        const payload = convertSource(validate.payload);

        const properties = {};
        const required = [];
        const sources = new Map();

        for (const [sourceName, source] of [
            ['params', params],
            ['query', query],
            ['payload', payload]
        ]) {
            for (const [key, propertySchema] of Object.entries(source.properties)) {
                if (omit.has(key)) {
                    continue;
                }
                if (sources.has(key)) {
                    // A path parameter and a payload field sharing a name cannot both be a single
                    // tool argument. None of the wrapped routes do this; refuse at build time so
                    // the next one cannot silently shadow.
                    throw new Error(`MCP tool ${options.name}: argument ${key} is defined by two request sources`);
                }
                sources.set(key, sourceName);
                properties[key] = propertySchema;
                if (source.required.includes(key)) {
                    required.push(key);
                }
            }
        }

        const grant = routeGrant(route);

        const annotations = {
            title: options.title,
            readOnlyHint: grant.action === ACTION.READ,
            destructiveHint: grant.action === ACTION.DESTRUCTIVE,
            // Sending mail reaches arbitrary external recipients; everything else stays inside
            // the connected mailboxes
            openWorldHint: grant.action === ACTION.SEND
        };

        const inputSchema = {
            type: 'object',
            properties,
            additionalProperties: false
        };
        if (required.length) {
            inputSchema.required = required;
        }

        byName.set(options.name, {
            definition: {
                name: options.name,
                title: options.title,
                description: options.description || (route.settings && route.settings.description),
                inputSchema,
                annotations
            },
            method: route.method,
            path: route.path,
            sources,
            binary: !!options.binary,
            resourceUriTemplate: options.resourceUriTemplate
        });
    }

    const tools = [...byName.values()].map(entry => entry.definition).sort((a, b) => a.name.localeCompare(b.name, 'en'));

    return { tools, byName };
}

// Fills a Hapi path template ('/v1/account/{account}/message/{message}') from tool arguments.
function buildPath(template, args, sources) {
    return template.replace(/\{([^}]+)\}/g, (match, name) => {
        // A missing path parameter can only mean the argument was optional in the schema and the
        // caller left it out; the joi 400 from the injected request names it either way, but the
        // URL must not be built with the literal placeholder in it.
        if (!sources.has(name) || args[name] === undefined || args[name] === null) {
            return '';
        }
        return encodeURIComponent(String(args[name]));
    });
}

function buildQuery(args, tool) {
    const query = new URLSearchParams();

    for (const [key, sourceName] of tool.sources) {
        if (sourceName !== 'query' || args[key] === undefined || args[key] === null) {
            continue;
        }
        for (const value of [].concat(args[key])) {
            query.append(key, String(value));
        }
    }

    const rendered = query.toString();
    return rendered ? `?${rendered}` : '';
}

function textResult(text, { isError = false } = {}) {
    const result = { content: [{ type: 'text', text }] };
    if (isError) {
        result.isError = true;
    }
    return result;
}

function jsonResult(value) {
    // Compact on purpose: an indent is pure padding to a model, it inflates every response by a
    // double-digit percentage, and it counts against the size cap below
    let text = JSON.stringify(value);
    let structuredContent = value;

    const size = Buffer.byteLength(text);
    if (size > MAX_TOOL_RESULT_BYTES) {
        text = text.slice(0, MAX_TOOL_RESULT_BYTES) + TRUNCATION_NOTICE(size);
        // A structuredContent that repeats the oversized value would defeat the cap
        structuredContent = undefined;
    }

    const result = { content: [{ type: 'text', text }] };
    if (structuredContent !== undefined && structuredContent !== null && typeof structuredContent === 'object') {
        result.structuredContent = structuredContent;
    }
    return result;
}

/**
 * Executes one tool call by injecting the equivalent API request.
 *
 * @param {Object} opts
 * @param {Object} opts.server - the Hapi server (for inject)
 * @param {Object} opts.tool - registry entry from buildToolRegistry().byName
 * @param {Object} opts.args - tool arguments as sent by the client
 * @param {Object} opts.request - the outer /mcp request (credential, client IP, timeout header)
 * @returns {Object} an MCP tool result ({ content, structuredContent?, isError? })
 */
async function callTool({ server, tool, args, request }) {
    args = args || {};

    if (typeof args !== 'object' || Array.isArray(args)) {
        return textResult('Tool arguments must be an object', { isError: true });
    }

    const unknown = Object.keys(args).filter(key => !tool.sources.has(key));
    if (unknown.length) {
        return textResult(`Unknown tool argument${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}`, { isError: true });
    }

    const payload = {};
    let hasPayload = false;
    for (const [key, sourceName] of tool.sources) {
        if (sourceName === 'payload' && args[key] !== undefined) {
            payload[key] = args[key];
            hasPayload = true;
        }
    }

    const res = await apiInject({
        server,
        request,
        method: tool.method,
        url: buildPath(tool.path, args, tool.sources) + buildQuery(args, tool),
        payload: hasPayload ? payload : undefined
    });

    if (res.statusCode >= 400) {
        // The API's own error payload (a Boom body plus fields like requiredPermission) is the
        // actionable feedback; tool-execution errors are results, not protocol errors
        let body = res.result;
        if (Buffer.isBuffer(body)) {
            body = body.toString();
        }
        return textResult(typeof body === 'string' ? body : JSON.stringify(body), { isError: true });
    }

    if (tool.binary) {
        const data = res.rawPayload || Buffer.alloc(0);

        if (data.length > MAX_TOOL_BINARY_BYTES) {
            return textResult(
                `The file is ${data.length} bytes, which is larger than the ${MAX_TOOL_BINARY_BYTES} byte limit for inline tool results. ` +
                    `Download it over the REST API instead: GET ${tool.path}`,
                { isError: true }
            );
        }

        return {
            content: [
                {
                    type: 'resource',
                    resource: {
                        uri: buildResourceUri(tool, args),
                        mimeType: res.headers['content-type'] || 'application/octet-stream',
                        blob: data.toString('base64')
                    }
                }
            ]
        };
    }

    if (res.result === null || res.result === undefined) {
        return textResult('OK');
    }

    if (typeof res.result === 'string') {
        return textResult(res.result);
    }

    return jsonResult(res.result);
}

// A stable, opaque identifier for binary content, so the client has a URI to attach the blob to.
// These are not listed by resources/list and not readable by resources/read - the tool result
// carries the content inline.
function buildResourceUri(tool, args) {
    const template = tool.resourceUriTemplate || `emailengine://${tool.path.replace(/^\/v1\//, '')}`;
    return template.replace(/\{([^}]+)\}/g, (match, name) => encodeURIComponent(String(args[name] === undefined ? '' : args[name])));
}

module.exports = { buildToolRegistry, callTool, MAX_TOOL_RESULT_BYTES, MAX_TOOL_BINARY_BYTES };
