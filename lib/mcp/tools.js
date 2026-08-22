'use strict';

// The MCP tool registry and executor.
//
// Tools are not defined here. A route opts in by carrying a `plugins.mcp` block
// ({ name, title, description, omit?, force? }), and this module derives everything else from what
// the route already declares: the input schema from its joi validation schemas, the behavior
// annotations from routeGrant() - the same source /swagger.json publishes as x-ee-action and
// x-ee-group - and the dispatch target from its method and path. There is deliberately no second
// description of any endpoint: a tool cannot disagree with the route it wraps.
//
// Tool calls are dispatched with server.inject(), so an MCP call IS an API request: the api-token
// strategy re-runs against the caller's own credential, and scope checks, token permissions,
// account binding, IP restrictions, rate limits and the token audit log all apply exactly as they
// do over REST. This module never touches Redis and never bypasses a handler.

const { routeGrant, ACTION } = require('../api-routes/permission-map');
const tokenPermissions = require('../token-permissions');
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

// One registry per Hapi server, built on first use and held for the life of the worker - route
// definitions cannot change while it runs, and the build walks every joi schema of every wrapped
// route. Keyed weakly so a test server and its registry are released together.
const registryCache = new WeakMap();

/**
 * The memoized tool registry of a running server. Shared by the /mcp endpoint and the admin UI
 * (the MCP config page renders the tool catalog from it), so the two cannot disagree about what
 * is exposed.
 *
 * @param {Object} server - the Hapi server
 * @returns {{tools: Array, byName: Map}}
 */
function getToolRegistry(server) {
    if (!registryCache.has(server)) {
        registryCache.set(server, buildToolRegistry(server.table()));
    }
    return registryCache.get(server);
}

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
        // Every request argument of the route, omitted ones included. `sources` is what a caller
        // may address; this is what the route actually accepts, and it is what a forced value has
        // to be looked up in - a forced argument is almost always an omitted one.
        const argSources = new Map();

        for (const [sourceName, source] of [
            ['params', params],
            ['query', query],
            ['payload', payload]
        ]) {
            for (const [key, propertySchema] of Object.entries(source.properties)) {
                if (argSources.has(key)) {
                    // A path parameter and a payload field sharing a name cannot both be a single
                    // tool argument. None of the wrapped routes do this; refuse at build time so
                    // the next one cannot silently shadow.
                    throw new Error(`MCP tool ${options.name}: argument ${key} is defined by two request sources`);
                }
                argSources.set(key, sourceName);
                if (omit.has(key)) {
                    continue;
                }
                sources.set(key, sourceName);
                properties[key] = propertySchema;
                if (source.required.includes(key)) {
                    required.push(key);
                }
            }
        }

        // Values the MCP layer pins on every call, so a tool has one behavior rather than a matrix
        // of them. A forced value is sent with the injected request but is not a tool argument: the
        // point is that the calling model does not get to choose. The lookup is against every
        // argument of the route rather than against the tool's own, since an omitted key has left
        // the latter - which is also why `force` without a matching `omit` is refused. That pair is
        // the whole mechanism, and declaring one half of it would advertise an argument whose value
        // is then thrown away, which reads to the model as a control it does not have.
        const force = Object.entries(options.force || {});
        const forcedValues = {};
        // The routing table the injected request is built from: the tool's own arguments plus the
        // forced ones, which are not tool arguments and so are absent from `sources`. Only when
        // there is something to add - otherwise the tool routes through `sources` itself.
        const forcedSources = force.length ? new Map(sources) : sources;

        for (const [key, value] of force) {
            const sourceName = argSources.get(key);
            if (!sourceName) {
                throw new Error(`MCP tool ${options.name}: forced argument ${key} is not an argument of ${route.method} ${route.path}`);
            }
            if (!omit.has(key)) {
                throw new Error(`MCP tool ${options.name}: forced argument ${key} must also be omitted, or the schema offers a choice that is not there`);
            }
            forcedSources.set(key, sourceName);
            forcedValues[key] = value;
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
            forcedSources,
            forcedValues,
            // The operation this tool resolves to, for consumers that answer per-credential
            // questions about the catalog: tools/list uses it to show a permission-narrowed
            // token only the tools its record can actually call
            grant,
            binary: !!options.binary,
            resourceUriTemplate: options.resourceUriTemplate
        });
    }

    const tools = [...byName.values()].map(entry => entry.definition).sort((a, b) => a.name.localeCompare(b.name, 'en'));

    return { tools, byName };
}

/**
 * The effective arguments and their request sources for one call.
 *
 * Three inputs are folded together here: what the caller sent, the values the tool forces (which
 * the caller cannot have sent - the builder refuses a forced argument that is still exposed), and
 * the account a bound credential is pinned to.
 *
 * The binding is a default rather than an override. A bound credential is advertised tools that
 * take no `account` argument at all (see toolDefinitionFor), so the argument is normally absent
 * and filled in here - but a client working from a stale catalog still sends one, and letting it
 * through unchanged keeps the mismatch a 403 from the inner request rather than a call that
 * quietly acts on a different mailbox than the one asked for.
 *
 * @param {Object} tool - registry entry
 * @param {Object} args - arguments as sent by the client
 * @param {String} [boundAccount] - the account this credential is pinned to, if any
 * @returns {{args: Object, sources: Map}}
 */
function effectiveArguments(tool, args, boundAccount) {
    const effective = Object.assign({}, args, tool.forcedValues);

    if (boundAccount && tool.sources.has('account') && (effective.account === undefined || effective.account === null || effective.account === '')) {
        effective.account = boundAccount;
    }

    return { args: effective, sources: tool.forcedSources };
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

function buildQuery(args, sources) {
    const query = new URLSearchParams();

    for (const [key, sourceName] of sources) {
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

/**
 * Cuts a string to a UTF-8 byte budget.
 *
 * String.slice() counts UTF-16 code units, so slicing to the byte cap left a result up to three
 * times over it - a mailbox of CJK or Cyrillic text sailed through the cap while carrying a
 * notice claiming it had been truncated. Cutting the encoded bytes instead, then walking back off
 * any trailing continuation byte, keeps the budget honest and never emits a split code point.
 */
function truncateToBytes(text, maxBytes) {
    const buf = Buffer.from(text, 'utf8');
    if (buf.length <= maxBytes) {
        return text;
    }

    let end = maxBytes;
    // 0b10xxxxxx marks a continuation byte, so back up until `end` sits on a lead byte
    while (end > 0 && (buf[end] & 0xc0) === 0x80) {
        end--;
    }

    return buf.subarray(0, end).toString('utf8');
}

function jsonResult(value) {
    // Compact on purpose: an indent is pure padding to a model, it inflates every response by a
    // double-digit percentage, and it counts against the size cap below
    let text = JSON.stringify(value);
    let structuredContent = value;

    const size = Buffer.byteLength(text);
    if (size > MAX_TOOL_RESULT_BYTES) {
        text = truncateToBytes(text, MAX_TOOL_RESULT_BYTES) + TRUNCATION_NOTICE(size);
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

    const boundAccount = request.app && request.app.mcpBoundAccount;
    const effective = effectiveArguments(tool, args, boundAccount);

    // Required arguments are checked here rather than left to the injected request. A missing
    // path parameter does not reach joi at all: it renders as an empty path segment, and Hapi
    // answers the resulting `/v1/account//message/x` with a bare 404 that names neither the tool
    // nor the argument, which an agent can only respond to by retrying the same call.
    //
    // Checked over the effective arguments, so the account a bound credential never had to send
    // does not read as one it forgot.
    const missing = (tool.definition.inputSchema.required || []).filter(key => effective.args[key] === undefined || effective.args[key] === null);
    if (missing.length) {
        return textResult(`Missing required tool argument${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}`, { isError: true });
    }

    const payload = {};
    let hasPayload = false;
    for (const [key, sourceName] of effective.sources) {
        if (sourceName === 'payload' && effective.args[key] !== undefined) {
            payload[key] = effective.args[key];
            hasPayload = true;
        }
    }

    const res = await apiInject({
        server,
        request,
        method: tool.method,
        url: buildPath(tool.path, effective.args, effective.sources) + buildQuery(effective.args, effective.sources),
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
                        uri: buildResourceUri(tool, effective.args),
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

    return jsonResult(dropPlaintextTwin(res.result));
}

/**
 * Reduces a message body to the one rendering an MCP caller is given.
 *
 * The web-safe HTML is generated from both MIME parts, so the plaintext part beside it is the same
 * message a second time: double the tokens for a rendering the model has no use for, on the largest
 * results this endpoint returns. Keyed on the `webSafe` marker the API sets rather than on a tool
 * name, so it only ever fires where the HTML really is the generated one.
 *
 * Only `get_message` needs this. The text endpoint's own web-safe mode returns one body already
 * (webSafeTextResponse in lib/web-safe-html.js), which is where that promise belongs - it is the
 * shape of the API response, not something the MCP layer decides.
 *
 * @param {*} result - the API response
 * @returns {*} the same value, with the redundant plaintext removed
 */
function dropPlaintextTwin(result) {
    const text = result && result.text;
    if (text && typeof text === 'object' && text.webSafe === true) {
        delete text.plain;
    }
    return result;
}

// A stable, opaque identifier for binary content, so the client has a URI to attach the blob to.
// These are not listed by resources/list and not readable by resources/read - the tool result
// carries the content inline.
function buildResourceUri(tool, args) {
    const template = tool.resourceUriTemplate || `emailengine://${tool.path.replace(/^\/v1\//, '')}`;
    return template.replace(/\{([^}]+)\}/g, (match, name) => encodeURIComponent(String(args[name] === undefined ? '' : args[name])));
}

/**
 * Whether one credential is advertised one tool.
 *
 * The single spelling of what tools/list filters on, so a credential's view of the catalog is
 * decided in one place. Two rules, and a consumer that applies only one of them overstates the
 * catalog: the permission record, and the account binding - a credential bound to one account is
 * never offered the tools that take no account argument, because there is nothing to bind them to.
 *
 * Advertisement only. tools/call dispatches whatever is asked and the injected inner request stays
 * the enforcement, so this is allowed to be a prediction rather than a gate.
 *
 * @param {Object} entry - a registry entry, from getToolRegistry().byName
 * @param {Object} opts
 * @param {Object} opts.tokenData - the token record, as the auth strategy leaves it in artifacts
 * @param {String} [opts.boundAccount] - the account this credential is pinned to, if any
 * @returns {Boolean}
 */
function toolVisibleTo(entry, { tokenData, boundAccount }) {
    if (boundAccount && !entry.sources.has('account')) {
        return false;
    }
    return tokenPermissions.check({ tokenData, operation: entry.grant }).allowed;
}

/**
 * The tool definition one credential is shown.
 *
 * An account-bound credential reaches exactly one account, and the endpoint knows which - so its
 * tools do not take an `account` argument at all. Leaving it in the schema asks the model for a
 * value it has no way to know (the same credential is refused the account listing), which is a
 * failed call and a round trip of guessing before the agent gets anywhere. The executor fills the
 * binding in on dispatch.
 *
 * The stripped definition is derived once per registry entry and cached on it: the shape does not
 * depend on which account the credential is bound to, only on whether it is bound at all.
 *
 * @param {Object} entry - a registry entry, from getToolRegistry().byName
 * @param {Object} opts
 * @param {String} [opts.boundAccount] - the account this credential is pinned to, if any
 * @returns {Object} the tool definition to advertise
 */
function toolDefinitionFor(entry, { boundAccount } = {}) {
    if (!boundAccount || !entry.sources.has('account')) {
        return entry.definition;
    }

    if (!entry.boundDefinition) {
        const properties = Object.assign({}, entry.definition.inputSchema.properties);
        delete properties.account;

        const inputSchema = Object.assign({}, entry.definition.inputSchema, { properties });
        const required = (entry.definition.inputSchema.required || []).filter(key => key !== 'account');
        if (required.length) {
            inputSchema.required = required;
        } else {
            delete inputSchema.required;
        }

        entry.boundDefinition = Object.assign({}, entry.definition, { inputSchema });
    }

    return entry.boundDefinition;
}

/**
 * The catalog one credential is advertised, in tools/list order.
 *
 * The single spelling of per-credential advertisement: which tools are offered (toolVisibleTo) and
 * what each of them looks like to this caller (toolDefinitionFor). The route handler calls this
 * rather than applying the two itself, so the filter and the reshaping cannot come apart.
 *
 * @param {Object} server - the Hapi server
 * @param {Object} opts
 * @param {Object} opts.tokenData - the token record, as the auth strategy leaves it in artifacts
 * @param {String} [opts.boundAccount] - the account this credential is pinned to, if any
 * @returns {Array} tool definitions
 */
function listToolsFor(server, { tokenData, boundAccount }) {
    const { tools, byName } = getToolRegistry(server);
    return tools
        .map(tool => byName.get(tool.name))
        .filter(entry => toolVisibleTo(entry, { tokenData, boundAccount }))
        .map(entry => toolDefinitionFor(entry, { boundAccount }));
}

/**
 * The exposed tools with the operation each one dispatches under, in tools/list order.
 *
 * For consumers that answer per-credential questions about the catalog without dispatching
 * anything - the admin token form counts how many tools a permission record would leave callable,
 * which is what the two permission axes alone cannot tell a reader. Kept here rather than having
 * callers walk `byName`, so the dispatch table stays this module's business.
 *
 * `accountScoped` is what the binding half of toolVisibleTo() reads, carried along because the
 * admin pages have to apply the same two filters in a browser, where neither this module nor the
 * permission checker can be called. test/mcp-tools-test.js asserts that the two-allowlist model
 * those pages use agrees with toolVisibleTo() over the whole catalog, so the prediction cannot
 * drift away from the rule it predicts.
 *
 * @param {Object} server - the Hapi server
 * @returns {Array<{name: String, action: String, group: String, accountScoped: Boolean}>}
 */
function toolGrants(server) {
    const { tools, byName } = getToolRegistry(server);
    return tools.map(tool => {
        const entry = byName.get(tool.name);
        return Object.assign({ name: tool.name, accountScoped: entry.sources.has('account') }, entry.grant);
    });
}

module.exports = {
    buildToolRegistry,
    getToolRegistry,
    toolGrants,
    toolVisibleTo,
    toolDefinitionFor,
    listToolsFor,
    callTool,
    MAX_TOOL_RESULT_BYTES,
    MAX_TOOL_BINARY_BYTES
};
