'use strict';

// The MCP wire protocol state machine (lib/mcp/protocol.js): version negotiation across the two
// protocol eras, the mirrored-header validation of the modern revision, and method dispatch.
// Everything here is pure - the dispatch context is stubbed, so no Redis, no Hapi.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    processMcpRequest,
    decodeHeaderValue,
    isAllowedOrigin,
    acceptsEventStream,
    ERROR_CODES,
    MODERN_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
    META_PROTOCOL_VERSION,
    SERVER_INFO
} = require('../lib/mcp/protocol');

const TOOLS = [{ name: 'demo_tool', description: 'demo', inputSchema: { type: 'object', properties: {} } }];

function ctx(overrides) {
    return Object.assign(
        {
            listTools: () => TOOLS,
            callTool: async name => ({ content: [{ type: 'text', text: `called ${name}` }] }),
            listResources: async () => [],
            readResource: async () => [],
            acceptsEventStream: false
        },
        overrides || {}
    );
}

function modernRequest(method, { id = 1, params = {}, headers = {}, name } = {}) {
    const body = {
        jsonrpc: '2.0',
        id,
        method,
        params: Object.assign({ _meta: { [META_PROTOCOL_VERSION]: MODERN_PROTOCOL_VERSION } }, params)
    };

    const requestHeaders = Object.assign(
        {
            'mcp-protocol-version': MODERN_PROTOCOL_VERSION,
            'mcp-method': method
        },
        name !== undefined ? { 'mcp-name': name } : {},
        headers
    );

    return { body, headers: requestHeaders };
}

test('MCP protocol', async t => {
    await t.test('rejects JSON-RPC batches', async () => {
        const outcome = await processMcpRequest({ body: [{ jsonrpc: '2.0', id: 1, method: 'ping' }], headers: {}, ctx: ctx() });
        assert.equal(outcome.httpStatus, 200);
        assert.equal(outcome.body.error.code, ERROR_CODES.INVALID_REQUEST);
        assert.equal(outcome.body.id, null);
    });

    await t.test('rejects a body that is not a JSON-RPC request', async () => {
        for (const body of [null, 'ping', 42, { id: 1, method: 'ping' }, { jsonrpc: '2.0', id: 1 }]) {
            const outcome = await processMcpRequest({ body, headers: {}, ctx: ctx() });
            assert.equal(outcome.body.error.code, ERROR_CODES.INVALID_REQUEST, JSON.stringify(body));
        }
    });

    await t.test('origin policy: no header passes, loopback and own origin pass, the rest is refused', () => {
        const policy = { serviceUrl: 'https://ee.example.com', corsOrigins: ['https://app.example.com'] };

        assert.ok(isAllowedOrigin(undefined, policy));
        assert.ok(isAllowedOrigin('http://localhost:3210', policy));
        assert.ok(isAllowedOrigin('https://ee.example.com', policy));
        assert.ok(isAllowedOrigin('https://app.example.com', policy));

        assert.ok(!isAllowedOrigin('https://evil.example.net', policy));
        assert.ok(!isAllowedOrigin('null', policy));
        assert.ok(!isAllowedOrigin('https://evil.example.net', { serviceUrl: 'not a url', corsOrigins: [] }));
        assert.ok(isAllowedOrigin('https://anywhere.example.net', { serviceUrl: '', corsOrigins: ['*'] }));
    });

    await t.test('the Accept test honors q-values, not just the media type', () => {
        assert.ok(acceptsEventStream('application/json, text/event-stream'));
        assert.ok(acceptsEventStream('text/event-stream;q=0.9'));
        assert.ok(acceptsEventStream('*/*'));
        assert.ok(acceptsEventStream('text/*'));

        // The standard way for a JSON-only client to refuse the stream. Matching the media type
        // and stopping at the ';' handed it an SSE response it had said it cannot consume.
        assert.ok(!acceptsEventStream('application/json, text/event-stream;q=0'));
        assert.ok(!acceptsEventStream('text/event-stream; q=0'));
        assert.ok(!acceptsEventStream('*/*;q=0'));

        assert.ok(!acceptsEventStream('application/json'));
        assert.ok(!acceptsEventStream(''));
        assert.ok(!acceptsEventStream(undefined));
    });

    await t.test('decodes the base64 header sentinel', () => {
        assert.equal(decodeHeaderValue('plain-value'), 'plain-value');
        assert.equal(decodeHeaderValue('=?base64?SGVsbG8sIOS4lueVjA==?='), 'Hello, 世界');
        assert.equal(decodeHeaderValue(undefined), undefined);
    });

    await t.test('modern: requires the header to match the body version', async () => {
        const { body, headers } = modernRequest('ping');
        headers['mcp-protocol-version'] = '2025-11-25';

        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });
        assert.equal(outcome.httpStatus, 400);
        assert.equal(outcome.body.error.code, ERROR_CODES.HEADER_MISMATCH);
    });

    await t.test('modern: rejects an unknown protocol version with the supported list', async () => {
        const { body, headers } = modernRequest('ping');
        body.params._meta[META_PROTOCOL_VERSION] = '2030-01-01';
        headers['mcp-protocol-version'] = '2030-01-01';

        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });
        assert.equal(outcome.httpStatus, 400);
        assert.equal(outcome.body.error.code, ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION);
        assert.deepEqual(outcome.body.error.data.supported, SUPPORTED_PROTOCOL_VERSIONS);
        assert.equal(outcome.body.error.data.requested, '2030-01-01');
    });

    await t.test('modern: requires the Mcp-Method header', async () => {
        const { body, headers } = modernRequest('ping');
        delete headers['mcp-method'];

        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });
        assert.equal(outcome.httpStatus, 400);
        assert.equal(outcome.body.error.code, ERROR_CODES.HEADER_MISMATCH);
    });

    await t.test('modern: requires Mcp-Name to match the tool name, sentinel encoding included', async () => {
        const mismatch = modernRequest('tools/call', { params: { name: 'demo_tool', arguments: {} }, name: 'other_tool' });
        const refused = await processMcpRequest({ body: mismatch.body, headers: mismatch.headers, ctx: ctx() });
        assert.equal(refused.httpStatus, 400);
        assert.equal(refused.body.error.code, ERROR_CODES.HEADER_MISMATCH);

        const encoded = modernRequest('tools/call', {
            params: { name: 'demo_tool', arguments: {} },
            name: `=?base64?${Buffer.from('demo_tool').toString('base64')}?=`
        });
        const accepted = await processMcpRequest({ body: encoded.body, headers: encoded.headers, ctx: ctx() });
        assert.equal(accepted.httpStatus, 200);
        assert.equal(accepted.body.result.content[0].text, 'called demo_tool');
        assert.equal(accepted.body.result.resultType, 'complete');
    });

    await t.test('modern: server/discover reports versions, capabilities and identity', async () => {
        const { body, headers } = modernRequest('server/discover');
        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });

        assert.equal(outcome.httpStatus, 200);
        const result = outcome.body.result;
        assert.equal(result.resultType, 'complete');
        assert.deepEqual(result.supportedVersions, SUPPORTED_PROTOCOL_VERSIONS);
        assert.ok(result.capabilities.tools);
        assert.deepEqual(result._meta['io.modelcontextprotocol/serverInfo'], SERVER_INFO);
        assert.ok(result.instructions.length);
    });

    await t.test('modern: unknown methods are 404 with a method-not-found error', async () => {
        const { body, headers } = modernRequest('prompts/list');
        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });
        assert.equal(outcome.httpStatus, 404);
        assert.equal(outcome.body.error.code, ERROR_CODES.METHOD_NOT_FOUND);
    });

    await t.test('modern: notifications are answered 202 with no body', async () => {
        const { body, headers } = modernRequest('notifications/whatever');
        delete body.id;
        delete headers['mcp-method'];

        const outcome = await processMcpRequest({ body, headers, ctx: ctx() });
        assert.equal(outcome.httpStatus, 202);
        assert.equal(outcome.body, undefined);
    });

    await t.test('modern: subscriptions/listen requires an SSE-accepting client, then hands back a descriptor', async () => {
        const refused = modernRequest('subscriptions/listen', { params: { notifications: { resourceSubscriptions: ['emailengine://account/a'] } } });
        const refusedOutcome = await processMcpRequest({ body: refused.body, headers: refused.headers, ctx: ctx({ acceptsEventStream: false }) });
        assert.equal(refusedOutcome.httpStatus, 400);

        const accepted = modernRequest('subscriptions/listen', { id: 7, params: { notifications: { resourceSubscriptions: ['emailengine://account/a'] } } });
        const outcome = await processMcpRequest({ body: accepted.body, headers: accepted.headers, ctx: ctx({ acceptsEventStream: true }) });
        assert.ok(outcome.listen);
        assert.equal(outcome.listen.id, 7);
        assert.deepEqual(outcome.listen.filter.resourceSubscriptions, ['emailengine://account/a']);
    });

    await t.test('legacy: initialize echoes a supported version and counters an unsupported one', async () => {
        for (const proposed of LEGACY_PROTOCOL_VERSIONS) {
            const outcome = await processMcpRequest({
                body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: proposed, capabilities: {}, clientInfo: {} } },
                headers: {},
                ctx: ctx()
            });
            assert.equal(outcome.body.result.protocolVersion, proposed);
            assert.deepEqual(outcome.body.result.serverInfo, SERVER_INFO);
            assert.equal(outcome.body.result.capabilities.resources.subscribe, false);
        }

        const countered = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: {} } },
            headers: {},
            ctx: ctx()
        });
        assert.equal(countered.body.result.protocolVersion, LEGACY_PROTOCOL_VERSIONS[0]);
    });

    await t.test('legacy: results carry no resultType marker', async () => {
        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
            headers: { 'mcp-protocol-version': '2025-06-18' },
            ctx: ctx()
        });
        assert.equal(outcome.httpStatus, 200);
        assert.deepEqual(outcome.body.result.tools, TOOLS);
        assert.ok(!('resultType' in outcome.body.result));
    });

    await t.test('legacy: unknown methods stay HTTP 200', async () => {
        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 3, method: 'logging/setLevel', params: {} },
            headers: {},
            ctx: ctx()
        });
        assert.equal(outcome.httpStatus, 200);
        assert.equal(outcome.body.error.code, ERROR_CODES.METHOD_NOT_FOUND);
    });

    await t.test('legacy: a modern version header without modern body metadata is a header mismatch', async () => {
        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 4, method: 'ping', params: {} },
            headers: { 'mcp-protocol-version': MODERN_PROTOCOL_VERSION },
            ctx: ctx()
        });
        assert.equal(outcome.httpStatus, 400);
        assert.equal(outcome.body.error.code, ERROR_CODES.HEADER_MISMATCH);
    });

    await t.test('legacy: an unknown version header is refused with the supported list', async () => {
        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 5, method: 'ping', params: {} },
            headers: { 'mcp-protocol-version': '2024-11-05' },
            ctx: ctx()
        });
        assert.equal(outcome.httpStatus, 400);
        assert.equal(outcome.body.error.code, ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION);
    });

    await t.test('legacy: notifications are answered 202', async () => {
        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', method: 'notifications/initialized' },
            headers: {},
            ctx: ctx()
        });
        assert.equal(outcome.httpStatus, 202);
    });

    await t.test('tools/call reports protocol errors from the dispatcher as JSON-RPC errors', async () => {
        const failing = ctx({
            callTool: async () => {
                const err = new Error('Unknown tool: nope');
                err.rpcCode = ERROR_CODES.INVALID_PARAMS;
                throw err;
            }
        });

        const outcome = await processMcpRequest({
            body: { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'nope', arguments: {} } },
            headers: {},
            ctx: failing
        });
        assert.equal(outcome.httpStatus, 200);
        assert.equal(outcome.body.error.code, ERROR_CODES.INVALID_PARAMS);
    });
});
