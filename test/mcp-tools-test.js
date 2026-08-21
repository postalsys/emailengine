'use strict';

// The MCP tool registry and executor (lib/mcp/tools.js).
//
// The registry half runs against the REAL route table via the same capture helper the route-table
// guardrail uses, and locks the derived tool manifest to a golden fixture: the manifest is what
// every connected agent sees, so a joi edit that silently reshapes a tool schema should fail a
// build the same way a /swagger.json drift does. Re-record with UPDATE_MCP_GOLDEN=true.
//
// The executor half runs against a throwaway Hapi server with stub routes, exercising argument
// routing (path/query/payload), error mapping, result capping and the binary path.

const fs = require('fs');
const path = require('path');

const test = require('node:test');
const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');
const Joi = require('joi');

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const { buildToolRegistry, callTool, MAX_TOOL_RESULT_BYTES, MAX_TOOL_BINARY_BYTES } = require('../lib/mcp/tools');
const { surfaceAdmits, routeGrant } = require('../lib/api-routes/permission-map');
const { walkJson: walk } = require('./helpers/walk-json');

const GOLDEN_PATH = path.join(__dirname, 'fixtures', 'mcp-tools-golden.json');
const UPDATE_ENV = 'UPDATE_MCP_GOLDEN';

// Requiring lib/api-routes opens Redis and BullMQ handles that outlive the tests.
registerRedisTeardown(redis);

// A fake outer /mcp request carrying just what callTool() reads
function outerRequest() {
    return {
        auth: { credentials: { token: 'a'.repeat(64) } },
        headers: { 'x-ee-timeout': '5000' },
        app: { ip: '198.51.100.7' }
    };
}

test('MCP tool registry', async t => {
    const { routes } = await captureApiRoutes();
    const { tools, byName } = buildToolRegistry(routes);

    await t.test('the tool manifest matches the golden fixture', () => {
        const manifest = JSON.stringify(tools, null, 4) + '\n';

        if (process.env[UPDATE_ENV] === 'true') {
            fs.writeFileSync(GOLDEN_PATH, manifest);
        }

        assert.ok(fs.existsSync(GOLDEN_PATH), `golden fixture missing - record it with ${UPDATE_ENV}=true npm run test:unit`);

        const golden = fs.readFileSync(GOLDEN_PATH, 'utf-8');
        assert.equal(
            manifest,
            golden,
            `the MCP tool manifest changed. The manifest is what every connected agent sees; if the change is intentional, ` +
                `re-record with ${UPDATE_ENV}=true npm run test:unit and review the fixture diff as part of the change`
        );
    });

    await t.test('every tool stays inside the mcp surface grants', () => {
        // The `mcp` token scope admits an injected request only when surfaceAdmits() says so -
        // the same predicate the api-token strategy calls - so a tool wrapping a route outside
        // that list would exist in the manifest but be uncallable by the very tokens minted for
        // it.
        const outside = [];

        for (const [name, tool] of byName) {
            const route = routes.find(entry => entry.path === tool.path && entry.method === tool.method);
            const grant = routeGrant(route);
            if (!surfaceAdmits('mcp', grant)) {
                outside.push(`${name} (${tool.method.toUpperCase()} ${tool.path} -> ${grant.action}/${grant.group})`);
            }
        }

        assert.deepEqual(outside, [], `tools outside SURFACE_GRANTS.mcp: ${JSON.stringify(outside)}`);
    });

    await t.test('tool schemas are self-contained JSON Schema', () => {
        for (const tool of tools) {
            walk(tool.inputSchema, (node, pointer) => {
                if (node && typeof node === 'object' && !Array.isArray(node)) {
                    for (const key of Object.keys(node)) {
                        assert.ok(key !== '$ref', `${tool.name}: $ref at ${pointer}`);
                        assert.ok(key !== 'nullable', `${tool.name}: OpenAPI nullable at ${pointer}`);
                        assert.ok(!/^x-/.test(key), `${tool.name}: vendor extension ${key} at ${pointer}`);
                    }
                }
            });

            assert.equal(tool.inputSchema.type, 'object', tool.name);
            assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
            assert.ok(tool.description, `${tool.name} has no description`);
        }
    });

    await t.test('omitted arguments stay out of the schema', () => {
        const sendMessage = tools.find(tool => tool.name === 'send_message');
        for (const key of ['proxy', 'localAddress', 'documentStore']) {
            assert.ok(!(key in sendMessage.inputSchema.properties), `send_message must not expose ${key}`);
        }
    });

    await t.test('destructive and sending tools carry honest annotations', () => {
        const annotations = Object.fromEntries(tools.map(tool => [tool.name, tool.annotations]));

        assert.equal(annotations.delete_message.destructiveHint, true);
        assert.equal(annotations.send_message.openWorldHint, true);
        assert.equal(annotations.list_messages.readOnlyHint, true);
        assert.equal(annotations.get_message.readOnlyHint, true);
        assert.equal(annotations.update_message.readOnlyHint, false);
    });
});

test('MCP tool executor', async t => {
    const server = Hapi.server({ port: 0 });

    server.route({
        method: 'GET',
        path: '/v1/demo/{id}',
        handler: request => ({ id: request.params.id, filter: request.query.filter || null, timeout: request.headers['x-ee-timeout'] || null }),
        options: {
            validate: {
                params: Joi.object({ id: Joi.string().required() }),
                query: Joi.object({ filter: Joi.string() })
            },
            plugins: { mcp: { name: 'demo_get', title: 'Demo get', description: 'demo' } }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/demo/{id}/items',
        handler: request => ({ id: request.params.id, received: request.payload }),
        options: {
            validate: {
                params: Joi.object({ id: Joi.string().required() }),
                payload: Joi.object({ value: Joi.string().required(), count: Joi.number().integer() })
            },
            plugins: { mcp: { name: 'demo_post', title: 'Demo post', description: 'demo' } }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/demo/huge',
        handler: () => ({ blob: 'x'.repeat(MAX_TOOL_RESULT_BYTES + 1024) }),
        options: { plugins: { mcp: { name: 'demo_huge', title: 'Demo huge', description: 'demo' } } }
    });

    server.route({
        method: 'GET',
        path: '/v1/demo/huge-utf8',
        handler: () => ({ blob: '世'.repeat(MAX_TOOL_RESULT_BYTES) }),
        options: { plugins: { mcp: { name: 'demo_huge_utf8', title: 'Demo huge utf8', description: 'demo' } } }
    });

    server.route({
        method: 'GET',
        path: '/v1/demo/binary/{size}',
        handler: (request, h) => h.response(Buffer.alloc(Number(request.params.size), 7)).type('application/pdf'),
        options: {
            validate: { params: Joi.object({ size: Joi.number().integer().required() }) },
            plugins: {
                mcp: {
                    name: 'demo_binary',
                    title: 'Demo binary',
                    description: 'demo',
                    binary: true,
                    resourceUriTemplate: 'emailengine://demo/{size}'
                }
            }
        }
    });

    await server.initialize();
    const { byName } = buildToolRegistry(server.table());

    await t.test('routes arguments to path, query and payload', async () => {
        const getResult = await callTool({ server, tool: byName.get('demo_get'), args: { id: 'a b', filter: 'unread' }, request: outerRequest() });
        assert.deepEqual(JSON.parse(getResult.content[0].text), { id: 'a b', filter: 'unread', timeout: '5000' });
        assert.equal(getResult.structuredContent.id, 'a b');

        const postResult = await callTool({ server, tool: byName.get('demo_post'), args: { id: 'x', value: 'v', count: 2 }, request: outerRequest() });
        assert.deepEqual(JSON.parse(postResult.content[0].text).received, { value: 'v', count: 2 });
    });

    await t.test('unknown arguments are refused before any request is made', async () => {
        const result = await callTool({ server, tool: byName.get('demo_get'), args: { id: 'x', nope: 1 }, request: outerRequest() });
        assert.equal(result.isError, true);
        assert.match(result.content[0].text, /nope/);
    });

    await t.test('API validation errors come back as tool errors, not exceptions', async () => {
        // A value the schema refuses reaches the injected request and fails there. The stub
        // server keeps hapi's terse default failAction; the production routes attach their own
        // detailed one, so only the error mapping is asserted here.
        const result = await callTool({ server, tool: byName.get('demo_post'), args: { id: 'x', value: 'v', count: 'not-a-number' }, request: outerRequest() });
        assert.equal(result.isError, true);
        assert.match(result.content[0].text, /Bad Request/);
    });

    await t.test('oversized results are truncated and lose structuredContent', async () => {
        const result = await callTool({ server, tool: byName.get('demo_huge'), args: {}, request: outerRequest() });
        assert.ok(!result.isError);
        assert.ok(Buffer.byteLength(result.content[0].text) < MAX_TOOL_RESULT_BYTES + 1024);
        assert.match(result.content[0].text, /Result truncated by EmailEngine/);
        assert.ok(!('structuredContent' in result));
    });

    await t.test('the size cap is measured in bytes, so multibyte results are really truncated', async () => {
        // String.slice() counts UTF-16 code units: a result of CJK text is ~3 bytes per unit, so
        // slicing at the byte cap returned the whole thing while claiming it had been truncated
        const result = await callTool({ server, tool: byName.get('demo_huge_utf8'), args: {}, request: outerRequest() });

        assert.ok(!result.isError);
        assert.match(result.content[0].text, /Result truncated by EmailEngine/);
        assert.ok(
            Buffer.byteLength(result.content[0].text) < MAX_TOOL_RESULT_BYTES + 1024,
            `expected the result to respect the byte cap, got ${Buffer.byteLength(result.content[0].text)} bytes`
        );
        // and the cut never splits a code point into a replacement character
        assert.ok(!result.content[0].text.includes('�'), 'truncation must not split a multibyte character');
    });

    await t.test('a missing required argument is named, rather than becoming a bare 404', async () => {
        // Omitting a path parameter renders an empty path segment, which Hapi answers with a
        // plain "Not Found" that names neither the tool nor the argument
        const result = await callTool({ server, tool: byName.get('demo_get'), args: {}, request: outerRequest() });

        assert.equal(result.isError, true);
        assert.match(result.content[0].text, /Missing required tool argument: id/);
    });

    await t.test('binary tools return an embedded base64 resource, capped', async () => {
        const small = await callTool({ server, tool: byName.get('demo_binary'), args: { size: 1024 }, request: outerRequest() });
        assert.equal(small.content[0].type, 'resource');
        assert.equal(small.content[0].resource.uri, 'emailengine://demo/1024');
        assert.equal(small.content[0].resource.mimeType, 'application/pdf');
        assert.equal(Buffer.from(small.content[0].resource.blob, 'base64').length, 1024);

        const large = await callTool({ server, tool: byName.get('demo_binary'), args: { size: MAX_TOOL_BINARY_BYTES + 1 }, request: outerRequest() });
        assert.equal(large.isError, true);
        assert.match(large.content[0].text, /REST API/);
    });

    await server.stop();
});
