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
const { buildToolRegistry, callTool, toolVisibleTo, toolDefinitionFor, MAX_TOOL_RESULT_BYTES, MAX_TOOL_BINARY_BYTES } = require('../lib/mcp/tools');
const { surfaceAdmits, routeGrant, ACTION, GROUP } = require('../lib/api-routes/permission-map');
const { MCP_MAX_PAGE_SIZE } = require('../lib/consts');
const { MCP_READ_ONLY_PERMISSIONS, MCP_MAIL_AGENT_PERMISSIONS } = require('../lib/token-permission-view');
const { walkJson: walk } = require('./helpers/walk-json');

const GOLDEN_PATH = path.join(__dirname, 'fixtures', 'mcp-tools-golden.json');
const UPDATE_ENV = 'UPDATE_MCP_GOLDEN';

// Requiring lib/api-routes opens Redis and BullMQ handles that outlive the tests.
registerRedisTeardown(redis);

// A fake outer /mcp request carrying just what callTool() reads. `boundAccount` mirrors what the
// api-token strategy parks on request.app for an account-bound credential.
function outerRequest(boundAccount) {
    return {
        auth: { credentials: { token: 'a'.repeat(64) } },
        headers: { 'x-ee-timeout': '5000' },
        app: { ip: '198.51.100.7', mcpBoundAccount: boundAccount }
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

            // The grant stored on the registry entry is what tools/list filters a narrowed
            // credential's catalog by, so it has to be the same operation the inner request
            // will enforce - re-derived here rather than trusted
            assert.deepEqual(tool.grant, grant, `${name}: stored grant differs from routeGrant()`);
        }

        assert.deepEqual(outside, [], `tools outside SURFACE_GRANTS.mcp: ${JSON.stringify(outside)}`);
    });

    await t.test('the admin pages predict the same catalog tools/list advertises', () => {
        // The three pages that mint an mcp-scoped token report how many tools the credential
        // would be offered. They run in a browser, where neither toolVisibleTo() nor the
        // permission checker can be called, so they apply a two-allowlist model over the data
        // toolGrants() hands them. This asserts the two agree over the whole catalog: if the
        // enforcement grows a rule the pages do not know about, the count starts promising an
        // agent tools it will not receive, and only this test would notice.
        //
        // Not a re-implementation of the rule under test - it is the browser's simplified model,
        // written out once here so its equivalence is checked rather than assumed. The page-side
        // copy lives in uiMcpToolCount() in static/js/ui.js.
        const grants = tools.map(tool => {
            const entry = byName.get(tool.name);
            return { name: tool.name, accountScoped: entry.sources.has('account'), ...entry.grant };
        });

        const browserModel = (record, boundAccount) =>
            grants
                .filter(tool => !boundAccount || tool.accountScoped)
                .filter(tool => !record || (record.actions.includes(tool.action) && record.groups.includes(tool.group)))
                .map(tool => tool.name);

        const enforced = (record, boundAccount) =>
            tools.filter(tool => toolVisibleTo(byName.get(tool.name), { tokenData: { permissions: record }, boundAccount })).map(tool => tool.name);

        // Every level the pages offer, plus the shapes a hand-built custom record takes: one axis
        // emptied out, and one section that carries no tool at all
        const records = [
            null,
            MCP_READ_ONLY_PERMISSIONS,
            MCP_MAIL_AGENT_PERMISSIONS,
            { actions: [ACTION.DESTRUCTIVE], groups: [GROUP.MESSAGE] },
            { actions: [ACTION.READ], groups: [GROUP.WEBHOOK] },
            { actions: [], groups: [] }
        ];

        for (const record of records) {
            for (const boundAccount of [null, 'acct-1']) {
                assert.deepEqual(
                    browserModel(record, boundAccount),
                    enforced(record, boundAccount),
                    `the browser tool count disagrees with tools/list for ${JSON.stringify(record)} (bound: ${boundAccount})`
                );
            }
        }
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

    await t.test('the composition tools expose the message, not the operator settings around it', () => {
        // The exhaustive property set is locked by the golden fixture. What is asserted here is
        // the intent behind it, so a re-record cannot quietly wave through the entries that
        // matter: `raw` and `envelope` are each a way around the structured fields the tool is
        // made of, and `mailMerge` would turn one call into a bulk send.
        for (const [name, keys] of Object.entries({
            send_message: ['raw', 'envelope', 'mailMerge', 'headers', 'gateway'],
            create_draft: ['raw', 'headers']
        })) {
            const tool = tools.find(entry => entry.name === name);
            for (const key of keys) {
                assert.ok(!(key in tool.inputSchema.properties), `${name} must not expose ${key}`);
            }
        }

        // ...and still take the message itself, so the narrowing cannot hollow the tool out
        const sendMessage = tools.find(tool => tool.name === 'send_message');
        for (const key of ['to', 'subject', 'text', 'html', 'reference', 'attachments']) {
            assert.ok(key in sendMessage.inputSchema.properties, `send_message must expose ${key}`);
        }
    });

    await t.test('the body-rendering knobs are pinned rather than offered', () => {
        // One canonical body shape is what an agent can reason about, so the tools that return a
        // message body neither ask which rendering to produce nor let the caller pick one
        for (const [name, pinned] of [
            ['get_message', { webSafeHtml: true, embedAttachedImages: false }],
            ['get_message_text', { webSafeHtml: true }]
        ]) {
            const tool = tools.find(entry => entry.name === name);
            for (const key of ['textType', 'webSafeHtml', 'preProcessHtml', 'embedAttachedImages', 'maxBytes']) {
                assert.ok(!(key in tool.inputSchema.properties), `${name} must not expose ${key}`);
            }

            // The rendering is pinned to one shape; the budget beside it is a number the golden
            // fixture records and the test below relates to the result cap, so here it only has to
            // be present
            const forced = byName.get(name).forcedValues;
            assert.deepEqual(Object.fromEntries(Object.entries(forced).filter(([key]) => key !== 'maxBytes')), pinned, name);
            assert.equal(typeof forced.maxBytes, 'number', `${name} must pin a body budget`);
        }
    });

    await t.test('the two body budgets leave margin under the result cap, and the follow-up tool is the larger one', () => {
        // get_message caps the body it inlines and tells the model get_message_text returns more of
        // it, so a text budget at or below the message budget would make that pointer a dead end.
        //
        // The margin is the other half. A budget merely BELOW the cap would not establish that a
        // result fits: maxBytes counts characters per text part before the web-safe rendering, and
        // that rendering reads both parts and can come out larger than either. Half the cap is
        // what keeps a normal message clear of a truncation that hands the caller a JSON fragment
        // it cannot parse.
        const bodyBudget = byName.get('get_message').forcedValues.maxBytes;
        const textBudget = byName.get('get_message_text').forcedValues.maxBytes;

        assert.ok(textBudget > bodyBudget, `get_message_text (${textBudget}) must return more than get_message (${bodyBudget})`);
        assert.ok(
            textBudget <= MAX_TOOL_RESULT_BYTES / 2,
            `get_message_text (${textBudget}) leaves no margin under MAX_TOOL_RESULT_BYTES (${MAX_TOOL_RESULT_BYTES})`
        );
    });

    await t.test('every listing tool advertises a page a model can afford', () => {
        // Asserted over the whole catalog rather than the five known listings, so one added later
        // cannot quietly ship the route's own 1000 (see MCP_MAX_PAGE_SIZE for why it must not)
        for (const entry of byName.values()) {
            const pageSize = entry.definition.inputSchema.properties.pageSize;
            if (!pageSize) {
                continue;
            }
            assert.equal(pageSize.maximum, MCP_MAX_PAGE_SIZE, `${entry.definition.name} advertises pageSize up to ${pageSize.maximum}`);
            assert.equal(entry.bounds.get('pageSize'), MCP_MAX_PAGE_SIZE, `${entry.definition.name} does not clamp pageSize on dispatch`);
        }
    });

    await t.test('a forced argument is never also an offered one', () => {
        // Advertising an argument whose value is then discarded reads to the model as a control it
        // does not have, so the builder refuses `force` without a matching `omit`. Asserted over
        // the real catalog as well, in case a route declares one half of the pair.
        for (const entry of byName.values()) {
            for (const key of Object.keys(entry.forcedValues)) {
                assert.ok(!(key in entry.definition.inputSchema.properties), `${entry.definition.name}: ${key} is both forced and offered`);
            }
        }
    });

    await t.test('the body tools tell the model where the quoted thread starts', () => {
        // The collapse marker is the machine-readable "show more" boundary, and it is only useful
        // to an agent that has been told the class name means that
        for (const name of ['get_message', 'get_message_text']) {
            const tool = tools.find(entry => entry.name === name);
            assert.match(tool.description, /ee-collapsed-thread/, `${name} must name the collapse marker`);
        }
    });

    await t.test('a bound credential is offered tools that take no account argument', () => {
        // The endpoint already knows which account the credential reaches. Asking the model for it
        // anyway asks for a value it cannot look up - the same credential is refused list_accounts.
        for (const tool of tools) {
            const entry = byName.get(tool.name);
            if (!entry.sources.has('account')) {
                continue;
            }

            const bound = toolDefinitionFor(entry, { boundAccount: 'acct-1' });

            assert.ok('account' in tool.inputSchema.properties, `${tool.name}: unbound definition must still take an account`);
            assert.ok(!('account' in bound.inputSchema.properties), `${tool.name}: bound definition must not take an account`);
            assert.ok(!(bound.inputSchema.required || []).includes('account'), `${tool.name}: bound definition must not require an account`);

            // Nothing else about the tool changes, and the shared definition is not mutated
            assert.equal(bound.name, tool.name);
            assert.deepEqual(
                Object.keys(bound.inputSchema.properties),
                Object.keys(tool.inputSchema.properties).filter(key => key !== 'account')
            );
            assert.ok('account' in toolDefinitionFor(entry, {}).inputSchema.properties, `${tool.name}: the unbound definition was mutated`);
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

    // Mirrors what the message routes wrap: an account-scoped tool with pinned rendering arguments,
    // answering with the bodies under `text` and the web-safe marker beside them
    server.route({
        method: 'GET',
        path: '/v1/demo/account/{account}/message/{message}',
        handler: request => ({
            account: request.params.account,
            asked: request.query,
            text: { html: '<p>hello</p>', plain: 'hello', webSafe: request.query.preProcessHtml === 'true' }
        }),
        options: {
            validate: {
                params: Joi.object({ account: Joi.string().required(), message: Joi.string().required() }),
                query: Joi.object({ textType: Joi.string(), preProcessHtml: Joi.string(), markAsSeen: Joi.string() })
            },
            plugins: {
                mcp: {
                    name: 'demo_message',
                    title: 'Demo message',
                    description: 'demo',
                    omit: ['textType', 'preProcessHtml'],
                    force: { textType: '*', preProcessHtml: 'true' }
                }
            }
        }
    });

    // Mirrors what the listing routes wrap: a page size the REST schema takes in full and the tool
    // narrows, so the clamp can be exercised without depending on a real listing's numbers
    server.route({
        method: 'GET',
        path: '/v1/demo/listing',
        handler: request => ({ pageSize: request.query.pageSize }),
        options: {
            validate: { query: Joi.object({ pageSize: Joi.number().integer().min(1).max(1000).default(20) }) },
            plugins: { mcp: { name: 'demo_listing', title: 'Demo listing', description: 'demo', bounds: { pageSize: 100 } } }
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

    await t.test('a bounded argument is narrowed in the schema and clamped on dispatch', async () => {
        // Two halves of one bound. The schema half is what a well-behaved client never exceeds;
        // the dispatch half is what holds for a client that ignores the schema, or a model that
        // repeats a number it saw elsewhere.
        assert.equal(byName.get('demo_listing').definition.inputSchema.properties.pageSize.maximum, 100);

        for (const [asked, expected] of [
            [1000, 100],
            ['1000', 100],
            [50, 50],
            [undefined, 20]
        ]) {
            const result = await callTool({
                server,
                tool: byName.get('demo_listing'),
                args: asked === undefined ? {} : { pageSize: asked },
                request: outerRequest()
            });
            assert.equal(JSON.parse(result.content[0].text).pageSize, expected, `pageSize ${asked}`);
        }
    });

    await t.test('a bound that does not narrow an exposed argument is refused at build time', () => {
        const route = bounds => ({
            method: 'get',
            path: '/v1/demo/bounded',
            settings: {
                validate: { query: Joi.object({ pageSize: Joi.number().integer().max(1000), name: Joi.string() }) },
                plugins: { mcp: { name: 'demo_bounded', title: 'Demo', description: 'demo', bounds } }
            }
        });

        assert.throws(() => buildToolRegistry([route({ missing: 10 })]), /bounded argument missing is not an exposed argument/);
        assert.throws(() => buildToolRegistry([route({ pageSize: 1000 })]), /does not narrow the schema maximum/);
        assert.throws(() => buildToolRegistry([route({ name: 10 })]), /does not narrow the schema maximum/);
    });

    await t.test('a declaration that hides nothing, or hides too much, is refused at build time', () => {
        // Every knob in a plugins.mcp block hides or pins something on the agent-facing schema, so
        // a knob that quietly does nothing is the opposite of what was declared - a misspelled key
        // under `omit` leaves the argument exposed, one under `keep` leaves it hidden.
        const route = mcp => ({
            method: 'post',
            path: '/v1/demo/declared',
            settings: {
                validate: {
                    params: Joi.object({ account: Joi.string().required() }),
                    payload: Joi.object({ subject: Joi.string(), raw: Joi.string() })
                },
                plugins: { mcp: Object.assign({ name: 'demo_declared', title: 'Demo', description: 'demo' }, mcp) }
            }
        });

        assert.throws(() => buildToolRegistry([route({ omit: ['nosuch'] })]), /omitted argument nosuch is not an argument/);
        assert.throws(() => buildToolRegistry([route({ keep: ['nosuch'] })]), /kept argument nosuch is not an argument/);
        assert.throws(() => buildToolRegistry([route({ keep: ['subject'], omit: ['raw'] })]), /declare either keep or omit, not both/);
        assert.throws(() => buildToolRegistry([route({ bound: { subject: 1 } })]), /unknown plugins\.mcp option: bound/);

        // A required argument the tool does not offer and does not force is a tool whose every
        // call dies on the same joi 400, with nothing the model can do about it
        assert.throws(() => buildToolRegistry([route({ keep: ['subject'] })]), /required argument account is hidden but not forced/);
        assert.throws(() => buildToolRegistry([route({ omit: ['account'] })]), /required argument account is hidden but not forced/);
        assert.doesNotThrow(() => buildToolRegistry([route({ omit: ['account'], force: { account: 'pinned' } })]));
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

    await t.test("forced arguments are sent, and are not the caller's to set", async () => {
        const result = await callTool({ server, tool: byName.get('demo_message'), args: { account: 'acct-1', message: 'msg-1' }, request: outerRequest() });
        assert.deepEqual(JSON.parse(result.content[0].text).asked, { textType: '*', preProcessHtml: 'true' });

        // A forced key is omitted from the schema, so naming it is naming an argument the tool
        // does not have - refused, rather than accepted and then quietly overridden
        const refused = await callTool({
            server,
            tool: byName.get('demo_message'),
            args: { account: 'acct-1', message: 'msg-1', textType: 'plain' },
            request: outerRequest()
        });
        assert.equal(refused.isError, true);
        assert.match(refused.content[0].text, /Unknown tool argument: textType/);
    });

    await t.test('the plaintext twin is dropped from a web-safe body', async () => {
        // The generated HTML is built from both parts, so returning the plaintext beside it is the
        // same message twice - on the largest results this endpoint produces
        const message = await callTool({ server, tool: byName.get('demo_message'), args: { account: 'a', message: 'm' }, request: outerRequest() });
        const messageBody = JSON.parse(message.content[0].text);
        assert.equal(messageBody.text.webSafe, true);
        assert.equal(messageBody.text.html, '<p>hello</p>');
        assert.ok(!('plain' in messageBody.text), 'the plaintext twin must not survive');

        // A response the API did not mark web-safe keeps whatever it carries: the rule is keyed on
        // the marker, not on a tool name
        const raw = await callTool({ server, tool: byName.get('demo_get'), args: { id: 'x' }, request: outerRequest() });
        assert.equal(JSON.parse(raw.content[0].text).id, 'x');
    });

    await t.test('a bound credential does not have to name its account', async () => {
        const filled = await callTool({ server, tool: byName.get('demo_message'), args: { message: 'msg-1' }, request: outerRequest('acct-9') });
        assert.equal(JSON.parse(filled.content[0].text).account, 'acct-9');

        // An account the caller does send is passed through rather than silently rewritten: the
        // mismatch is the inner request's 403 to give, not this layer's to paper over
        const explicit = await callTool({
            server,
            tool: byName.get('demo_message'),
            args: { account: 'acct-other', message: 'msg-1' },
            request: outerRequest('acct-9')
        });
        assert.equal(JSON.parse(explicit.content[0].text).account, 'acct-other');

        // and without a binding the argument is still required, named rather than 404ed
        const missing = await callTool({ server, tool: byName.get('demo_message'), args: { message: 'msg-1' }, request: outerRequest() });
        assert.equal(missing.isError, true);
        assert.match(missing.content[0].text, /Missing required tool argument: account/);
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
