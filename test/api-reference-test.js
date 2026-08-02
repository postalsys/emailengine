'use strict';

// Unit tests for the API reference model (lib/api-reference/).
//
// The spec is generated in-process from the REAL route table (test/helpers/build-openapi-spec.js)
// rather than read from swagger.json, which is gitignored - `npm run swagger` writes it by
// booting a server, so it is absent on a fresh checkout and in CI. Generating it here also
// means these assertions run against what the current routes actually produce, so a route
// whose spec entry regresses (a missing 2xx, an unresolvable $ref) fails here.
//
// Only the pure modules of lib/api-reference are exercised here; the request-scoped half
// (lib/api-reference/index.js) is covered by test/e2e/reference.spec.js against a live server.

const { test, before } = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { buildOpenApiSpec } = require('./helpers/build-openapi-spec');

const { buildModel } = require('../lib/api-reference/model');
const { buildSchemaTree, buildExample, typeLabel } = require('../lib/api-reference/schema-tree');
const { buildCodeSamples } = require('../lib/api-reference/code-samples');
const { formatDescription, slugify, constraintList } = require('../lib/api-reference/format');

let spec;
let model;
let allOperations;

before(async () => {
    spec = await buildOpenApiSpec();
    model = buildModel(spec);
    allOperations = model.tags.flatMap(tag => tag.operations);
});

// Requiring lib/api-routes opens Redis and BullMQ handles that outlive the tests.
registerRedisTeardown(redis);

function walkTree(node, visit) {
    if (!node) {
        return;
    }
    visit(node);
    for (const child of node.children || []) {
        walkTree(child, visit);
    }
    for (const variant of node.variants || []) {
        walkTree(variant, visit);
    }
}

function everyTree(visit) {
    for (const operation of allOperations) {
        if (operation.body) {
            walkTree(operation.body.tree, visit);
        }
        for (const response of operation.responses) {
            walkTree(response.tree, visit);
        }
    }
}

test('API reference model', async t => {
    await t.test('covers every operation in the spec', () => {
        const specOperations = Object.values(spec.paths).flatMap(pathItem =>
            Object.keys(pathItem).filter(key => ['get', 'post', 'put', 'patch', 'delete'].includes(key))
        );

        assert.equal(allOperations.length, specOperations.length);
        assert.ok(model.tags.length > 10);
    });

    await t.test('operation ids and tab ids are unique across the document', () => {
        const ids = allOperations.map(operation => operation.id);
        assert.equal(new Set(ids).size, ids.length, 'operationIds collide');

        const tabIds = allOperations.flatMap(operation => operation.responses.map(response => response.tabId));
        assert.equal(new Set(tabIds).size, tabIds.length, 'response tab ids collide');
    });

    await t.test('every operation declares a success response in the spec', () => {
        // The streaming and binary downloads have no response.schema for hapi-swagger to
        // derive a 200 from, so they need an explicit entry (streamResponses() in
        // lib/schemas.js). Without it the generated spec documents only their error cases
        // and EVERY consumer - Swagger UI, Postman, code generators - sees an operation
        // with no success response.
        const missing = [];
        for (const path of Object.keys(spec.paths)) {
            for (const method of Object.keys(spec.paths[path])) {
                const codes = Object.keys(spec.paths[path][method].responses || {});
                if (!codes.some(code => /^2/.test(code))) {
                    missing.push(`${method.toUpperCase()} ${path}`);
                }
            }
        }
        assert.deepEqual(missing, []);
    });

    await t.test('the model carries a success response through for every operation', () => {
        for (const operation of allOperations) {
            const success = operation.responses.filter(response => response.variant === 'success');
            assert.ok(success.length, `${operation.methodLabel} ${operation.path} has no 2xx response`);
        }

        // the binary download is the case that used to be missing entirely
        const download = allOperations.find(operation => operation.id === 'getV1AccountAccountAttachmentAttachment');
        assert.ok(download);
        assert.ok(download.responses.some(response => response.code === '200'));
    });

    await t.test('every operation documents what its success response returns', () => {
        // "Successful" is hapi-swagger's placeholder; apiResponses() in lib/schemas.js
        // replaces it with prose per operation, which is what a caller actually needs
        const placeholder = [];
        for (const path of Object.keys(spec.paths)) {
            for (const method of Object.keys(spec.paths[path])) {
                const ok = (spec.paths[path][method].responses || {})['200'];
                if (!ok || !ok.description || ok.description === 'Successful') {
                    placeholder.push(`${method.toUpperCase()} ${path}`);
                }
            }
        }
        assert.deepEqual(placeholder, []);
    });

    await t.test('documented enum values reach the model with their descriptions', () => {
        const documented = [];
        everyTree(node => {
            if (node.enumDocumented) {
                documented.push(node);
            }
        });

        assert.ok(documented.length, 'no enum carried per-value descriptions');

        // every value of a documented enum must be described - a half-filled map is worse
        // than none, because the gaps read as "this value means nothing"
        for (const node of documented) {
            for (const entry of node.enumValues) {
                assert.ok(entry.description, `${node.name}: value "${entry.value}" has no description`);
            }
        }

        // the account state is the one operators hit most, so assert it specifically
        const state = documented.find(node => node.enumValues.some(entry => entry.value === 'authenticationError'));
        assert.ok(state, 'account state enum is not documented');
        assert.match(state.enumValues.find(entry => entry.value === 'connected').description, /steady state/);
    });

    await t.test('behavior notes reach the operations that need them', () => {
        const withBehavior = allOperations.filter(operation => operation.behavior.length);
        assert.ok(withBehavior.length >= 15, `only ${withBehavior.length} operations carry behavior notes`);

        // submitting is the case the notes exist for: a 2xx means queued, not sent
        const submit = allOperations.find(operation => operation.id === 'postV1AccountAccountSubmit');
        assert.ok(submit.behavior.length);
        assert.ok(
            submit.behavior.some(note => /queued, not that it was sent/.test(note)),
            'the submit operation does not warn that a 2xx only means queued'
        );

        // notes are pre-escaped for the template's triple stash
        for (const operation of allOperations) {
            for (const note of operation.behavior) {
                assert.ok(!/<(?!code|a|br|\/)/.test(note), `unexpected markup in a behavior note on ${operation.id}`);
            }
        }
    });

    await t.test('behavior notes also reach the standard description field', () => {
        // Routes declare each note twice: in the `notes` array, which hapi-swagger joins
        // into `description` for every consumer of the spec, and under x-ee-behavior so
        // this renderer can pull it into a callout. A note present in only the extension
        // would be invisible to Postman, Redoc and code generators - which is the audience
        // most likely to ship "a 2xx means sent".
        const missing = [];
        for (const path of Object.keys(spec.paths)) {
            for (const method of Object.keys(spec.paths[path])) {
                const operation = spec.paths[path][method];
                for (const note of operation['x-ee-behavior'] || []) {
                    if (!(operation.description || '').includes(note)) {
                        missing.push(`${method.toUpperCase()} ${path}: ${note.slice(0, 50)}...`);
                    }
                }
            }
        }
        assert.deepEqual(missing, []);
    });

    await t.test('the operation prose does not repeat its behavior notes', () => {
        // The notes arrive inside `description`, so the model has to strip them back out or
        // the page shows each one twice - once in the prose, once in the callout.
        for (const operation of allOperations) {
            for (const note of operation.behavior) {
                assert.ok(!operation.descriptionHtml.includes(note), `${operation.id} renders a behavior note in its prose as well as the callout`);
            }
        }
    });

    await t.test('every schema node resolves to a concrete type', () => {
        // "any" means a $ref the tree builder failed to follow - the bug that made
        // 46 array properties render as "array of any"
        const unresolved = [];
        everyTree(node => {
            if (!node.typeLabel || node.typeLabel.includes('any')) {
                unresolved.push(`${node.name || '(root)'}: ${node.typeLabel}`);
            }
        });
        assert.deepEqual(unresolved, []);
    });

    await t.test('no schema node is left circular or truncated', () => {
        const flagged = [];
        everyTree(node => {
            if (node.circular || node.truncated || node.unresolved) {
                flagged.push(node.name);
            }
        });
        assert.deepEqual(flagged, []);
    });

    await t.test('anyOf branches are rendered as variants', () => {
        const variants = [];
        everyTree(node => {
            if (node.variants.length) {
                variants.push(node.typeLabel);
            }
        });

        assert.ok(variants.length, 'no anyOf nodes found');
        // x-alt-definitions refs must be resolved for the summary line to be useful
        for (const label of variants) {
            assert.ok(label.includes(' or '), `variant label not composed: ${label}`);
        }
    });

    await t.test('joi extensions become constraint chips', () => {
        const chips = constraintList({
            type: 'string',
            maxLength: 256,
            'x-convert': { trim: true, case: 'lower' },
            'x-format': { uri: { scheme: ['http', 'https'] } },
            'x-constraint': { single: true }
        });

        assert.deepEqual(chips, ['max 256 chars', 'URI (http, https)', 'trimmed', 'lowercased', 'single value allowed']);
    });

    await t.test('array item types are resolved through $ref', () => {
        const tree = buildSchemaTree(spec, { $ref: '#/components/schemas/AccountsFilterResponse' });
        assert.ok(tree);

        const arrays = [];
        walkTree(tree, node => {
            if ((node.typeLabel || '').startsWith('array of')) {
                arrays.push(node.typeLabel);
            }
        });

        assert.ok(arrays.length);
        assert.ok(!arrays.some(label => label.endsWith('any')));
    });
});

test('API reference examples', async t => {
    await t.test('every JSON response carries an example', () => {
        const missing = [];
        for (const operation of allOperations) {
            for (const response of operation.responses) {
                if (response.tree && !response.exampleJson) {
                    missing.push(`${operation.id} ${response.code}`);
                }
            }
        }
        assert.deepEqual(missing, []);
    });

    await t.test('examples are valid JSON', () => {
        for (const operation of allOperations) {
            if (operation.body && operation.body.exampleJson) {
                assert.doesNotThrow(() => JSON.parse(operation.body.exampleJson), `${operation.id} request example`);
            }
            for (const response of operation.responses) {
                if (response.exampleJson) {
                    assert.doesNotThrow(() => JSON.parse(response.exampleJson), `${operation.id} ${response.code} example`);
                }
            }
        }
    });

    await t.test('a schema example wins over synthesis', () => {
        const value = buildExample(spec, { type: 'string', example: 'chosen', default: 'ignored' });
        assert.equal(value, 'chosen');
    });

    await t.test('scalars without an example fall back to default, enum, then format', () => {
        assert.equal(buildExample(spec, { type: 'string', default: 'fallback' }), 'fallback');
        assert.equal(buildExample(spec, { type: 'string', enum: ['first', 'second'] }), 'first');
        assert.equal(buildExample(spec, { type: 'string', format: 'date-time' }), '2026-01-15T09:30:00.000Z');
        assert.equal(buildExample(spec, { type: 'boolean' }), false);
    });
});

test('API reference code samples', async t => {
    const operation = allOperations.find(entry => entry.id === 'postV1AccountAccountSubmit');

    await t.test('fills path parameters and keeps the three languages runnable', () => {
        const samples = buildCodeSamples(operation, 'https://ee.example.com', operation.body.exampleValue, operation.body.exampleJson);

        assert.deepEqual(
            samples.map(sample => sample.id),
            ['curl', 'node', 'python']
        );
        assert.ok(samples[0].active);

        for (const sample of samples) {
            // no unsubstituted path placeholders, and the token comes from the env var
            assert.ok(!sample.code.includes('{account}'), `${sample.id} left a path placeholder`);
            assert.ok(sample.code.includes('EMAILENGINE_TOKEN'), `${sample.id} does not read the token`);
            assert.ok(sample.code.includes('https://ee.example.com/v1/account/'), `${sample.id} lost the base URL`);
        }
    });

    await t.test('python samples emit python literals, not JSON', () => {
        const withBooleans = allOperations.find(entry => entry.body && /: (true|false)/.test(entry.body.exampleJson || ''));

        assert.ok(withBooleans, 'no operation with a boolean in its example');

        const samples = buildCodeSamples(withBooleans, 'https://ee.example.com', withBooleans.body.exampleValue, withBooleans.body.exampleJson);
        const python = samples.find(sample => sample.id === 'python').code;

        assert.ok(/\b(True|False)\b/.test(python));
        assert.ok(!/: true|: false/.test(python.split('json=')[1] || ''));
    });

    await t.test('single quotes in a body are escaped for the shell', () => {
        const samples = buildCodeSamples(
            { method: 'post', path: '/v1/x', pathParams: [], queryParams: [], id: 'x' },
            'https://e.test',
            { a: "it's" },
            `{"a":"it's"}`
        );

        const curl = samples[0].code;
        assert.ok(curl.includes(`'\\''`), 'single quote not escaped');
    });
});

test('API reference formatting', async t => {
    await t.test('escapes markup before adding its own tags back', () => {
        // The templateHtmlHead description documents injecting into the <head> section
        const html = formatDescription('Custom HTML to inject into the <head> section');
        assert.ok(html.includes('&lt;head&gt;'));
        assert.ok(!html.includes('<head>'));
    });

    await t.test('renders code spans and safe links only', () => {
        assert.equal(formatDescription('use `null` here'), 'use <code class="ee-code">null</code> here');

        const link = formatDescription('see [docs](https://example.com/x)');
        assert.ok(link.includes('href="https://example.com/x"'));

        // a javascript: target is left as literal text
        const unsafe = formatDescription('see [x](javascript:alert(1))');
        assert.ok(!unsafe.includes('href'));
        assert.ok(!unsafe.includes('javascript:alert(1)</a>'));
    });

    await t.test('slugs match the route parameter pattern', () => {
        for (const tag of model.tags) {
            assert.match(tag.slug, /^[a-z0-9-]+$/, `${tag.name} -> ${tag.slug}`);
        }

        assert.equal(slugify('Export (Beta)'), 'export-beta');
        assert.equal(slugify('SMTP Gateway'), 'smtp-gateway');
    });

    await t.test('slugs are unique', () => {
        const slugs = model.tags.map(tag => tag.slug);
        assert.equal(new Set(slugs).size, slugs.length);
    });

    await t.test('no slug collides with a literal route under /admin/reference', () => {
        // hapi routes a literal path segment ahead of /{tag}, so a tag slugging to one of
        // these would render the literal page instead of the group - silently unreachable
        const RESERVED_SLUGS = ['token'];

        for (const tag of model.tags) {
            assert.ok(!RESERVED_SLUGS.includes(tag.slug), `tag "${tag.name}" slugs to the reserved "${tag.slug}"`);
        }
    });

    await t.test('labels arrays by their item type, following $refs', () => {
        assert.equal(typeLabel(spec, { type: 'array', items: { type: 'string' } }), 'array of string');
        assert.equal(typeLabel(spec, { type: 'object' }), 'object');
        assert.equal(typeLabel(spec, {}), 'any');

        // the case a spec-free implementation cannot answer: items behind a $ref
        const refName = Object.keys(spec.components.schemas).find(name => spec.components.schemas[name].type === 'object');
        assert.equal(typeLabel(spec, { type: 'array', items: { $ref: `#/components/schemas/${refName}` } }), 'array of object');
    });
});
