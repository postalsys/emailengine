'use strict';

// Golden-document guard for the generated OpenAPI specification.
//
// /swagger.json is a public product surface: it is served by every instance, mirrored on
// emailengine.dev, and consumed by Postman and code generators. Nothing else in the suite notices
// when a joi schema edit quietly changes it, so this test records the whole document and fails on
// any drift. An intentional change is re-recorded with UPDATE_OPENAPI_GOLDEN=true, which puts the
// spec diff in the commit where it can be reviewed.
//
// The companion test/api-reference-test.js asserts structural invariants (every operation has a
// success response, every $ref resolves). This one is deliberately dumber and only asks "is the
// document byte for byte what we last agreed to publish".

const fs = require('fs');
const path = require('path');

const { test, before } = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { buildOpenApiSpec } = require('./helpers/build-openapi-spec');

const GOLDEN_PATH = path.join(__dirname, 'fixtures', 'openapi-golden.json');

// How the failure message tells a developer to re-record the file. Kept next to the writer so the
// instruction and the mechanism cannot drift apart.
const UPDATE_ENV = 'UPDATE_OPENAPI_GOLDEN';

// A single changed helper schema can shift hundreds of pointers, and the first few are enough to
// identify it.
const REPORTED_DIFFERENCES = 25;

let spec;

before(async () => {
    spec = await buildOpenApiSpec();
});

// Requiring lib/api-routes opens Redis and BullMQ handles that outlive the tests.
registerRedisTeardown(redis);

function describeValue(value) {
    if (typeof value === 'undefined') {
        return '(missing)';
    }

    const json = JSON.stringify(value);

    return json.length > 120 ? `${json.slice(0, 120)}...` : json;
}

// Lists the JSON pointers where the two documents differ. assert.deepEqual on a 400 KB document
// prints something nobody can read; a pointer list says exactly which operation or schema moved.
function diffPointers(actual, expected) {
    const differences = [];

    const walk = (left, right, pointer) => {
        if (differences.length >= REPORTED_DIFFERENCES || left === right) {
            return;
        }

        const leftIsObject = left && typeof left === 'object';
        const rightIsObject = right && typeof right === 'object';

        if (!leftIsObject || !rightIsObject || Array.isArray(left) !== Array.isArray(right)) {
            differences.push(`${pointer || '/'}: ${describeValue(right)} -> ${describeValue(left)}`);
            return;
        }

        // Sorted union of both key sets, so the report is stable no matter which side has the key
        for (const key of [...new Set([...Object.keys(right), ...Object.keys(left)])].sort()) {
            // JSON pointer escaping: ~ and / are the only characters with meaning
            const encoded = String(key).replace(/~/g, '~0').replace(/\//g, '~1');
            walk(left[key], right[key], `${pointer}/${encoded}`);
        }
    };

    walk(actual, expected, '');

    return differences;
}

test('the generated OpenAPI document matches the recorded golden file', () => {
    if (process.env[UPDATE_ENV] === 'true' || process.env[UPDATE_ENV] === '1') {
        fs.writeFileSync(GOLDEN_PATH, JSON.stringify(spec, null, 2) + '\n');
        return;
    }

    const golden = JSON.parse(fs.readFileSync(GOLDEN_PATH, 'utf-8'));

    // Compared as JSON text rather than with deepEqual, because key order is part of what gets
    // published: the document is served as-is, and a reordered `paths` object is a visible diff for
    // anyone tracking the hosted copy.
    if (JSON.stringify(spec) === JSON.stringify(golden)) {
        return;
    }

    assert.fail(
        [
            `The generated OpenAPI document differs from ${path.relative(process.cwd(), GOLDEN_PATH)}.`,
            '',
            ...diffPointers(spec, golden),
            '',
            `If the change is intentional, re-record the file with ${UPDATE_ENV}=true npm run test:unit and review the diff.`
        ].join('\n')
    );
});
