'use strict';

// The schema names in /swagger.json are public type names: code generators turn each one into a
// class. A joi schema without a label is named after the property it sits under (`status`, `ca`),
// and two different schemas sharing a label get a numeric suffix (`AddressList2`), which renumbers
// whenever the route order changes. Both read as noise in a generated client, so every component
// name has to be a deliberate, distinct label: starting with a capital, and no collision suffix.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { buildOpenApiSpec } = require('./helpers/build-openapi-spec');

registerRedisTeardown(redis);

// Names that end in a digit on purpose rather than through a collision
const DIGIT_SUFFIXED_NAMES = new Set(['OAuth2']);

test('OpenAPI component names', async t => {
    const spec = await buildOpenApiSpec();
    const names = Object.keys(spec.components.schemas);

    await t.test('every component is named by a label, not by the property it sits under', () => {
        assert.deepEqual(
            names.filter(name => !/^[A-Z]/.test(name)),
            [],
            'label these schemas'
        );
    });

    await t.test('no two different schemas share a label', () => {
        // A suffix is only added when the name is already taken by a different definition
        const suffixed = names.filter(name => /\d$/.test(name) && !DIGIT_SUFFIXED_NAMES.has(name) && names.includes(name.replace(/\d+$/, '')));
        assert.deepEqual(suffixed, [], 'give these schemas distinct labels');
    });
});
