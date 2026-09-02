'use strict';

// The joi-to-JSON-Schema bridge for MCP tool definitions (lib/mcp/json-schema.js): the OpenAPI
// 3.0 idioms of the shared SchemaConverter have to come out as their 2020-12 equivalents, with
// every named schema inlined - a $ref has nothing to point at inside a tool definition.

const test = require('node:test');
const assert = require('node:assert').strict;

const Joi = require('joi');

const { joiToJsonSchema } = require('../lib/mcp/json-schema');
const { walkJson: walk } = require('./helpers/walk-json');

test('MCP JSON Schema conversion', async t => {
    await t.test('inlines labelled schemas instead of emitting $ref', () => {
        const schema = Joi.object({
            entry: Joi.object({ id: Joi.string().required() }).label('NamedEntry'),
            list: Joi.array().items(Joi.string().valid('a', 'b').label('NamedEnum'))
        }).label('NamedRoot');

        const converted = joiToJsonSchema(schema);

        walk(converted, (node, pointer) => {
            if (node && typeof node === 'object' && !Array.isArray(node)) {
                assert.ok(!('$ref' in node), `unexpected $ref at ${pointer}`);
            }
        });

        assert.equal(converted.properties.entry.type, 'object');
        assert.deepEqual(converted.properties.entry.required, ['id']);
        assert.deepEqual(converted.properties.list.items.enum, ['a', 'b']);
    });

    await t.test('rewrites nullable into a type array and extends enums with null', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                plain: Joi.string().allow(null),
                choice: Joi.string().valid('x', 'y').allow(null)
            })
        );

        assert.deepEqual(converted.properties.plain.type, ['string', 'null']);
        assert.deepEqual(converted.properties.choice.type, ['string', 'null']);
        assert.deepEqual(converted.properties.choice.enum, ['x', 'y', null]);

        walk(converted, (node, pointer) => {
            if (node && typeof node === 'object' && !Array.isArray(node)) {
                assert.ok(!('nullable' in node), `nullable survived at ${pointer}`);
            }
        });
    });

    await t.test('nullable alternatives gain a null branch instead of losing the nullability', () => {
        // The converter parks `nullable: true` next to `anyOf` with no type keyword to widen;
        // dropping it published a tool schema that forbade null where the API accepts it
        const converted = joiToJsonSchema(
            Joi.object({
                either: Joi.alternatives().try(Joi.string(), Joi.number()).allow(null)
            })
        );

        assert.deepEqual(converted.properties.either.anyOf, [{ type: 'string' }, { type: 'number' }, { type: 'null' }]);
        assert.ok(!('nullable' in converted.properties.either));
    });

    await t.test('an allow(false) sentinel beside an object becomes a const branch, not an exclusive enum', () => {
        // The converter emits `.allow(false)` as `enum: [false]` beside `type: object`, which in
        // JSON Schema no object can satisfy - a validating client refused every valid call
        const converted = joiToJsonSchema(
            Joi.object({
                render: Joi.object({ format: Joi.string().valid('html', 'markdown') })
                    .allow(false)
                    .description('Rendering options, or false to skip rendering')
            })
        );

        const render = converted.properties.render;
        assert.equal(render.description, 'Rendering options, or false to skip rendering');
        assert.ok(!('enum' in render));
        assert.ok(!('type' in render));
        assert.deepEqual(render.anyOf, [{ type: 'object', properties: { format: { type: 'string', enum: ['html', 'markdown'] } } }, { const: false }]);
    });

    await t.test('allow(false, null) on a string keeps null in the type array and drops the emptied enum', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                reference: Joi.string().allow(false, null).max(256).example('AAAAAQAACnAcde')
            })
        );

        const reference = converted.properties.reference;
        assert.deepEqual(reference.examples, ['AAAAAQAACnAcde']);
        assert.deepEqual(reference.anyOf, [{ type: ['string', 'null'], maxLength: 256 }, { const: false }]);
    });

    await t.test('a valid() list survives beside a sentinel, null included', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                choice: Joi.string().valid('x', 'y').allow(null, false)
            })
        );

        assert.deepEqual(converted.properties.choice.anyOf, [{ type: ['string', 'null'], enum: ['x', 'y', null] }, { const: false }]);
    });

    await t.test('enum members that are instances of the declared type are left alone', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                count: Joi.number().integer().valid(1, 2),
                flag: Joi.boolean().valid(false)
            })
        );

        assert.deepEqual(converted.properties.count, { type: 'integer', enum: [1, 2] });
        assert.deepEqual(converted.properties.flag, { type: 'boolean', enum: [false] });
    });

    await t.test('moves the singular example into the examples array and drops x- extensions', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                field: Joi.string().hostname().trim().example('mail.example.com').meta({ internal: true })
            })
        );

        assert.deepEqual(converted.properties.field.examples, ['mail.example.com']);

        walk(converted, (node, pointer) => {
            if (node && typeof node === 'object' && !Array.isArray(node)) {
                for (const key of Object.keys(node)) {
                    assert.ok(!/^x-/.test(key), `vendor extension ${key} survived at ${pointer}`);
                    assert.ok(key !== 'example', `singular example survived at ${pointer}`);
                }
            }
        });
    });

    await t.test('keeps standard keywords intact', () => {
        const converted = joiToJsonSchema(
            Joi.object({
                count: Joi.number().integer().min(1).max(10).default(5),
                name: Joi.string().max(256).required(),
                tags: Joi.array().items(Joi.string()).max(4)
            })
        );

        assert.equal(converted.properties.count.type, 'integer');
        assert.equal(converted.properties.count.minimum, 1);
        assert.equal(converted.properties.count.maximum, 10);
        assert.equal(converted.properties.count.default, 5);
        assert.equal(converted.properties.name.maxLength, 256);
        assert.deepEqual(converted.required, ['name']);
        assert.equal(converted.properties.tags.maxItems, 4);
    });
});
