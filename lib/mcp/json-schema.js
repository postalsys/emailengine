'use strict';

// Converts joi schemas into the JSON Schema (2020-12 dialect) shape MCP tool definitions carry.
//
// Reuses the OpenAPI SchemaConverter from lib/openapi/joi-schema.js rather than walking joi's
// describe() output a second time: that converter is the one place the repo reads joi schemas,
// and a second reader would drift from it. The converter is asked to inline everything
// (useDefinitions: false, so no #/components/schemas refs can appear), and the OpenAPI 3.0
// idioms in its output are then rewritten into their JSON Schema equivalents:
//
//   - `nullable: true` becomes `type: [..., "null"]` (and null joins an enum when one exists)
//   - the singular `example` becomes the standard `examples` array
//   - the `x-*` vendor extensions (x-meta, x-constraint, x-format, x-convert) are dropped -
//     they carry joi rules for the API reference renderer, which no MCP client reads, and the
//     spec reserves x-mcp-header for transport behavior, so unknown x- keys are noise at best.
//     One of them is not renderer detail though: `x-meta.enumDescriptions` says what each value
//     of an enum MEANS, which is the difference between a model picking a value and guessing
//     one. It is folded into the description before the key goes, so the meanings survive in the
//     one field every client shows.
//
// Everything else the converter emits (properties, required, enum, anyOf, minimum/maxLength and
// friends) is already valid 2020-12.

const { SchemaConverter } = require('../openapi/joi-schema');

function toJsonSchema(node) {
    if (Array.isArray(node)) {
        return node.map(entry => toJsonSchema(entry));
    }

    if (!node || typeof node !== 'object') {
        return node;
    }

    const result = {};

    // Collected before the loop drops the key it lives on, and appended after the description is
    // known - the two can arrive in either order.
    const enumDescriptions = node['x-meta'] && node['x-meta'].enumDescriptions;

    for (const [key, value] of Object.entries(node)) {
        if (/^x-/.test(key)) {
            continue;
        }

        switch (key) {
            case 'nullable':
                // handled below, once `type` and `enum` are known
                continue;

            case 'example':
                result.examples = [value];
                continue;

            case 'properties': {
                const mapped = {};
                for (const [property, schema] of Object.entries(value)) {
                    mapped[property] = toJsonSchema(schema);
                }
                result[key] = mapped;
                continue;
            }

            // The only nesting keywords the converter emits: alternatives and .when() collapse
            // into anyOf, array items stay items. Nothing produces allOf/oneOf/not.
            case 'items':
            case 'anyOf':
                result[key] = toJsonSchema(value);
                continue;

            default:
                result[key] = value;
        }
    }

    if (enumDescriptions && typeof enumDescriptions === 'object') {
        // Only the values this schema actually offers, in the order it offers them, so a shared
        // table describing more values than one field accepts cannot widen it in the prose
        const described = (Array.isArray(result.enum) ? result.enum : Object.keys(enumDescriptions))
            .filter(value => enumDescriptions[value])
            .map(value => `"${value}" - ${enumDescriptions[value]}`);

        if (described.length) {
            result.description = `${result.description ? `${result.description}. ` : ''}${described.join('; ')}`;
        }
    }

    if (node.nullable === true) {
        if (typeof result.type === 'string') {
            result.type = [result.type, 'null'];
        } else if (Array.isArray(result.anyOf)) {
            // alternatives().allow(null): the converter parks nullable next to anyOf, where
            // there is no type keyword to widen - null becomes one more accepted branch
            result.anyOf = result.anyOf.concat({ type: 'null' });
        }
        if (Array.isArray(result.enum) && !result.enum.includes(null)) {
            result.enum = result.enum.concat(null);
        }
    }

    return result;
}

/**
 * Converts a compiled joi schema into a JSON Schema object for an MCP tool definition.
 *
 * @param {Object} schema - a joi schema
 * @returns {Object|undefined} JSON Schema, or undefined when the schema documents nothing
 */
function joiToJsonSchema(schema) {
    if (!schema || typeof schema.describe !== 'function') {
        return undefined;
    }

    const converted = new SchemaConverter().convert(schema, { useDefinitions: false });

    return converted ? toJsonSchema(converted) : undefined;
}

module.exports = { joiToJsonSchema };
