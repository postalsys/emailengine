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
//     spec reserves x-mcp-header for transport behavior, so unknown x- keys are noise at best
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

    if (node.nullable === true) {
        if (typeof result.type === 'string') {
            result.type = [result.type, 'null'];
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
