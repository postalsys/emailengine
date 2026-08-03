'use strict';

// Turns an OpenAPI schema into the two things the reference pages render: a nested
// property tree and a synthesized JSON example.
//
// The generated document (lib/openapi/) uses a small corner of OpenAPI: no allOf, no
// oneOf, no discriminator, no additionalProperties and no recursive schemas. This module
// deliberately handles exactly that subset plus the guards needed so a future schema
// that breaks those assumptions degrades into a visible marker instead of hanging the
// worker.

const { formatDescription, constraintList } = require('./format');
const { SCHEMA_REF_PREFIX } = require('../openapi');

// Depth cap for both the property tree and the example. The deepest schema in the
// current document nests 9 levels, so this only trips on something new.
const MAX_DEPTH = 14;

// Nested property groups render inside a <details>. The first levels start open so the
// shape of a payload is visible without clicking; deeper ones start collapsed so a
// large schema (GET /v1/settings carries 104 properties) does not bury the page.
const OPEN_BY_DEFAULT_DEPTH = 2;

// Placeholder values for string formats that have no example of their own, so a
// synthesized example still shows the expected shape rather than a wall of "string".
const FORMAT_PLACEHOLDERS = {
    'date-time': '2026-01-15T09:30:00.000Z',
    date: '2026-01-15',
    email: 'user@example.com',
    uri: 'https://example.com',
    hostname: 'example.com',
    ipv4: '127.0.0.1',
    ipv6: '::1',
    uuid: '00000000-0000-0000-0000-000000000000',
    guid: '00000000-0000-0000-0000-000000000000',
    byte: 'aGVsbG8=',
    binary: '<binary>',
    password: 'secret'
};

// Resolves a local $ref against the document. Every named schema lives in one place, so an
// unresolvable ref means the document is malformed rather than that another bucket needs
// looking in - buildNode() surfaces that as a visible marker.
function lookupRef(spec, ref) {
    if (typeof ref !== 'string' || !ref.startsWith(SCHEMA_REF_PREFIX)) {
        return null;
    }

    const name = ref.slice(SCHEMA_REF_PREFIX.length);

    return (spec.components && spec.components.schemas && spec.components.schemas[name]) || null;
}

// Follows a $ref chain to the underlying schema. `refStack` carries the refs already
// visited on the current branch; revisiting one means the document is recursive, which
// is reported rather than followed.
function resolve(spec, schema, refStack) {
    let current = schema;
    let stack = refStack;

    while (current && typeof current === 'object' && current.$ref) {
        const ref = current.$ref;
        if (stack.includes(ref)) {
            return { schema: null, refStack: stack, circular: true };
        }

        const target = lookupRef(spec, ref);
        if (!target) {
            return { schema: null, refStack: stack, unresolved: ref };
        }

        stack = stack.concat(ref);
        current = target;
    }

    return { schema: current, refStack: stack };
}

// Human-readable type for a schema node. Arrays name their item type so a property row
// reads "array of object" instead of a bare "array".
//
// This lives here rather than in format.js because it has to follow $refs to be correct:
// 46 array properties in the document have `items: {$ref}`, and an anyOf's branches are
// refs too. format.js is deliberately spec-free, so a copy there could only ever answer
// "any" for those - which it did, until buildNode() patched the result afterwards. One
// ref-aware implementation replaces that and the two overrides it needed.
function typeLabel(spec, schema, refStack = []) {
    const resolved = resolve(spec, schema, refStack);
    const target = resolved.schema;

    if (!target || typeof target !== 'object') {
        return 'any';
    }

    if (Array.isArray(target.anyOf) && target.anyOf.length) {
        return target.anyOf.map(entry => typeLabel(spec, entry, resolved.refStack)).join(' or ');
    }

    if (target.type === 'array') {
        return `array of ${target.items ? typeLabel(spec, target.items, resolved.refStack) : 'any'}`;
    }

    if (target.enum && target.enum.length && !target.type) {
        return 'enum';
    }

    return target.type || 'any';
}

// Enum values with their per-value documentation, when the joi schema carries any.
// `.meta({ enumDescriptions })` in lib/schemas.js surfaces as `x-meta.enumDescriptions`
// beside the `enum` array - OpenAPI itself has no field for documenting individual values.
// Returns null when the schema is not an enum, so callers can assign both fields in one go.
function enumInfo(schema) {
    if (!Array.isArray(schema.enum) || !schema.enum.length) {
        return null;
    }

    const documented = (schema['x-meta'] && schema['x-meta'].enumDescriptions) || {};

    // Object.hasOwn, not a bare lookup: an enum value named `constructor` or `toString`
    // would otherwise pick up an inherited function and render as garbage.
    const values = schema.enum.map(value => {
        const key = typeof value === 'string' ? value : JSON.stringify(value);
        return { value: key, description: Object.hasOwn(documented, key) ? documented[key] : null };
    });

    return { values, documented: values.some(entry => entry.description) };
}

// The properties to show underneath a node: an object's own properties, or - for an
// array of objects - the item properties, so an array row expands straight into the
// item shape instead of an intermediate "items" level.
function childSource(spec, schema, refStack) {
    if (!schema || typeof schema !== 'object') {
        return null;
    }

    if (schema.type === 'array' && schema.items) {
        const resolved = resolve(spec, schema.items, refStack);
        if (resolved.schema && resolved.schema.properties) {
            return { schema: resolved.schema, refStack: resolved.refStack };
        }
        return null;
    }

    if (schema.properties) {
        return { schema, refStack };
    }

    return null;
}

function buildNode(spec, rawSchema, options) {
    const { name, required, depth, refStack } = options;

    const resolved = resolve(spec, rawSchema, refStack);

    const node = {
        name: name || null,
        required: !!required,
        openByDefault: depth < OPEN_BY_DEFAULT_DEPTH,
        circular: !!resolved.circular,
        unresolved: resolved.unresolved || null,
        truncated: false,
        children: [],
        variants: []
    };

    const schema = resolved.schema;
    if (!schema || typeof schema !== 'object') {
        node.typeLabel = node.circular ? 'circular reference' : 'any';
        node.descriptionHtml = '';
        node.constraints = [];
        return node;
    }

    node.typeLabel = typeLabel(spec, schema, resolved.refStack);

    node.descriptionHtml = formatDescription(schema.description);
    node.constraints = constraintList(schema);
    node.deprecated = !!schema.deprecated;
    node.nullable = !!schema.nullable;

    const enums = enumInfo(schema);
    if (enums) {
        node.enumValues = enums.values;
        node.enumDocumented = enums.documented;
    }

    if (typeof schema.default !== 'undefined') {
        node.defaultValue = typeof schema.default === 'string' ? schema.default : JSON.stringify(schema.default);
    }

    if (depth >= MAX_DEPTH) {
        node.truncated = true;
        return node;
    }

    if (Array.isArray(schema.anyOf) && schema.anyOf.length) {
        node.variants = schema.anyOf.map((variant, index) =>
            buildNode(spec, variant, {
                name: `option ${index + 1}`,
                required: false,
                depth: depth + 1,
                refStack: resolved.refStack
            })
        );
        return node;
    }

    const source = childSource(spec, schema, resolved.refStack);
    if (source) {
        const requiredNames = Array.isArray(source.schema.required) ? source.schema.required : [];
        node.children = Object.keys(source.schema.properties).map(propertyName =>
            buildNode(spec, source.schema.properties[propertyName], {
                name: propertyName,
                required: requiredNames.includes(propertyName),
                depth: depth + 1,
                refStack: source.refStack
            })
        );

        // Composed here rather than in the template: Handlebars has no inline
        // conditional that can pluralize "property" without a block helper, and the
        // disclosure partial takes its summary as a plain string
        node.childLabel = `${node.children.length} ${node.children.length === 1 ? 'property' : 'properties'}`;
    }

    return node;
}

// Public entry point: property tree for a schema, or null when there is no schema.
function buildSchemaTree(spec, schema) {
    if (!schema) {
        return null;
    }

    return buildNode(spec, schema, { name: null, required: false, depth: 0, refStack: [] });
}

function scalarExample(schema) {
    if (typeof schema.default !== 'undefined') {
        return schema.default;
    }

    if (Array.isArray(schema.enum) && schema.enum.length) {
        return schema.enum[0];
    }

    switch (schema.type) {
        case 'boolean':
            return false;
        case 'integer':
        case 'number':
            if (typeof schema.minimum === 'number') {
                return schema.minimum;
            }
            return 0;
        case 'string': {
            if (schema.format && FORMAT_PLACEHOLDERS[schema.format]) {
                return FORMAT_PLACEHOLDERS[schema.format];
            }
            const xFormat = schema['x-format'];
            if (xFormat && typeof xFormat === 'object') {
                for (const key of Object.keys(xFormat)) {
                    if (FORMAT_PLACEHOLDERS[key]) {
                        return FORMAT_PLACEHOLDERS[key];
                    }
                }
            }
            return 'string';
        }
        default:
            return null;
    }
}

function exampleFor(spec, rawSchema, depth, refStack) {
    const resolved = resolve(spec, rawSchema, refStack);
    const schema = resolved.schema;

    if (!schema || typeof schema !== 'object') {
        return null;
    }

    // An explicit example always wins, including on nested objects - those are the
    // curated payloads the joi schemas carry.
    if (typeof schema.example !== 'undefined') {
        return schema.example;
    }

    if (depth >= MAX_DEPTH) {
        return null;
    }

    if (Array.isArray(schema.anyOf) && schema.anyOf.length) {
        return exampleFor(spec, schema.anyOf[0], depth + 1, resolved.refStack);
    }

    if (schema.type === 'array') {
        if (!schema.items) {
            return [];
        }
        return [exampleFor(spec, schema.items, depth + 1, resolved.refStack)];
    }

    if (schema.properties) {
        const result = {};
        for (const propertyName of Object.keys(schema.properties)) {
            result[propertyName] = exampleFor(spec, schema.properties[propertyName], depth + 1, resolved.refStack);
        }
        return result;
    }

    if (schema.type === 'object') {
        return {};
    }

    return scalarExample(schema);
}

// Public entry point: a JSON value illustrating the schema, or undefined when the
// schema carries nothing to build one from.
function buildExample(spec, schema) {
    if (!schema) {
        return undefined;
    }

    const value = exampleFor(spec, schema, 0, []);
    return value === null && !schema.nullable ? undefined : value;
}

module.exports = {
    buildSchemaTree,
    buildExample,
    typeLabel,
    enumInfo
};
