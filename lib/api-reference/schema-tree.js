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

// Nested property groups render inside a <details>, and which of them start open is
// decided from the size of the tree rather than from a fixed depth - see
// assignDisclosure(). A depth rule cannot tell a six-property object from
// AccountResponse's 128, and applied the same two open levels to both: right for the
// first, a 6,700 pixel operation for the second.
//
// The budget is how many rows may be on screen before a level is left collapsed. 87 of the
// document's 111 trees fit under it and so arrive fully open; the rest arrive as a
// scannable top level. It can be this tight because reference/operation now renders the
// example payload above the tree and open, so the shape of a wrapper response is already
// on screen and its four top-level keys do not have to carry that job alone.
const OPEN_ROW_BUDGET = 25;

// How many child names a collapsed group lists in its summary before it says "+N more".
const CHILD_PREVIEW_COUNT = 4;

// Rows a schema has to render before it is worth a filter box and expand/collapse controls.
const SCHEMA_TOOLS_MIN_NODES = 12;

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

// Whether a value could be an instance of the schema's own declared type. A schema with no
// declared type is all enum, so everything in it belongs.
function matchesType(type, value) {
    switch (type) {
        case 'string':
            return typeof value === 'string';
        case 'number':
        case 'integer':
            return typeof value === 'number';
        case 'boolean':
            return typeof value === 'boolean';
        case 'array':
            return Array.isArray(value);
        case 'object':
            return value !== null && typeof value === 'object' && !Array.isArray(value);
        default:
            return true;
    }
}

// Enum values with their per-value documentation, when the joi schema carries any.
// `.meta({ enumDescriptions })` in lib/schemas.js surfaces as `x-meta.enumDescriptions`
// beside the `enum` array - OpenAPI itself has no field for documenting individual values.
// Returns null when the schema is not an enum, so callers can assign both fields in one go.
//
// The enum is split by whether a value can be an instance of the schema's own type.
// lib/openapi/joi-schema.js emits `.valid()` and `.allow()` into one `enum`, so a joi
// `.allow(false)` lands there too - 35 schemas in the document carry `enum: [false]` beside
// a `string`, `integer` or `object` type. Those are sentinels standing next to the type, not
// its value domain: `false` clears the block on an update payload and means "not available"
// on a response. Rendered through the normal "Allowed" row they claimed the only value an
// IMAP configuration object accepts is `false`. `alsoAccepts` gets its own line instead.
function enumInfo(schema) {
    if (!Array.isArray(schema.enum) || !schema.enum.length) {
        return null;
    }

    const documented = (schema['x-meta'] && schema['x-meta'].enumDescriptions) || {};

    // Object.hasOwn, not a bare lookup: an enum value named `constructor` or `toString`
    // would otherwise pick up an inherited function and render as garbage.
    const values = schema.enum
        .filter(value => matchesType(schema.type, value))
        .map(value => {
            const key = typeof value === 'string' ? value : JSON.stringify(value);
            return { value: key, description: Object.hasOwn(documented, key) ? documented[key] : null };
        });

    const alsoAccepts = schema.enum.filter(value => !matchesType(schema.type, value)).map(value => JSON.stringify(value));

    return { values, documented: values.some(entry => entry.description), alsoAccepts };
}

// Names listed in a collapsed group's summary. "6 properties" is the only evidence a
// reader has for whether to open a group, and it says nothing about what is inside; the
// Account page alone renders 135 closed groups. Required names come first because
// requiredFirst() has already sorted the children.
function previewNames(children) {
    const shown = children.slice(0, CHILD_PREVIEW_COUNT).map(child => child.name);
    const rest = children.length - shown.length;

    return rest ? `${shown.join(', ')}, +${rest} more` : shown.join(', ');
}

// Required entries first, declared order preserved within each group (Array#sort is
// stable). "What do I have to send" is the first question a schema answers, and a
// payload like SubmitMessage has 33 properties of which 0 to 3 are required - finding
// them meant reading every row.
//
// Exported because operation parameters get the same treatment in model.js: they are
// deliberately built with the same field names as a tree node so they can render through
// the same partial, which makes this the right place for the ordering rule too.
function requiredFirst(nodes) {
    return nodes.sort((a, b) => Number(b.required) - Number(a.required));
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
    const { name, required, depth, refStack, path } = options;

    const resolved = resolve(spec, rawSchema, refStack);

    const node = {
        name: name || null,
        // Anchor id for this property, dotted from the tree root - see buildSchemaTree()
        anchor: path || null,
        required: !!required,
        // Set by assignDisclosure() once the whole tree is built, since the decision needs
        // sibling and subtree sizes that are not known while descending
        openByDefault: false,
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
    if (enums && enums.values.length) {
        node.enumValues = enums.values;
        node.enumDocumented = enums.documented;
    }
    if (enums && enums.alsoAccepts.length) {
        node.alsoAccepts = enums.alsoAccepts;
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
                refStack: resolved.refStack,
                // The index, not the display name: an anchor cannot carry the space in
                // "option 1", and two variants would otherwise share the parent's path
                path: path ? `${path}.option${index + 1}` : null
            })
        );
        return node;
    }

    const source = childSource(spec, schema, resolved.refStack);
    if (source) {
        const requiredNames = Array.isArray(source.schema.required) ? source.schema.required : [];
        node.children = requiredFirst(
            Object.keys(source.schema.properties).map(propertyName =>
                buildNode(spec, source.schema.properties[propertyName], {
                    name: propertyName,
                    required: requiredNames.includes(propertyName),
                    depth: depth + 1,
                    refStack: source.refStack,
                    path: path ? `${path}.${propertyName}` : null
                })
            )
        );

        // Composed here rather than in the template: Handlebars has no inline
        // conditional that can pluralize "property" without a block helper, and the
        // disclosure partial takes its summary as a plain string
        node.childLabel = `${node.children.length} ${node.children.length === 1 ? 'property' : 'properties'}`;
        node.childPreview = previewNames(node.children);
    }

    return node;
}

// Decides which nested groups arrive open, once the whole tree is known.
//
// Level at a time rather than node by node: opening `imap` but not `smtp` because one was
// reached first reads as arbitrary, and a reader cannot tell a collapsed group from a
// group with nothing in it. Whole levels keep the page predictable - everything at a given
// depth is either open or closed.
//
// anyOf variants render inline (reference/schema-node puts them in a bare <ul>, not a
// disclosure), so they are already on screen and descend for free. buildNode() returns
// early on anyOf, so a node carries either children or variants, never both.
function assignDisclosure(root) {
    let level = [...root.children, ...root.variants];
    let visible = level.length;

    while (level.length) {
        const groups = level.filter(node => node.children.length);
        if (!groups.length) {
            return;
        }

        const cost = groups.reduce((total, node) => total + node.children.length, 0);
        if (visible + cost > OPEN_ROW_BUDGET) {
            return;
        }

        for (const node of groups) {
            node.openByDefault = true;
        }

        visible += cost;
        // `groups` is filtered on children.length, and a node never carries both, so there
        // are no variants left to descend into here
        level = groups.flatMap(node => node.children);
    }
}

function countNodes(node) {
    return [...node.children, ...node.variants].reduce((total, child) => total + 1 + countNodes(child), 0);
}

// Public entry point: property tree for a schema, or null when there is no schema.
//
// `path` is the anchor prefix for the tree, e.g. "accountCreate.body". Every node below
// it gets a dotted id built from the property names on the way down, which is what makes
// an individual field linkable ("#accountCreate.body.imap.tls.rejectUnauthorized"). The
// ids are derived from the schema alone, so they stay stable as long as the field does.
// Passing no prefix leaves every anchor null and the rows render without a link.
function buildSchemaTree(spec, schema, path) {
    if (!schema) {
        return null;
    }

    const root = buildNode(spec, schema, { name: null, required: false, depth: 0, refStack: [], path: path || null });
    assignDisclosure(root);

    // Whether this schema is big enough to be worth a filter and expand/collapse controls
    // beside its heading (reference/schema-tools). On a three-property body those are noise,
    // and a tag page would otherwise carry two dozen of them.
    root.showTools = countNodes(root) >= SCHEMA_TOOLS_MIN_NODES;

    return root;
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
    enumInfo,
    requiredFirst
};
