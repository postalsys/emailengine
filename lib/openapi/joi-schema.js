'use strict';

// Converts joi schemas into OpenAPI 3.0 Schema Objects.
//
// This replaces the conversion half of hapi-swagger, which was archived upstream and pinned us to
// joi 17 because it read joi's private internals (`_flags`, `_rules`, `_ids`, `$_terms`). Everything
// here goes through the public `describe()` output instead, so a joi upgrade can only change what we
// read, never break how we read it.
//
// The output deliberately matches what hapi-swagger produced, quirks included - the generated
// document is a public surface (served at /swagger.json, mirrored on emailengine.dev, fed to Postman
// and code generators), so the migration had to be a no-op for consumers. Where a quirk is preserved
// on purpose it is called out in a comment. test/fixtures/openapi-golden.json is the proof: it was
// recorded from hapi-swagger's output before this module existed, and the switch moved exactly two
// things in it, both because hapi-swagger read joi's private internals and this does not:
//   - structurally identical schemas sharing a label are now one definition instead of two;
//   - one route's query parameters follow joi's validation order rather than declaration order,
//     because a key with a `.when()` moves to the end of what describe() reports.
//
// Two conventions from that document are load-bearing rather than cosmetic:
//   - `.label()` decides a schema's name under components/schemas, and labelled schemas are emitted
//     as a $ref instead of being inlined. Renaming a label renames a public type.
//   - The `x-constraint`, `x-format` and `x-convert` extensions carry joi rules that OpenAPI has no
//     keyword for. lib/api-reference/format.js renders them as constraint chips.

const { isDeepStrictEqual } = require('node:util');

const Joi = require('joi');

const SCHEMA_REF_PREFIX = '#/components/schemas/';

// joi type to the OpenAPI type it starts out as. `alternatives` is not an OpenAPI type; it is a
// marker that gets replaced by `anyOf` once the branches are known.
//
// A joi date accepts an ISO string, a timestamp or a Date, so `date-time` describes it and the plain
// OpenAPI `date` (a bare YYYY-MM-DD) does not. Every date EmailEngine returns is a full timestamp.
const TYPE_MAP = {
    boolean: { type: 'boolean' },
    binary: { type: 'string', format: 'binary' },
    date: { type: 'string', format: 'date-time' },
    number: { type: 'number' },
    string: { type: 'string' },
    any: { type: 'string' },
    array: { type: 'array' },
    function: { type: 'string' },
    object: { type: 'object' },
    alternatives: { type: 'alternatives' }
};

// joi rules that have no OpenAPI keyword, grouped into the extension that carries them. Order
// matters: it is the key order inside the emitted extension object.
const STRING_CONSTRAINT_RULES = ['insensitive', 'length'];
const STRING_FORMAT_RULES = ['creditCard', 'alphanum', 'token', 'email', 'ip', 'uri', 'guid', 'hex', 'hostname', 'isoDate'];
const STRING_CONVERT_RULES = ['case', 'trim'];
const NUMBER_CONSTRAINT_RULES = ['greater', 'less', 'precision', 'multiple', 'sign'];
const ARRAY_CONSTRAINT_RULES = ['length', 'unique'];

function flag(description, name) {
    return description.flags ? description.flags[name] : undefined;
}

// Value of a `.meta({ key: value })` entry, searching from the last meta backwards, so a schema that
// overrides an inherited meta wins.
function metaValue(description, name) {
    const metas = description.metas;
    if (!Array.isArray(metas)) {
        return undefined;
    }

    let index = metas.length;
    while (index--) {
        if (metas[index][name]) {
            return metas[index][name];
        }
    }

    return undefined;
}

function hasKeys(description) {
    return !!(description.keys && Object.keys(description.keys).length);
}

function hasRule(rules, name) {
    return Array.isArray(rules) && rules.some(rule => rule.name === name);
}

// Argument of a rule, searching backwards so the last occurrence wins. `key` picks a named argument
// (`.max(10)` describes as `{ limit: 10 }`); without it the first argument value is returned. Rules
// with no arguments at all report `true`, which is what the extension objects carry for flags like
// `trim`.
function ruleArg(rules, name, key) {
    if (!Array.isArray(rules)) {
        return undefined;
    }

    let index = rules.length;
    while (index--) {
        if (rules[index].name === name) {
            if (rules[index].args) {
                return key ? rules[index].args[key] : Object.values(rules[index].args)[0];
            }
            return true;
        }
    }

    return undefined;
}

function isPlainObject(value) {
    return value !== null && value !== undefined && typeof value === 'object' && !Array.isArray(value);
}

function isEmpty(value) {
    return value === null || (Array.isArray(value) && !value.length) || (isPlainObject(value) && !Object.keys(value).length);
}

// Drops keys that carry no information, so the document is not littered with `description: null` and
// `properties: {}`. `default` and `example` are exempt because an empty object or an explicit null is
// a meaningful value for them.
function deleteEmptyProperties(obj) {
    for (const key of Object.keys(obj)) {
        const value = obj[key];

        if (value === undefined || (!['default', 'example'].includes(key) && isEmpty(value))) {
            delete obj[key];
        }
    }

    return obj;
}

// joi's describe() renders a pattern as `/source/flags` because it stringifies the RegExp. OpenAPI
// wants the bare source, so the delimiters are peeled back off. The greedy match takes the LAST
// slash as the closing delimiter, which is correct because a joi pattern is always a real RegExp and
// flags are always trailing lowercase letters.
function regexSource(value) {
    const match = /^\/(.*)\/[a-z]*$/s.exec(String(value));

    return match ? match[1] : String(value);
}

class SchemaConverter {
    constructor() {
        // Named schemas, keyed by the name a $ref points at
        this.definitions = {};

        // Highest numeric suffix handed out per base name, so allocating the next one does not scan
        // the whole collection
        this.suffixes = new Map();

        // describe() validates its own output as it walks, which is most of the cost of a build, and
        // the shared schemas in lib/schemas.js (every error response, every account id) are reached
        // from most of the 82 operations. Keyed by joi schema, which is immutable, and held on the
        // converter so it is released with it.
        this.descriptions = new WeakMap();
    }

    describe(schema) {
        if (!this.descriptions.has(schema)) {
            this.descriptions.set(schema, schema.describe());
        }

        return this.descriptions.get(schema);
    }

    /**
     * Converts a joi schema into an OpenAPI Schema Object.
     *
     * @param {Object} schema - a joi schema, or the describe() result of one
     * @param {Object} [context]
     * @param {String} [context.parameterType=body] - where the schema is used ('body', 'path', 'query', 'header')
     * @param {Boolean} [context.useDefinitions=true] - register named schemas and emit a $ref to them
     * @returns {Object|undefined} the schema object, or undefined when the schema is not documented
     */
    convert(schema, context) {
        const description = Joi.isSchema(schema) ? this.describe(schema) : schema;

        return this.parseProperty(null, description, null, Object.assign({ parameterType: 'body', useDefinitions: true }, context));
    }

    parseProperty(name, description, parent, context) {
        if (!description) {
            return undefined;
        }

        // A forbidden key exists only to be rejected, and swaggerHidden is how a schema opts out of
        // the public document (deprecated Document Store fields use it). Both must not appear.
        if (flag(description, 'presence') === 'forbidden' || metaValue(description, 'swaggerHidden') === true) {
            return undefined;
        }

        // Path parameters are named by the path template, so a label must not rename them
        if (!name && context.parameterType !== 'path') {
            name = flag(description, 'label') || name;
        }

        const mapped = TYPE_MAP[description.type] || TYPE_MAP.any;

        let property = { type: mapped.type };
        if (mapped.format) {
            property.format = mapped.format;
        }

        // Presence lives on the child but is expressed on the parent's `required` array, so it has to
        // be recorded before the child's own parsing starts
        this.setRequiredOnParent(name, parent, description);

        property = this.parseMetadata(property, description);
        property = this.parseEnum(property, description);

        if (property.type === 'string') {
            property = this.parseString(property, description);
        }

        if (property.type === 'number') {
            property = this.parseNumber(property, description);
        }

        if (description.type === 'date') {
            property = this.parseDate(property, description);
        }

        if (property.type === 'object') {
            // An object with neither keys nor a description says nothing about its own shape, so it is
            // published as a bare `{ type: 'object' }` - the example or default it may carry would
            // describe a structure the document does not otherwise mention
            property =
                hasKeys(description) || flag(description, 'description')
                    ? this.parseObject(property, description, context)
                    : { type: 'object', properties: {} };
        }

        if (property.type === 'array') {
            property = this.parseArray(property, description, context);
        }

        if (property.type === 'alternatives') {
            property = this.parseAlternatives(property, description, name, context);
        }

        // A named schema is registered once and referenced everywhere it is used. Scalars are inlined,
        // except for a set of allowed strings: that is worth a schema of its own so every operation
        // accepting it points at the same list. A numeric `enum` is not the same thing - it comes from
        // `.allow(false)` on a number, which is a sentinel value rather than a named vocabulary.
        if (context.useDefinitions && (['object', 'array'].includes(property.type) || (property.type === 'string' && property.enum))) {
            return { $ref: SCHEMA_REF_PREFIX + this.append(name, deleteEmptyProperties(property)) };
        }

        return deleteEmptyProperties(property);
    }

    // Records the child's name in the parent's `required` array. A `.when()` branch that makes the
    // key required counts as required, because OpenAPI cannot express the condition itself - the
    // alternative would be documenting a required field as optional.
    setRequiredOnParent(name, parent, description) {
        if (!parent || !name) {
            return;
        }

        const require = () => {
            if (!parent.required) {
                parent.required = [];
            }
            if (!parent.required.includes(name)) {
                parent.required.push(name);
            }
        };

        if (flag(description, 'presence') === 'required') {
            require();
        }

        for (const when of description.whens || []) {
            if (when.then && when.then.flags && when.then.flags.presence === 'required') {
                require();
            }
        }
    }

    parseMetadata(property, description) {
        property.description = flag(description, 'description');

        property.example = Array.isArray(description.examples) ? description.examples[0] : undefined;

        // Everything a schema was tagged with is published as-is, minus the keys that steer
        // generation rather than describe the value. This is how `.meta({ enumDescriptions })`
        // reaches the API reference.
        const published = Object.assign({}, ...(description.metas || []));
        delete published.swaggerHidden;

        if (Object.keys(published).length) {
            property['x-meta'] = published;
        }

        let defaultValue = flag(description, 'default');
        if (typeof defaultValue === 'function') {
            defaultValue = defaultValue();
        }

        // An empty array default says nothing beyond what `type: array` already says
        if (!(property.type === 'array' && Array.isArray(defaultValue) && !defaultValue.length)) {
            property.default = defaultValue;
        }

        return property;
    }

    // Allowed values become an enum. This covers `.valid()` and `.allow()` alike, matching how the
    // document has always been generated: `.allow('')` adds no enum (the empty string is dropped),
    // while `.allow(null)` marks the schema nullable.
    parseEnum(property, description) {
        if (!Array.isArray(description.allow) || !description.allow.length) {
            return property;
        }

        let allowed = description.allow;

        // `.valid()` prefixes the list with an override marker that is not a value
        if (isPlainObject(allowed[0]) && allowed[0].override === true && Object.keys(allowed[0]).length === 1) {
            allowed = allowed.slice(1);
        }

        const values = allowed.filter(value => value !== '' && value !== null);
        if (values.length) {
            property.enum = values;
        }

        if (allowed.includes(null)) {
            property.nullable = true;
        }

        return property;
    }

    parseString(property, description) {
        // Dates share the string branch but carry min/max as date bounds, not string lengths
        if (description.type !== 'date') {
            property.minLength = ruleArg(description.rules, 'min', 'limit');
            property.maxLength = ruleArg(description.rules, 'max', 'limit');
        }

        const pattern = ruleArg(description.rules, 'pattern', 'regex');
        if (pattern) {
            property.pattern = regexSource(pattern);
        }

        this.convertRules(property, description.rules, STRING_CONSTRAINT_RULES, 'x-constraint');
        this.convertRules(property, description.rules, STRING_FORMAT_RULES, 'x-format');
        this.convertRules(property, description.rules, STRING_CONVERT_RULES, 'x-convert');

        return property;
    }

    parseNumber(property, description) {
        property.minimum = ruleArg(description.rules, 'min');
        property.maximum = ruleArg(description.rules, 'max');

        if (hasRule(description.rules, 'integer')) {
            property.type = 'integer';
        }

        const format = metaValue(description, 'format');
        if (typeof format === 'string') {
            property.format = format;
        }

        this.convertRules(property, description.rules, NUMBER_CONSTRAINT_RULES, 'x-constraint');

        return property;
    }

    // A date expressed as a number of milliseconds or seconds is not a string at all
    parseDate(property, description) {
        if (['timestamp', 'javascript', 'unix'].includes(flag(description, 'format'))) {
            property.type = 'integer';
            delete property.format;
        }

        return property;
    }

    parseObject(property, description, context) {
        property.properties = {};

        for (const key of Object.keys(description.keys || {})) {
            const child = description.keys[key];

            // A labelled child is registered under its label but still keyed by its property name
            const childName = flag(child, 'label') || key;

            const parsed = this.parseProperty(childName, child, property, context);
            if (parsed) {
                property.properties[key] = parsed;
            }

            // The label was used for the definition name; the parent's required list has to name the
            // property, not the type
            if (childName !== key && property.required) {
                const index = property.required.indexOf(childName);
                if (index !== -1) {
                    property.required[index] = key;
                }
            }
        }

        return property;
    }

    parseArray(property, description, context) {
        property.minItems = ruleArg(description.rules, 'min');
        property.maxItems = ruleArg(description.rules, 'max');

        this.convertRules(property, description.rules, ARRAY_CONSTRAINT_RULES, 'x-constraint');

        // `.single()` accepts a bare value where a list is expected. OpenAPI has no way to say that,
        // and it is a real difference for a caller writing a request by hand.
        if (flag(description, 'sparse')) {
            this.addExtension(property, 'x-constraint', 'sparse', true);
        }
        if (flag(description, 'single')) {
            this.addExtension(property, 'x-constraint', 'single', true);
        }

        // Item schemas take no parent: an item's own presence flag has nowhere to go, since `required`
        // names an object's keys and an array has none
        const items = (description.items || []).map(item => this.parseProperty(flag(item, 'label'), item, null, context));

        if (items.length > 1) {
            property.items = { anyOf: items };
        } else {
            property.items = items[0] || { type: 'string' };
        }

        return property;
    }

    // `Joi.alternatives().try(a, b)` and a conditional `.when()` both collapse into `anyOf`. The
    // condition itself is dropped: OpenAPI has no way to say "this shape when that field is set".
    parseAlternatives(property, description, name, context) {
        const matches = description.matches || [];

        const branches =
            matches[0] && matches[0].schema ? matches.map(match => match.schema) : matches.flatMap(match => [match.then, match.otherwise].filter(Boolean));

        // No parent, for the same reason as array items: a branch has no key to be required under
        property.anyOf = branches.map(branch => this.parseProperty(flag(branch, 'label') || name, branch, null, context)).filter(Boolean);

        delete property.type;

        return property;
    }

    convertRules(property, rules, ruleNames, groupName) {
        for (const ruleName of ruleNames) {
            if (!hasRule(rules, ruleName)) {
                continue;
            }

            let value = ruleArg(rules, ruleName);
            if (isPlainObject(value) && !Object.keys(value).length) {
                value = undefined;
            }

            this.addExtension(property, groupName, ruleName, value);
        }
    }

    addExtension(property, groupName, ruleName, value) {
        if (!property[groupName]) {
            property[groupName] = {};
        }

        property[groupName][ruleName] = value !== undefined ? value : true;
    }

    /**
     * Registers a schema under a name and returns the name to reference it by.
     *
     * Names come from joi labels, and two structurally different schemas can carry the same label -
     * `AddressList` is used for four different address lists, `status` for three unrelated status
     * enums. Those get a numeric suffix (`AddressList1`) so neither definition is lost. It is a wart:
     * the fix is distinct labels in the schemas themselves, not a cleverer generator.
     *
     * Schemas that are structurally identical always share one definition, whatever joi object they
     * were built from. Without that, the same label reached from two routes produces two identical
     * copies, and the copies then differ only by which numbered sibling they reference.
     */
    append(name, definition) {
        const collection = this.definitions;

        if (!name) {
            name = this.nextName('Model');
        }

        // The name itself, then the numbered siblings it has already spawned
        for (let suffix = 0; suffix <= (this.suffixes.get(name) || 0); suffix++) {
            const candidate = suffix ? name + suffix : name;

            if (isDeepStrictEqual(collection[candidate], definition)) {
                return encodeURIComponent(candidate);
            }
        }

        const key = collection[name] ? this.nextName(name) : name;
        collection[key] = definition;

        return encodeURIComponent(key);
    }

    nextName(base) {
        const suffix = (this.suffixes.get(base) || 0) + 1;
        this.suffixes.set(base, suffix);

        return base + suffix;
    }
}

module.exports = { SchemaConverter, deleteEmptyProperties, SCHEMA_REF_PREFIX };
