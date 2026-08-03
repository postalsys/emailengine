'use strict';

// Builds the render model for the API reference from the OpenAPI document.
//
// Everything derived here depends only on the spec, so the result is built once per
// API worker and shared by every request. Anything that depends on the request (the
// base URL used in the code samples) is applied later, in lib/api-reference/index.js.

const { formatDescription, slugify, methodVariant, constraintList, stringifyExample } = require('./format');
const { buildSchemaTree, buildExample, typeLabel, enumInfo, requiredFirst } = require('./schema-tree');
const { readCodeSamples } = require('./code-samples');
const { NOTES_SEPARATOR } = require('../openapi');

const METHOD_ORDER = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

const JSON_CONTENT_TYPE = 'application/json';

function statusVariant(code) {
    const numeric = Number(code);
    if (numeric >= 200 && numeric < 300) {
        return 'success';
    }
    if (numeric >= 400 && numeric < 500) {
        return 'warning';
    }
    if (numeric >= 500) {
        return 'error';
    }
    return 'neutral';
}

// Picks the media type to document. Every operation in the current document either
// speaks JSON or streams (text/event-stream, application/octet-stream); JSON is
// preferred so the schema tree and examples have something to render.
function pickContent(content) {
    if (!content || typeof content !== 'object') {
        return null;
    }

    const types = Object.keys(content);
    if (!types.length) {
        return null;
    }

    const contentType = types.includes(JSON_CONTENT_TYPE) ? JSON_CONTENT_TYPE : types[0];
    return { contentType, media: content[contentType] };
}

function buildParameter(spec, parameter, operationId) {
    const schema = parameter.schema || {};

    const view = {
        name: parameter.name,
        anchor: `${operationId}.param.${parameter.name}`,
        in: parameter.in,
        required: !!parameter.required,
        typeLabel: typeLabel(spec, schema),
        descriptionHtml: formatDescription(parameter.description || schema.description),
        constraints: constraintList(schema),
        deprecated: !!parameter.deprecated,
        // Booleans and enums render as a select in the try-it form, not a text field
        isBoolean: schema.type === 'boolean'
    };

    const enums = enumInfo(schema);
    if (enums) {
        view.enumValues = enums.values;
        view.enumDocumented = enums.documented;
    }

    if (typeof schema.default !== 'undefined') {
        view.defaultValue = typeof schema.default === 'string' ? schema.default : JSON.stringify(schema.default);
    }

    if (typeof schema.example !== 'undefined') {
        view.exampleValue = typeof schema.example === 'string' ? schema.example : JSON.stringify(schema.example);
    }

    // Prefilled value for the try-it form, so an operation can be executed after filling
    // in only the values that are genuinely instance specific. Left undefined when the
    // schema offers nothing, which renders as an empty field.
    view.tryValue = view.exampleValue ?? view.defaultValue;

    // Value substituted into the generated code samples. Unlike tryValue this always
    // resolves, so a snippet shows `<account>` rather than an empty path segment.
    view.sampleValue = view.tryValue ?? (view.enumValues && view.enumValues[0].value) ?? `<${parameter.name}>`;

    return view;
}

function buildBody(spec, requestBody, operationId) {
    if (!requestBody) {
        return null;
    }

    const picked = pickContent(requestBody.content);
    if (!picked) {
        return null;
    }

    const schema = picked.media.schema;
    const exampleValue = typeof picked.media.example !== 'undefined' ? picked.media.example : buildExample(spec, schema);

    return {
        contentType: picked.contentType,
        descriptionHtml: formatDescription(requestBody.description),
        tree: buildSchemaTree(spec, schema, `${operationId}.body`),
        exampleValue,
        exampleJson: stringifyExample(exampleValue)
    };
}

// Tab ids are built here rather than in the template because ui/tabs neutralizes its own
// hash params inside the partial block, which puts the operation id out of reach for
// composing them there.
function buildResponses(spec, responses, operationId) {
    if (!responses) {
        return [];
    }

    const entries = Object.keys(responses).map(code => {
        const response = responses[code] || {};
        const variant = statusVariant(code);
        const picked = pickContent(response.content);
        const schema = picked && picked.media.schema;
        const exampleValue = picked && typeof picked.media.example !== 'undefined' ? picked.media.example : buildExample(spec, schema);

        return {
            code,
            variant,
            descriptionHtml: formatDescription(response.description),
            contentType: picked ? picked.contentType : null,
            // Property trees are built for success responses only. The document has 474
            // non-2xx responses sharing 8 distinct shapes - all variations on the
            // {statusCode, error, message} envelope - so expanding them per operation
            // added 2,400 of a tag page's 4,400 tree nodes and a quarter of its bytes to
            // restate the same thing. The error envelope is documented once on the
            // landing page, and each response still carries its own example.
            tree: schema && variant === 'success' ? buildSchemaTree(spec, schema, `${operationId}.resp.${code}`) : null,
            exampleJson: schema ? stringifyExample(exampleValue) : ''
        };
    });

    return entries.map((entry, index) =>
        Object.assign(entry, {
            tabId: `${operationId}-resp-${entry.code}`,
            active: index === 0
        })
    );
}

function buildOperation(spec, path, method, operation, tagName) {
    // Resolved first because it is the anchor prefix every parameter, property and
    // response node below hangs its own id off
    const id = operation.operationId || slugify(`${method}-${path}`);

    const parameters = (operation.parameters || []).map(parameter => buildParameter(spec, parameter, id));

    const body = buildBody(spec, operation.requestBody, id);

    // Behavior notes (lib/api-routes/behavior-notes.js): things the schemas cannot express,
    // like "a 2xx means queued, not sent", or a provider that handles the call differently.
    //
    // Routes declare them twice on purpose. They are appended to the route's `notes` array,
    // which the generator joins into the standard `description` - so every consumer of
    // /swagger.json gets them, not just this page. They are ALSO listed under the
    // x-ee-behavior extension so this renderer can tell them apart from the operation's own
    // prose and pull them into their own callout. A test asserts the two stay in step.
    const behaviorNotes = Array.isArray(operation['x-ee-behavior']) ? operation['x-ee-behavior'] : [];

    // Split back on the separator the generator joined the route's `notes` array with, so the two
    // halves of that contract cannot drift apart
    const paragraphs = (operation.description || '').split(NOTES_SEPARATOR);
    const prose = paragraphs.filter(paragraph => !behaviorNotes.includes(paragraph));

    return {
        id,
        behavior: behaviorNotes.map(note => formatDescription(note)),
        // Hand-written snippets the route declared; buildCodeSamples() puts them ahead of
        // the generated ones
        codeSamples: readCodeSamples(operation),
        method: method.toLowerCase(),
        methodLabel: method.toUpperCase(),
        methodVariant: methodVariant(method),
        path,
        summary: operation.summary || '',
        descriptionHtml: formatDescription(prose.join('\n\n')),
        deprecated: !!operation.deprecated,
        tag: tagName,
        tagSlug: slugify(tagName),
        // Path parameters keep their order in the path, which is the only order that makes
        // sense for them. The other two are grouped required-first: GET /v1/settings carries
        // 106 query parameters, and the handful that are mandatory should not be buried.
        pathParams: parameters.filter(parameter => parameter.in === 'path'),
        queryParams: requiredFirst(parameters.filter(parameter => parameter.in === 'query')),
        headerParams: requiredFirst(parameters.filter(parameter => parameter.in === 'header')),
        body,
        responses: buildResponses(spec, operation.responses, id)
    };
}

// Collects the property names in a schema tree, at every depth.
function collectNames(node, into) {
    if (!node) {
        return;
    }

    if (node.name) {
        into.add(node.name);
    }

    for (const child of node.children) {
        collectNames(child, into);
    }
    for (const variant of node.variants) {
        collectNames(variant, into);
    }
}

// The whole corpus the sidebar filter matches an operation against. Built here rather than
// interpolated in reference/nav.hbs so that what is searchable is decided in one place -
// the template just emits it.
//
// It is more than the hit row displays. The two questions the filter could not answer
// before are "which endpoint takes a `mailbox`" and "which one accepts `mailMerge`", so it
// also carries the operation id and every name a caller can SEND: query and header
// parameters, and request body properties at any depth. Path parameters are already covered
// by the path itself, which spells them out as `{account}`.
//
// Response property names are deliberately left out. The filter ANDs plain substrings, so
// every added term is also a chance to match something unrelated - and response shapes
// repeat the same envelope fields (`account`, `id`, `messages`) across most operations,
// which would blunt exactly the queries this is for. Descriptions are left out for the same
// reason, and because they are the bulk of the bytes.
function searchCorpus(operation) {
    const terms = new Set([operation.methodLabel, operation.path, operation.summary, operation.tag, operation.id]);

    for (const parameter of [...operation.queryParams, ...operation.headerParams]) {
        terms.add(parameter.name);
    }

    if (operation.body) {
        collectNames(operation.body.tree, terms);
    }

    terms.delete('');
    return [...terms].join(' ');
}

// Sorts operations inside a tag the way the old swagger-ui page did (`sortEndpoints:
// 'method'`), so the ordering people are used to carries over.
function sortOperations(operations) {
    return operations.sort((a, b) => {
        const methodDiff = METHOD_ORDER.indexOf(a.method) - METHOD_ORDER.indexOf(b.method);
        if (methodDiff) {
            return methodDiff;
        }
        return a.path.localeCompare(b.path);
    });
}

function buildModel(spec) {
    const tagsByName = new Map();

    // Seed from the spec's tag list first so the declared order (the `tags` array in
    // lib/swagger-options.js) drives the navigation, not path iteration order
    for (const tag of spec.tags || []) {
        tagsByName.set(tag.name, {
            name: tag.name,
            slug: slugify(tag.name),
            descriptionHtml: formatDescription(tag.description),
            externalDocs: tag.externalDocs && tag.externalDocs.url ? tag.externalDocs : null,
            operations: []
        });
    }

    const allOperations = [];

    for (const path of Object.keys(spec.paths || {})) {
        const pathItem = spec.paths[path] || {};
        for (const method of Object.keys(pathItem)) {
            if (!METHOD_ORDER.includes(method.toLowerCase())) {
                continue;
            }

            const operation = pathItem[method];
            const tagName = (operation.tags && operation.tags[0]) || 'Other';

            if (!tagsByName.has(tagName)) {
                tagsByName.set(tagName, {
                    name: tagName,
                    slug: slugify(tagName),
                    descriptionHtml: '',
                    externalDocs: null,
                    operations: []
                });
            }

            const view = buildOperation(spec, path, method, operation, tagName);
            tagsByName.get(tagName).operations.push(view);
            allOperations.push(view);
        }
    }

    const tags = [...tagsByName.values()].filter(tag => tag.operations.length);
    for (const tag of tags) {
        sortOperations(tag.operations);
        tag.operationCount = tag.operations.length;
    }

    return {
        version: (spec.info && spec.info.version) || '',
        // The document's own introduction, rendered on the landing page rather than
        // restated there. It is written as plain paragraphs for exactly this reason -
        // see the `info` block in workers/api.js.
        descriptionHtml: formatDescription(spec.info && spec.info.description),
        tags,
        tagsBySlug: new Map(tags.map(tag => [tag.slug, tag])),
        operationCount: allOperations.length,
        // Flat list backing the client-side filter on every page
        searchIndex: allOperations.map(operation => ({
            id: operation.id,
            method: operation.methodLabel,
            methodVariant: operation.methodVariant,
            path: operation.path,
            summary: operation.summary,
            tag: operation.tag,
            search: searchCorpus(operation),
            url: `/admin/reference/${operation.tagSlug}#${operation.id}`
        }))
    };
}

module.exports = {
    buildModel
};
