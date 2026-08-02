'use strict';

// Builds the render model for the API reference from the OpenAPI document.
//
// Everything derived here depends only on the spec, so the result is built once per
// API worker and shared by every request. Anything that depends on the request (the
// base URL used in the code samples) is applied later, in lib/api-reference/index.js.

const { formatDescription, slugify, methodVariant, constraintList, stringifyExample } = require('./format');
const { buildSchemaTree, buildExample, typeLabel } = require('./schema-tree');

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

function buildParameter(spec, parameter) {
    const schema = parameter.schema || {};

    const view = {
        name: parameter.name,
        in: parameter.in,
        required: !!parameter.required,
        typeLabel: typeLabel(spec, schema),
        descriptionHtml: formatDescription(parameter.description || schema.description),
        constraints: constraintList(schema),
        deprecated: !!parameter.deprecated,
        // Booleans and enums render as a select in the try-it form, not a text field
        isBoolean: schema.type === 'boolean'
    };

    if (Array.isArray(schema.enum) && schema.enum.length) {
        view.enumValues = schema.enum.map(value => (typeof value === 'string' ? value : JSON.stringify(value)));
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
    view.sampleValue = view.tryValue ?? (view.enumValues && view.enumValues[0]) ?? `<${parameter.name}>`;

    return view;
}

function buildBody(spec, requestBody) {
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
        tree: buildSchemaTree(spec, schema),
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
            tree: schema && variant === 'success' ? buildSchemaTree(spec, schema) : null,
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
    const parameters = (operation.parameters || []).map(parameter => buildParameter(spec, parameter));

    const body = buildBody(spec, operation.requestBody);

    const id = operation.operationId || slugify(`${method}-${path}`);

    return {
        id,
        method: method.toLowerCase(),
        methodLabel: method.toUpperCase(),
        methodVariant: methodVariant(method),
        path,
        summary: operation.summary || '',
        descriptionHtml: formatDescription(operation.description),
        deprecated: !!operation.deprecated,
        tag: tagName,
        tagSlug: slugify(tagName),
        pathParams: parameters.filter(parameter => parameter.in === 'path'),
        queryParams: parameters.filter(parameter => parameter.in === 'query'),
        headerParams: parameters.filter(parameter => parameter.in === 'header'),
        body,
        responses: buildResponses(spec, operation.responses, id)
    };
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
    // the hapi-swagger options) drives the navigation, not path iteration order
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
            url: `/admin/reference/${operation.tagSlug}#${operation.id}`
        }))
    };
}

module.exports = {
    buildModel
};
