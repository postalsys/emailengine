'use strict';

// Server-rendered API reference.
//
// The OpenAPI document is generated from the route joi schemas by lib/openapi/ - this
// module only reads it back (over server.inject, so there is no second source of truth)
// and turns it into a render model. The old /admin/swagger page shipped the same document
// to the browser and let swagger-ui build the DOM; here the whole page is HTML by the time
// it leaves the worker.
//
// The model is derived purely from the spec, so it is built once per API worker and
// shared. Only the code samples depend on the request, and those are applied per render.

const settings = require('../settings');
const { buildModel } = require('./model');
const { buildCodeSamples } = require('./code-samples');
const { operationUrl } = require('./format');

const SPEC_URL = '/swagger.json';

const FALLBACK_BASE_URL = 'https://your-emailengine-host';

// The in-flight or resolved model. Caching the promise itself means concurrent first
// requests share one load; a failed load clears the slot so the next request retries.
let modelPromise = null;

async function fetchSpec(server) {
    const res = await server.inject({ method: 'get', url: SPEC_URL });

    if (res.statusCode !== 200) {
        throw new Error(`Failed to load the API specification (HTTP ${res.statusCode})`);
    }

    // hapi returns the handler's own object for an in-process inject, so the JSON parse
    // is only the fallback for a serialized payload
    if (res.result && typeof res.result === 'object') {
        return res.result;
    }

    return JSON.parse(res.payload);
}

function getModel(server) {
    if (!modelPromise) {
        modelPromise = fetchSpec(server)
            .then(buildModel)
            .catch(err => {
                modelPromise = null;
                throw err;
            });
    }

    return modelPromise;
}

// Base address used in the generated samples. The configured public URL wins, because
// that is the address callers actually use; otherwise the request's own origin is used,
// normalized through the URL parser so a malformed Host header cannot smuggle anything
// into the rendered snippet.
//
// serviceUrl is memoized because the shared view context already reads it for every
// admin page render, so an unmemoized read here would be a second Redis round trip for
// the same value. The worker's existing settings broadcast clears it.
let cachedServiceUrl;

function clearServiceUrlCache() {
    cachedServiceUrl = undefined;
}

async function resolveBaseUrl(request) {
    if (typeof cachedServiceUrl === 'undefined') {
        cachedServiceUrl = (await settings.get('serviceUrl')) || null;
    }

    const serviceUrl = cachedServiceUrl;
    if (serviceUrl) {
        try {
            return new URL(serviceUrl).origin;
        } catch (err) {
            // fall through to the request origin
        }
    }

    try {
        return new URL(`${request.server.info.protocol}://${request.info.host}`).origin;
    } catch (err) {
        return FALLBACK_BASE_URL;
    }
}

// Per-request copy of an operation carrying its code samples. The cached model is never
// mutated - samples embed the base URL, which differs between callers.
function withSamples(operation, baseUrl) {
    return Object.assign({}, operation, {
        samples: buildCodeSamples(operation, baseUrl, operation.body && operation.body.exampleValue, operation.body && operation.body.exampleJson)
    });
}

// Navigation model shared by every reference page: all tags, with the active one marked.
// activeSlug is null on the overview page, which the nav marks instead.
//
// Every tag carries its operations, not only the active one. Below the layout's lg breakpoint
// the nav is a disclosure, where tapping a group opens its list in place instead of loading
// its page (views/partials/reference/nav.hbs), so the rows of a group you are not on have to
// already be there. The active tag's entries are in-page anchors - the same links the scroll
// spy tracks - and every other tag's carry the page they live on.
function buildNav(model, activeSlug) {
    return model.tags.map(tag => {
        const active = tag.slug === activeSlug;

        return {
            name: tag.name,
            slug: tag.slug,
            url: tag.url,
            operationCount: tag.operationCount,
            active,
            operations: tag.operations.map(operation => ({
                summary: operation.summary || operation.path,
                // The active tag's entries have to stay bare fragments: initScrollSpy matches
                // them literally, as a[href="#<id>"], to mark the operation being read.
                url: active ? `#${operation.id}` : operationUrl(tag.slug, operation.id)
            }))
        };
    });
}

// Serializes a value for embedding in a <script> element. JSON.stringify escapes quotes but
// NOT `<`, so a string containing `</script` would close the element and everything after it
// would be parsed as HTML. Nothing in this map can contain one today - operation ids are
// [A-Za-z0-9_] and slugs are [a-z0-9-] - but that is a property of the inputs, and this makes
// it a property of the sink instead. U+2028/2029 are escaped too: legal in JSON, but line
// terminators in JavaScript source.
function jsonForScript(value) {
    return JSON.stringify(value)
        .replace(/</g, '\\u003c')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

// Lookup tables for the /admin/swagger compatibility redirect. The old swagger-ui page deep
// linked as `#/Tag/operationId`, and a fragment never reaches the server, so the mapping has
// to be done in the browser.
//
// Operations map to their tag SLUG rather than a full URL: the shim composes the URL, which
// halves the payload since the operation id is already the key.
//
// The lookup is keyed on the operation id alone, deliberately ignoring the tag in the old
// hash - tags get renamed (the Chat endpoints now sit under "Deprecated endpoints (Document
// Store)"), which would strand every link that named the old one. The tag table is only a
// second chance for a link whose operation no longer exists but whose group still does.
let redirectMapJson;

async function getRedirectView(request) {
    const model = await getModel(request.server);

    if (!redirectMapJson) {
        redirectMapJson = jsonForScript({
            operations: Object.fromEntries(model.searchIndex.map(entry => [entry.id, entry.url.split('#')[0].split('/').pop()])),
            tags: Object.fromEntries(model.tags.map(tag => [tag.name.toLowerCase(), tag.slug]))
        });
    }

    return { redirectMap: redirectMapJson };
}

// Just the sidebar, for the reference pages that render no operations of their own
// (the access-token page).
async function getNavView(request) {
    const model = await getModel(request.server);

    return {
        nav: buildNav(model, null),
        // marks the nav's "Access token" entry as current
        tokenActive: true,
        searchIndex: model.searchIndex
    };
}

// Landing page: the tag directory plus the counts shown on it.
async function getIndexView(request) {
    const model = await getModel(request.server);

    return {
        version: model.version,
        descriptionHtml: model.descriptionHtml,
        operationCount: model.operationCount,
        tags: model.tags,
        nav: buildNav(model, null),
        // marks the nav's "Overview" entry as current
        overviewActive: true,
        baseUrl: await resolveBaseUrl(request),
        searchIndex: model.searchIndex
    };
}

// Per-tag page. Returns null when the slug does not match a tag, so the route can 404.
async function getTagView(request, slug) {
    const model = await getModel(request.server);

    const tag = model.tagsBySlug.get(slug);
    if (!tag) {
        return null;
    }

    const baseUrl = await resolveBaseUrl(request);

    return {
        tag,
        operations: tag.operations.map(operation => withSamples(operation, baseUrl)),
        nav: buildNav(model, slug),
        searchIndex: model.searchIndex
    };
}

module.exports = {
    getModel,
    getRedirectView,
    getNavView,
    getIndexView,
    getTagView,
    clearServiceUrlCache
};
