'use strict';

// Text and value formatting helpers for the server-rendered API reference.
//
// Everything here is pure and spec-free, so it can be unit tested in isolation. Anything
// that has to follow a $ref (type labels) lives in schema-tree.js, which owns resolution.
//
// SECURITY: this module is the single place where reference text becomes HTML. The
// OpenAPI document is generated from our own joi schemas, so the strings are not
// attacker controlled, but three descriptions legitimately contain angle brackets
// (`templateHtmlHead` documents injecting into the `<head>` section) and must render
// as literal text. formatDescription() therefore escapes first and only then adds a
// fixed, closed set of tags back. Never reverse that order and never widen the tag
// set to pass markup through.
//
// Note on `marked`: the repo already renders markdown with it (the EULA page), but it
// is deliberately not used here - the escape-first ordering is the security property,
// and marked would need separate sanitization to give the same guarantee.

const he = require('he');

// Only http(s) targets become links. The input is already HTML-escaped when this runs,
// but escaping does not neutralize a `javascript:` scheme in an href, so the scheme is
// checked explicitly rather than relying on the escape pass.
function isSafeUrl(url) {
    return /^https?:\/\//i.test(url);
}

// Minimal inline formatter for schema and operation descriptions. Handles the small
// subset of markdown our joi `.description()` strings actually use: backtick code
// spans, `[label](url)` links, bare URLs, and paragraph breaks. Input is escaped
// first, so the only tags in the output are the ones added here.
function formatDescription(text) {
    if (!text) {
        return '';
    }

    let html = he.escape(String(text));

    // he.escape() escapes the backtick too (to `&#x60;`, for an old IE attribute quirk),
    // so the code-span pass has to match the escaped form - it runs after escaping by
    // design and there are no literal backticks left to find.
    html = html.replace(/&#x60;([\s\S]+?)&#x60;/g, (match, code) => `<code class="ee-code">${code}</code>`);

    html = html.replace(/\[([^\]]+)\]\(([^\s)]+)\)/g, (match, label, url) => {
        if (!isSafeUrl(url)) {
            return match;
        }
        return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="link link-primary">${label}</a>`;
    });

    // Bare URLs, skipping ones already inside an href="..." emitted above
    html = html.replace(/(^|[\s(])(https?:\/\/[^\s<>"')]+)/g, (match, prefix, url) => {
        return `${prefix}<a href="${url}" target="_blank" rel="noopener noreferrer" class="link link-primary">${url}</a>`;
    });

    return html
        .split(/\n{2,}/)
        .map(paragraph => paragraph.replace(/\n/g, '<br>'))
        .join('</p><p class="mt-2">');
}

// URL segment for a tag name: "Export (Beta)" -> "export-beta"
function slugify(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

// Where a group and an operation live. Four surfaces link to them - the tag directory, the
// nav's group rows, its per-group lists and the filter index - so the shape of a reference
// link is stated here rather than composed at each of them. The route itself is registered in
// lib/ui-routes/reference-routes.js.
function tagUrl(tagSlug) {
    return `/admin/reference/${tagSlug}`;
}

function operationUrl(tagSlug, operationId) {
    return `${tagUrl(tagSlug)}#${operationId}`;
}

const METHOD_VARIANTS = {
    get: 'info',
    post: 'success',
    put: 'warning',
    patch: 'warning',
    delete: 'error'
};

function methodVariant(method) {
    return METHOD_VARIANTS[String(method || '').toLowerCase()] || 'neutral';
}

// "1 to 10 items" / "min 1 item" / "max 10 items", or null when neither bound is set.
function rangeChip(min, max, unit) {
    const suffix = unit ? ` ${unit}` : '';

    if (typeof min === 'number' && typeof max === 'number') {
        return `${min} to ${max}${suffix}`;
    }
    if (typeof min === 'number') {
        return `min ${min}${suffix}`;
    }
    if (typeof max === 'number') {
        return `max ${max}${suffix}`;
    }
    return null;
}

// Length limits at or above this read better as a size than as a character count. `max
// 5242880 chars` is a number nobody holds; `max 5 MB` is the same fact in a form a reader
// can act on. Below it the exact count is the more useful answer - a 1024 character limit
// on a preview line is about the text, not about bytes.
const SIZE_CHIP_MIN = 8192;

// Size label for a character limit, or null when the limit is not a round size. Only exact
// multiples of 1024 convert: rounding 2560 to "2.5 KB" or, worse, "3 KB" would state a
// limit the API does not have, and the exact number is the honest answer there.
function sizeLabel(value) {
    if (typeof value !== 'number' || value < SIZE_CHIP_MIN || value % 1024) {
        return null;
    }

    const mb = value / (1024 * 1024);
    if (Number.isInteger(mb)) {
        return `${mb} MB`;
    }

    return `${value / 1024} KB`;
}

// The string-length chip. A limit large enough to be a size is rendered as one, but only
// when there is no minimum to state alongside it - "1 to 5 MB" would be mixing a character
// count with a byte size in one phrase. No schema in the current document has both.
function lengthChip(min, max) {
    if (typeof min !== 'number') {
        const size = sizeLabel(max);
        if (size) {
            return `max ${size}`;
        }
    }

    return rangeChip(min, max, 'chars');
}

// Short constraint chips shown next to a property. Covers both the standard OpenAPI
// keywords and the `x-*` extensions the generator emits for joi rules OpenAPI has no
// keyword for (accepted URI schemes, email format, value coercion) - real validation
// rules that generic documentation tools drop on the floor.
function constraintList(schema) {
    if (!schema || typeof schema !== 'object') {
        return [];
    }

    const chips = [];

    if (schema.format) {
        chips.push(schema.format);
    }

    for (const chip of [
        rangeChip(schema.minimum, schema.maximum, ''),
        lengthChip(schema.minLength, schema.maxLength),
        rangeChip(schema.minItems, schema.maxItems, 'items')
    ]) {
        if (chip) {
            chips.push(chip);
        }
    }

    if (schema.pattern) {
        chips.push(`pattern ${schema.pattern}`);
    }

    const xFormat = schema['x-format'];
    if (xFormat && typeof xFormat === 'object') {
        for (const key of Object.keys(xFormat)) {
            const value = xFormat[key];
            if (key === 'uri' && value && Array.isArray(value.scheme) && value.scheme.length) {
                chips.push(`URI (${value.scheme.join(', ')})`);
            } else {
                chips.push(key);
            }
        }
    }

    // `trimmed` is deliberately not a chip. joi trims 162 strings in the document, so it was
    // the most common chip on the page and it never changed what anyone sent: leading
    // whitespace on an account id is not a thing callers do on purpose, and being told it
    // would be removed answered a question nobody had. Case coercion stays, because that one
    // does change the value you get back.
    const xConvert = schema['x-convert'];
    if (xConvert && typeof xConvert === 'object') {
        if (xConvert.case === 'lower') {
            chips.push('lowercased');
        }
        if (xConvert.case === 'upper') {
            chips.push('uppercased');
        }
    }

    if (schema['x-constraint'] && schema['x-constraint'].single) {
        chips.push('single value allowed');
    }

    return chips;
}

// How much of an example value a property row shows before it is cut.
//
// The value rides the end of the description rather than taking a line of its own, which
// only works while it is short enough to share one. The prose column is 34rem, about 86
// characters; the median example in the document is 15 characters and the 90th percentile
// is 33, so this cap trips on 67 rows out of 1,056 - base64 blobs, embedded JSON and long
// URLs, where the opening characters already show the shape. The full value stays reachable
// through the title attribute, and through data-example for the try-it autocompleter.
const EXAMPLE_MAX_CHARS = 40;

// One example value, formatted for a property row, or null when the value would say nothing.
//
// Everything is rendered as JSON, including strings, so the row shows what you would paste
// rather than prose that happens to sit where prose already is. A cut string is closed off
// again rather than sliced mid-literal, so the row never shows a dangling quote.
//
// A cut value comes back with two more fields, because the two things that want the whole
// value want it in different forms. `title` is the native tooltip and is the raw value, with
// no quotes around it. `full` is the JSON form, which is what the try-it autocompleter
// inserts - handing it `title` instead produced `"raw": TUlNRS1WZXJ...`, an unquoted string
// in a JSON body. Both are null when nothing was cut, and the row emits neither.
function formatExample(value) {
    if (typeof value === 'string') {
        // A multi-line example (an HTML body, a PEM key) would break the row it rides on
        const flat = value.replace(/\s+/g, ' ').trim();
        if (!flat) {
            return null;
        }

        if (flat.length <= EXAMPLE_MAX_CHARS) {
            return { text: JSON.stringify(flat), title: null, full: null };
        }

        return { text: JSON.stringify(`${flat.slice(0, EXAMPLE_MAX_CHARS)}...`), title: value, full: JSON.stringify(flat) };
    }

    // Everything else is a number or a flat array of scalars - rowExample() has already
    // rejected the values JSON.stringify has trouble with - so this cuts the rendered form
    // rather than the value, which is why it does not close anything back off.
    const text = JSON.stringify(value);

    if (text.length <= EXAMPLE_MAX_CHARS) {
        return { text, title: null, full: null };
    }

    return { text: `${text.slice(0, EXAMPLE_MAX_CHARS)}...`, title: text, full: text };
}

// JSON rendered for the example panels. Kept here so the pretty-printing is identical
// everywhere (page body, code samples, try-it request editor).
function stringifyExample(value) {
    if (typeof value === 'undefined') {
        return '';
    }
    try {
        return JSON.stringify(value, null, 2);
    } catch (err) {
        return '';
    }
}

module.exports = {
    formatDescription,
    slugify,
    tagUrl,
    operationUrl,
    methodVariant,
    constraintList,
    formatExample,
    stringifyExample
};
