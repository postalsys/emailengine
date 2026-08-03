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
        rangeChip(schema.minLength, schema.maxLength, 'chars'),
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

    const xConvert = schema['x-convert'];
    if (xConvert && typeof xConvert === 'object') {
        if (xConvert.trim) {
            chips.push('trimmed');
        }
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
    methodVariant,
    constraintList,
    stringifyExample
};
