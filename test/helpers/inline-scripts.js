'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// Finds the <script> elements in a page or template, for the tests that prove every inline one
// carries the Content-Security-Policy nonce and every one of them the data-cfasync opt-out
// (lib/security-headers.js): the template guardrail in the unit tier scans the .hbs sources, the
// smoke test in the integration tier scans rendered pages. One definition, so the two cannot
// drift on what counts as a script tag or on which of them a browser executes.

const SCRIPT_TAG = /<script\b([^>]*)>/gi;

// Script types the browser executes; anything else (a JSON data block, a template holder) is
// inert. An empty type attribute means a classic script, same as no attribute.
const EXECUTABLE_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module']);

// The nonce source in a policy header, capturing the base64url nonce
const NONCE_RE = /'nonce-([A-Za-z0-9_-]+)'/;

/**
 * @param {string} source - HTML or template source
 * @returns {string[]} The attribute strings of every script tag, inline or external
 */
function scriptTagAttrs(source) {
    return [...source.matchAll(SCRIPT_TAG)].map(match => match[1]);
}

/**
 * @param {string} source - HTML or template source
 * @returns {string[]} The attribute strings of the executable inline script tags
 */
function inlineScriptAttrs(source) {
    return scriptTagAttrs(source)
        .filter(attrs => !/\ssrc\s*=/i.test(attrs))
        .filter(attrs => {
            const type = attrs.match(/\btype\s*=\s*["']([^"']*)["']/i);
            return EXECUTABLE_TYPES.has((type ? type[1] : '').trim().toLowerCase());
        });
}

module.exports = { scriptTagAttrs, inlineScriptAttrs, NONCE_RE };
