'use strict';

// Guardrail for the Content-Security-Policy the admin surface sends (lib/security-headers.js).
// Only scripts carrying the request nonce run there, so every inline <script> in a view has
// to be written `<script nonce="{{cspNonce}}">`, and nothing may rely on an inline event
// handler attribute or a javascript: URL - the policy has no 'unsafe-inline' for scripts and
// a nonce does not rescue either. A page that breaks one of these rules renders, but its
// script silently never runs, which no other test would notice.
//
// Pure: reads the templates, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { inlineScriptAttrs } = require('./helpers/inline-scripts');

const VIEWS_DIR = pathlib.join(__dirname, '..', 'views');

const NONCE_ATTR = /\bnonce="\{\{cspNonce\}\}"/;
const INLINE_HANDLER = /<[a-z][^>]*\s+on[a-z]+\s*=/i;
const JAVASCRIPT_URL = /\b(href|action|src)\s*=\s*["']\s*javascript:/i;

test('every view template is compatible with the admin Content-Security-Policy', async t => {
    const templates = listFiles(VIEWS_DIR, '.hbs');
    assert.ok(templates.length > 100, 'the view tree was found');

    let inlineScripts = 0;

    for (let file of templates) {
        const rel = pathlib.relative(VIEWS_DIR, file);
        const source = fs.readFileSync(file, 'utf-8');

        await t.test(rel, () => {
            for (const attrs of inlineScriptAttrs(source)) {
                inlineScripts++;
                assert.match(attrs, NONCE_ATTR, `inline <script${attrs}> must carry nonce="{{cspNonce}}"`);
            }

            const handler = source.match(INLINE_HANDLER);
            assert.equal(handler, null, `inline event handler attribute: ${handler && handler[0]}`);

            const url = source.match(JAVASCRIPT_URL);
            assert.equal(url, null, `javascript: URL: ${url && url[0]}`);
        });
    }

    // The two pre-paint theme scripts alone account for two; a count of zero would mean the
    // scan matched nothing and the guardrail guards nothing
    assert.ok(inlineScripts >= 2, `expected inline scripts to be found, saw ${inlineScripts}`);
});
