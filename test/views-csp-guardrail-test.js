'use strict';

// Guardrail for the Content-Security-Policy the admin surface sends (lib/security-headers.js).
// Only scripts carrying the request nonce run there, so every inline <script> in a view has
// to be written `<script nonce="{{cspNonce}}">`, and nothing may rely on an inline event
// handler attribute or a javascript: URL - the policy has no 'unsafe-inline' for scripts and
// a nonce does not rescue either. Stylesheet elements answer to the same nonce, so a view may
// not carry a <style> block either. A page that breaks one of these rules renders, but its
// script silently never runs, which no other test would notice.
//
// Every script tag also carries data-cfasync="false" - see `.claude/rules/admin-ui.md` for the
// rule and the reasoning. Found on an instance behind a Cloudflare zone with Rocket Loader on,
// where the admin UI came up looking entirely normal with nothing on it working.
//
// Pure: reads the templates, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { scriptTagAttrs, inlineScriptAttrs } = require('./helpers/inline-scripts');
const { stripHandlebarsComments } = require('./helpers/hbs-comments');

const VIEWS_DIR = pathlib.join(__dirname, '..', 'views');

const NONCE_ATTR = /\bnonce="\{\{cspNonce\}\}"/;
const CFASYNC_ATTR = /\bdata-cfasync="false"/;
const JAVASCRIPT_URL = /\b(href|action|src|formaction|xlink:href)\s*=\s*["']?\s*javascript:/i;
const STYLE_ELEMENT = /<style\b/i;

// Every triple-stash in the views, by file and expression. Each one writes its value into the
// page unescaped, so a new one is a decision to review, not a pattern to copy: the layouts'
// {{{content}}}, operator branding injected on the public layout, the EULA, and HTML the API
// reference builds from the OpenAPI document through its own escaping formatter.
const TRIPLE_STASH_ALLOWLIST = new Set([
    'layout/app.hbs {{{content}}}',
    'layout/login.hbs {{{content}}}',
    'layout/main.hbs {{{content}}}',
    'layout/prompt.hbs {{{content}}}',
    'layout/public.hbs {{{content}}}',
    'layout/public.hbs {{{embeddedTemplateHeader}}}',
    'layout/public.hbs {{{embeddedTemplateHtmlHead}}}',
    'license.hbs {{{eulaText}}}',
    'partials/reference/operation.hbs {{{body.descriptionHtml}}}',
    'partials/reference/operation.hbs {{{descriptionHtml}}}',
    'partials/reference/operation.hbs {{{this}}}',
    'partials/reference/schema-node.hbs {{{descriptionHtml}}}',
    'partials/reference/schema-node.hbs {{{usageHtml}}}',
    'partials/reference/schema.hbs {{{descriptionHtml}}}',
    'reference/index.hbs {{{descriptionHtml}}}',
    'reference/redirect.hbs {{{redirectMap}}}',
    'reference/tag.hbs {{{tag.descriptionHtml}}}'
]);

/**
 * Finds inline event handler attributes. Handlebars expressions are blanked first (their quotes
 * would confuse the attribute scan), then each tag is read with quoted attribute values
 * skipped, so a `>` inside a value cannot end the tag early and hide a later handler.
 *
 * @param {string} source - template source, comments stripped
 * @returns {string|null} the first offending tag
 */
function findInlineHandler(source) {
    const markup = source.replace(/\{\{\{?[\s\S]*?\}\}\}?/g, 'X');
    for (const tag of markup.matchAll(/<[a-z][a-z0-9-]*((?:"[^"]*"|'[^']*'|[^'">])*)>/gi)) {
        const attrs = tag[1].replace(/"[^"]*"|'[^']*'/g, '""');
        if (/\son[a-z]+\s*=/i.test(attrs)) {
            return tag[0];
        }
    }
    return null;
}

/**
 * Finds a Handlebars expression written inside a JavaScript string literal of an inline
 * script. HTML escaping is not JavaScript escaping (entities are not decoded inside <script>,
 * a backslash is not escaped at all), so a value belongs in a hidden input or a data
 * attribute that the script reads.
 *
 * @param {string} source - template source, comments stripped
 * @returns {string|null} the offending line
 */
function findScriptStringInterpolation(source) {
    for (const script of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
        if (/\ssrc\s*=/i.test(script[1])) {
            continue;
        }
        const hit = script[2].match(/[^\n]*(['"`])\{\{[^\n]*/);
        if (hit) {
            return hit[0].trim();
        }
    }
    return null;
}

// Splits the parameter list of a helper call into its top-level tokens: quoted strings and
// parenthesised subexpressions stay whole
function splitParams(text) {
    const tokens = [];
    let current = '';
    let depth = 0;
    let quote = null;
    for (const ch of text) {
        if (quote) {
            current += ch;
            if (ch === quote) {
                quote = null;
            }
        } else if (ch === '"' || ch === "'") {
            quote = ch;
            current += ch;
        } else if (ch === '(') {
            depth++;
            current += ch;
        } else if (ch === ')') {
            depth--;
            current += ch;
        } else if (/\s/.test(ch) && depth === 0) {
            if (current) {
                tokens.push(current);
            }
            current = '';
        } else {
            current += ch;
        }
    }
    if (current) {
        tokens.push(current);
    }
    return tokens;
}

const STRING_LITERAL = /^("[^"]*"|'[^']*')$/;

/**
 * Checks the parameters of every `_` translation helper call. The helper escapes a parameter
 * unless it is already a SafeString, so what can inject markup is a subexpression returning
 * one: only `escapeHtml` (escapes) and `markup` with a string literal (template-authored) are
 * admitted. `markup` anywhere else must take a literal too.
 *
 * @param {string} source - template source, comments stripped
 * @returns {string|null} the offending call
 */
function findUnsafeTranslationParam(source) {
    for (const call of source.matchAll(/\{\{\{?~?\s*_\s+(?:"[^"]*"|'[^']*')([\s\S]*?)\}\}/g)) {
        // the first parameter is the locale
        const params = splitParams(call[1].trim()).slice(1);
        for (const param of params) {
            if (!param.startsWith('(')) {
                continue;
            }
            const inner = splitParams(param.slice(1, -1).trim());
            const admitted = inner[0] === 'escapeHtml' || (inner[0] === 'markup' && inner.length === 2 && STRING_LITERAL.test(inner[1]));
            if (!admitted) {
                return call[0].replace(/\s+/g, ' ');
            }
        }
    }
    for (const call of source.matchAll(/[({]\s*markup\s+([^)}]*)[)}]/g)) {
        if (!STRING_LITERAL.test(call[1].trim())) {
            return call[0];
        }
    }
    return null;
}

/**
 * @param {string} rel - template path relative to views/
 * @param {string} source - template source, comments stripped
 * @returns {string|null} the first triple-stash not on the allowlist
 */
function findUnlistedTripleStash(rel, source) {
    for (const match of source.matchAll(/\{\{\{\s*([^}]*?)\s*\}\}\}/g)) {
        const key = `${rel.split(pathlib.sep).join('/')} {{{${match[1]}}}}`;
        if (!TRIPLE_STASH_ALLOWLIST.has(key)) {
            return key;
        }
    }
    return null;
}

test('the guardrail scanners find what they look for', async t => {
    await t.test('an event handler after a > inside an attribute value', () => {
        const source = '<button data-hint="a > b" onclick="run()">x</button>';
        // The old single-regex scan stopped at the > inside the value and missed the handler
        assert.equal(/<[a-z][^>]*\s+on[a-z]+\s*=/i.test(source), false);
        assert.ok(findInlineHandler(source));
        assert.equal(findInlineHandler('<a title="{{_ "x" locale}}" data-on="1" href="/">x</a>'), null);
        assert.equal(findInlineHandler('<p>Click on=this</p>'), null);
    });

    await t.test('a javascript: URL in formaction or xlink:href', () => {
        assert.match('<button formaction="javascript:run()">', JAVASCRIPT_URL);
        assert.match('<use xlink:href="javascript:run()">', JAVASCRIPT_URL);
    });

    await t.test('an expression inside a string literal of an inline script', () => {
        assert.ok(findScriptStringInterpolation('<script nonce="{{cspNonce}}">const a = \'{{account}}\';</script>'));
        assert.ok(findScriptStringInterpolation('<script nonce="{{cspNonce}}">const a = "{{account}}";</script>'));
        assert.equal(findScriptStringInterpolation('<script nonce="{{cspNonce}}">{{#if x}}run();{{/if}}</script>'), null);
        assert.equal(findScriptStringInterpolation('<script src="/x.js" data-a="{{b}}"></script>'), null);
    });

    await t.test('a translation parameter that could carry markup', () => {
        assert.equal(findUnsafeTranslationParam('{{_ "a %s" templateLocale value}}'), null);
        assert.equal(findUnsafeTranslationParam('{{_ "a %s" templateLocale (escapeHtml value)}}'), null);
        assert.equal(findUnsafeTranslationParam(`{{_ "a <a%s>" templateLocale (markup " href='#'")}}`), null);
        assert.ok(findUnsafeTranslationParam('{{_ "a %s" templateLocale (markup value)}}'));
        assert.ok(findUnsafeTranslationParam('{{_ "a %s" templateLocale (lastVal value)}}'));
        assert.ok(findUnsafeTranslationParam('{{markup value}}'));
    });

    await t.test('a triple-stash outside the allowlist', () => {
        assert.equal(findUnlistedTripleStash('license.hbs', '{{{eulaText}}}'), null);
        assert.ok(findUnlistedTripleStash('license.hbs', '{{{somethingElse}}}'));
    });
});

test('every view template is compatible with the admin Content-Security-Policy', async t => {
    const templates = listFiles(VIEWS_DIR, '.hbs');
    assert.ok(templates.length > 100, 'the view tree was found');

    let inlineScripts = 0;

    for (let file of templates) {
        const rel = pathlib.relative(VIEWS_DIR, file);
        // comments document usage with example markup that is not rendered
        const source = stripHandlebarsComments(fs.readFileSync(file, 'utf-8'));

        await t.test(rel, () => {
            for (const attrs of inlineScriptAttrs(source)) {
                inlineScripts++;
                assert.match(attrs, NONCE_ATTR, `inline <script${attrs}> must carry nonce="{{cspNonce}}"`);
            }

            for (const attrs of scriptTagAttrs(source)) {
                assert.match(attrs, CFASYNC_ATTR, `<script${attrs}> must carry data-cfasync="false"`);
            }

            const handler = findInlineHandler(source);
            assert.equal(handler, null, `inline event handler attribute: ${handler}`);

            const interpolation = findScriptStringInterpolation(source);
            assert.equal(interpolation, null, `expression inside a JavaScript string literal (use a hidden input): ${interpolation}`);

            const translation = findUnsafeTranslationParam(source);
            assert.equal(translation, null, `translation parameter that can carry markup: ${translation}`);

            const tripleStash = findUnlistedTripleStash(rel, source);
            assert.equal(tripleStash, null, `unescaped triple-stash not on the allowlist: ${tripleStash}`);

            // style-src-elem carries the nonce too, and a template has no reason to inline a
            // sheet: the admin styles are built into static/css/flyonui.css, the public pages
            // use static/css/public.css. A style attribute is fine (style-src-attr).
            const style = source.match(STYLE_ELEMENT);
            assert.equal(style, null, `inline <style> element: ${style && style[0]}`);

            const url = source.match(JAVASCRIPT_URL);
            assert.equal(url, null, `javascript: URL: ${url && url[0]}`);
        });
    }

    // The two pre-paint theme scripts alone account for two; a count of zero would mean the
    // scan matched nothing and the guardrail guards nothing
    assert.ok(inlineScripts >= 2, `expected inline scripts to be found, saw ${inlineScripts}`);
});
