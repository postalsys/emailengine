'use strict';

// Tripwire: every lib/ui-routes/*.js module that contains translatable strings (gt.gettext(...) calls)
// MUST be listed in the `gettext` npm script so jsxgettext extracts its strings into
// translations/messages.pot. The routes-ui.js decomposition moves route handlers - and their gettext
// strings - into focused ui-routes/ modules; this test guards against forgetting to add a new module to
// the gettext file list, which would silently drop its translatable strings on the next `npm run gettext`.
//
// Pure filesystem read - no Redis, no server, exits cleanly on its own.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const ROOT = pathlib.join(__dirname, '..');

test('every ui-routes module with gettext strings is listed in the gettext npm script', () => {
    const pkg = JSON.parse(fs.readFileSync(pathlib.join(ROOT, 'package.json'), 'utf-8'));
    const gettextScript = (pkg.scripts && pkg.scripts.gettext) || '';

    const uiRoutesDir = pathlib.join(ROOT, 'lib', 'ui-routes');
    const files = fs.readdirSync(uiRoutesDir).filter(name => name.endsWith('.js'));

    const missing = [];
    for (const name of files) {
        const content = fs.readFileSync(pathlib.join(uiRoutesDir, name), 'utf-8');
        // Translatable strings are wrapped in gt.gettext(...) / request.app.gt.gettext(...)
        if (!/\.gettext\(/.test(content)) {
            continue;
        }
        const ref = `lib/ui-routes/${name}`;
        if (!gettextScript.includes(ref)) {
            missing.push(ref);
        }
    }

    assert.deepStrictEqual(
        missing,
        [],
        `These lib/ui-routes modules contain gettext() strings but are NOT listed in the "gettext" npm script, ` +
            `so their translatable strings are dropped from translations/messages.pot:\n${missing.join('\n')}\n` +
            `Add each to the jsxgettext file list in package.json (and keep the "no newer syntax like ?." NB comment in the file).`
    );
});

test('ui-routes gettext() calls use quoted string literals, not template literals', () => {
    // jsxgettext (ecmaVersion 2018) extracts only quoted-string arguments; a gettext(`...`) template
    // literal is silently dropped from translations/messages.pot. Translatable strings must not be
    // interpolated anyway, so they should always be plain quoted literals.
    const uiRoutesDir = pathlib.join(ROOT, 'lib', 'ui-routes');
    const files = fs.readdirSync(uiRoutesDir).filter(name => name.endsWith('.js'));

    const offenders = [];
    for (const name of files) {
        const lines = fs.readFileSync(pathlib.join(uiRoutesDir, name), 'utf-8').split('\n');
        lines.forEach((line, i) => {
            if (/\.gettext\(`/.test(line)) {
                offenders.push(`lib/ui-routes/${name}:${i + 1}`);
            }
        });
    }

    assert.deepStrictEqual(
        offenders,
        [],
        `gettext() is called with a template literal (backticks) at these locations; jsxgettext cannot ` +
            `extract them, so the strings are silently dropped from translations/messages.pot. Use a quoted ` +
            `string literal instead:\n${offenders.join('\n')}`
    );
});
