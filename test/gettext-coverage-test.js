'use strict';

// Tripwire: every lib/ui-routes/*.js module that contains translatable strings (gt.gettext(...) calls)
// MUST have reference entries in translations/messages.pot. JS sources are scanned dynamically by
// gettext-extract.js (run via `npm run gettext`), which records a "lib/ui-routes/<file>:<line>"
// reference for every extracted string. The routes-ui.js decomposition moves route handlers - and
// their gettext strings - into focused ui-routes/ modules; this test guards against a module whose
// translatable strings never made it into the POT, which would silently drop them from translations
// (e.g. the extractor scan list was narrowed, or `npm run gettext` was not re-run after adding the
// first gettext string to a new module).
//
// Pure filesystem read - no Redis, no server, exits cleanly on its own.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const ROOT = pathlib.join(__dirname, '..');

test('every ui-routes module with gettext strings is referenced in translations/messages.pot', () => {
    const pot = fs.readFileSync(pathlib.join(ROOT, 'translations', 'messages.pot'), 'utf-8');

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
        if (!pot.includes(ref)) {
            missing.push(ref);
        }
    }

    assert.deepStrictEqual(
        missing,
        [],
        `These lib/ui-routes modules contain gettext() strings but have no references in translations/messages.pot, ` +
            `so their translatable strings are missing from the POT:\n${missing.join('\n')}\n` +
            `Run "npm run gettext" to re-extract strings, and check the SCAN_DIRS list in gettext-extract.js if the module is still missing.`
    );
});
