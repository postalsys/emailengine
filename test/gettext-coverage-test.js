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
const os = require('os');
const pathlib = require('path');

const ROOT = pathlib.join(__dirname, '..');

test('every ui-routes module with gettext strings is referenced in translations/messages.pot', () => {
    const pot = fs.readFileSync(pathlib.join(ROOT, 'translations', 'messages.pot'), 'utf-8');

    const uiRoutesDir = pathlib.join(ROOT, 'lib', 'ui-routes');
    const files = fs.readdirSync(uiRoutesDir).filter(name => name.endsWith('.js'));

    const missing = [];
    for (const name of files) {
        const content = fs.readFileSync(pathlib.join(uiRoutesDir, name), 'utf-8');
        // Translatable strings are wrapped in gt.gettext(...) / request.app.gt.gettext(...),
        // plural strings in gt.ngettext(...) - a module may legitimately contain only the latter
        if (!/\.n?gettext\(/.test(content)) {
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

// gettext-extract.js silently skips interpolated template literals (they forward runtime values
// and cannot define a msgid), so a gettext(\`...\${x}\`) call would ship untranslated in every
// locale with no other warning - this tripwire fails CI with the offending file:line instead.
// Zero-expression backtick strings are legitimate and extracted normally.
test('gettext()/ngettext() calls do not use interpolated template literals', () => {
    const { listScanFiles, parseFile, calleeName } = require(pathlib.join(ROOT, 'gettext-extract.js'));
    const { full: walkFull } = require('acorn-walk');

    const offenders = [];
    for (const filePath of listScanFiles()) {
        const ast = parseFile(filePath);
        walkFull(ast, node => {
            if (node.type !== 'CallExpression') {
                return;
            }
            const name = calleeName(node.callee);
            if (name !== 'gettext' && name !== 'ngettext') {
                return;
            }
            // msgid argument for gettext, msgid + plural for ngettext
            const stringArgs = name === 'gettext' ? node.arguments.slice(0, 1) : node.arguments.slice(0, 2);
            for (const arg of stringArgs) {
                if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
                    offenders.push(`${pathlib.relative(ROOT, filePath)}:${arg.loc.start.line}`);
                }
            }
        });
    }

    assert.deepStrictEqual(
        offenders,
        [],
        `gettext()/ngettext() must be called with literal strings - gettext-extract.js skips interpolated template ` +
            `literals, so these strings would silently ship untranslated. Use a literal msgid with util.format-style ` +
            `placeholders instead:\n${offenders.join('\n')}`
    );
});

// In gettext-parser the entry with msgid "" is the POT file header, so an extracted empty msgid
// would append source references onto the header block (and ngettext would inject msgid_plural
// into it), corrupting the file for msgmerge/poedit
test('gettext-extract skips empty msgids that would corrupt the POT header', () => {
    const { extractFromFile } = require(pathlib.join(ROOT, 'gettext-extract.js'));

    const tmpFile = pathlib.join(os.tmpdir(), `gettext-extract-test-${process.pid}.js`);
    fs.writeFileSync(
        tmpFile,
        ["gt.gettext('');", "gt.ngettext('', '%d items', n);", "gt.gettext('Real string');", "gt.ngettext('%d item', '%d items', n);", ''].join('\n')
    );

    try {
        const entries = extractFromFile(tmpFile);
        assert.deepStrictEqual(
            entries.map(entry => entry.msgid),
            ['Real string', '%d item'],
            'empty msgids must be skipped, non-empty msgids must be extracted'
        );
    } finally {
        fs.unlinkSync(tmpFile);
    }
});
