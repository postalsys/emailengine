'use strict';

// Extracts translatable strings from JS sources into translations/messages.pot.
// Run via `npm run gettext` after xgettext-template has generated the POT from the
// Handlebars views - this script joins the strings found in JS files into that file.
//
// Replaces jsxgettext, which bundled acorn 5 and crashed on post-ES2018 syntax
// (optional chaining, nullish coalescing, etc.). Files are discovered dynamically,
// so new modules with gettext()/ngettext() calls are picked up automatically.

const { parse } = require('acorn');
const { full: walkFull } = require('acorn-walk');
const { po } = require('gettext-parser');
const fs = require('fs');
const Path = require('path');

const ROOT_DIR = __dirname;
const POT_PATH = Path.join(ROOT_DIR, 'translations', 'messages.pot');

// All server-side code that may contain gettext()/ngettext() calls
const SCAN_DIRS = ['bin', 'lib', 'workers'];
const SCAN_FILES = ['server.js'];

function listJsFiles(dir) {
    return fs
        .readdirSync(dir, { recursive: true })
        .filter(entryPath => entryPath.endsWith('.js'))
        .map(entryPath => Path.join(dir, entryPath));
}

// Resolves a call argument into a string value. Handles string literals and
// concatenation of string literals ('foo' + 'bar'). Returns false for anything
// dynamic (identifiers, template literals with expressions, etc.) - such calls
// forward runtime values and do not define new translatable strings.
function resolveString(node) {
    switch (node.type) {
        case 'Literal':
            return typeof node.value === 'string' ? node.value : false;
        case 'TemplateLiteral':
            return node.expressions.length === 0 ? node.quasis[0].value.cooked : false;
        case 'BinaryExpression': {
            if (node.operator !== '+') {
                return false;
            }
            let left = resolveString(node.left);
            let right = resolveString(node.right);
            return left !== false && right !== false ? left + right : false;
        }
        default:
            return false;
    }
}

function calleeName(callee) {
    if (callee.type === 'Identifier') {
        return callee.name;
    }
    if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
        return callee.property.name;
    }
    return false;
}

function extractFromFile(filePath) {
    const source = fs.readFileSync(filePath, 'utf-8');

    let ast;
    try {
        ast = parse(source, { ecmaVersion: 'latest', sourceType: 'script', locations: true, allowHashBang: true });
    } catch (err) {
        err.message = `Failed to parse ${filePath}: ${err.message}`;
        throw err;
    }

    let entries = [];
    let reference = node => `${Path.relative(ROOT_DIR, filePath)}:${node.loc.start.line}`;

    walkFull(ast, node => {
        if (node.type !== 'CallExpression') {
            return;
        }

        let name = calleeName(node.callee);

        if (name === 'gettext' && node.arguments.length >= 1) {
            let msgid = resolveString(node.arguments[0]);
            if (msgid !== false) {
                entries.push({ msgid, reference: reference(node) });
            }
        }

        if (name === 'ngettext' && node.arguments.length >= 2) {
            let msgid = resolveString(node.arguments[0]);
            let msgidPlural = resolveString(node.arguments[1]);
            if (msgid !== false && msgidPlural !== false) {
                entries.push({ msgid, msgidPlural, reference: reference(node) });
            }
        }
    });

    return entries;
}

function main() {
    let files = SCAN_FILES.map(file => Path.join(ROOT_DIR, file));
    for (let dir of SCAN_DIRS) {
        files = files.concat(listJsFiles(Path.join(ROOT_DIR, dir)));
    }
    // keep POT reference output deterministic
    files.sort();

    let extracted = [];
    for (let filePath of files) {
        extracted = extracted.concat(extractFromFile(filePath));
    }

    let pot = po.parse(fs.readFileSync(POT_PATH));
    let translations = (pot.translations[''] = pot.translations[''] || {});

    // xgettext-template does not stamp a creation date, so set it here (jsxgettext used to)
    pot.headers = pot.headers || {};
    pot.headers['POT-Creation-Date'] = new Date()
        .toISOString()
        .replace(/T/, ' ')
        .replace(/:\d+\.\d+Z$/, '+0000');

    for (let { msgid, msgidPlural, reference } of extracted) {
        let entry = translations[msgid];
        if (!entry) {
            entry = translations[msgid] = { msgid, msgstr: [''] };
        }

        if (msgidPlural && !entry.msgid_plural) {
            entry.msgid_plural = msgidPlural;
            entry.msgstr = ['', ''];
        }

        entry.comments = entry.comments || {};
        let references = entry.comments.reference ? entry.comments.reference.split('\n') : [];
        if (!references.includes(reference)) {
            references.push(reference);
        }
        entry.comments.reference = references.join('\n');
    }

    fs.writeFileSync(POT_PATH, po.compile(pot));
    console.log(`Extracted ${extracted.length} gettext strings from ${files.length} JS files into ${Path.relative(ROOT_DIR, POT_PATH)}`);
}

main();
