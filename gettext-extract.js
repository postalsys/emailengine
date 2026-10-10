'use strict';

// Extracts translatable strings from JS sources into translations/messages.pot.
// Run via `npm run gettext` after xgettext-template has written the strings of the Handlebars
// views to translations/messages.pot.tmp - this script joins the strings found in JS files into
// that catalog and writes the result to translations/messages.pot.
//
// The output is canonical: an unchanged source tree produces a byte-identical file. That takes
// two things xgettext-template does not do. It parses the views in the order their reads
// complete (async.parallel over fs.readFile), so both the entry order and the order of the
// reference lines of a string used in several views changed from run to run; both are sorted
// here. And the creation date is only stamped when the catalog content actually changed.
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
// The catalog of the Handlebars views, as written by xgettext-template
const TEMPLATES_POT_PATH = `${POT_PATH}.tmp`;

// All server-side code that may contain gettext()/ngettext() calls
const SCAN_DIRS = ['bin', 'lib', 'workers'];
const SCAN_FILES = ['server.js'];

function listJsFiles(dir) {
    return fs
        .readdirSync(dir, { recursive: true })
        .filter(entryPath => entryPath.endsWith('.js'))
        .map(entryPath => Path.join(dir, entryPath));
}

// The full sorted scan set (sorted to keep POT reference output deterministic)
function listScanFiles() {
    let files = SCAN_FILES.map(file => Path.join(ROOT_DIR, file));
    for (let dir of SCAN_DIRS) {
        files = files.concat(listJsFiles(Path.join(ROOT_DIR, dir)));
    }
    return files.sort();
}

function parseFile(filePath) {
    const source = fs.readFileSync(filePath, 'utf-8');
    try {
        return parse(source, { ecmaVersion: 'latest', sourceType: 'script', locations: true, allowHashBang: true });
    } catch (err) {
        err.message = `Failed to parse ${filePath}: ${err.message}`;
        throw err;
    }
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
    const ast = parseFile(filePath);

    let entries = [];
    let reference = node => `${Path.relative(ROOT_DIR, filePath)}:${node.loc.start.line}`;

    walkFull(ast, node => {
        if (node.type !== 'CallExpression') {
            return;
        }

        let name = calleeName(node.callee);

        // An empty msgid is skipped (like xgettext does): translations[''] is the POT header
        // entry in gettext-parser, so an empty key would corrupt the header block
        if (name === 'gettext' && node.arguments.length >= 1) {
            let msgid = resolveString(node.arguments[0]);
            if (msgid !== false && msgid !== '') {
                entries.push({ msgid, reference: reference(node) });
            }
        }

        if (name === 'ngettext' && node.arguments.length >= 2) {
            let msgid = resolveString(node.arguments[0]);
            let msgidPlural = resolveString(node.arguments[1]);
            if (msgid !== false && msgid !== '' && msgidPlural !== false) {
                entries.push({ msgid, msgidPlural, reference: reference(node) });
            }
        }
    });

    return entries;
}

// "views/a.hbs:12" -> ['views/a.hbs', 12], so line 9 sorts before line 10
function parseReference(reference) {
    let separator = reference.lastIndexOf(':');
    return [reference.slice(0, separator), Number(reference.slice(separator + 1))];
}

function compareReferences(a, b) {
    let [pathA, lineA] = parseReference(a);
    let [pathB, lineB] = parseReference(b);
    if (pathA !== pathB) {
        return pathA < pathB ? -1 : 1;
    }
    return lineA - lineB;
}

// One reference per line as written here, but several to a line in catalogs from GNU tools
function getReferences(entry) {
    let reference = entry.comments && entry.comments.reference;
    return reference ? reference.split(/\s+/).filter(value => value) : [];
}

const compareStrings = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Entries in source order: by their first reference, so a file's strings stay together in the
// order they appear in it. Context, then msgid, break ties (several strings on one line)
function compareEntries(a, b) {
    let refA = getReferences(a)[0] || '';
    let refB = getReferences(b)[0] || '';
    if (refA !== refB) {
        return compareReferences(refA, refB);
    }
    return compareStrings(a.msgctxt || '', b.msgctxt || '') || compareStrings(a.msgid, b.msgid);
}

/**
 * Compiles a parsed catalog in canonical form: every entry's references sorted, and the entries
 * sorted by their first one. Mutates the reference comments of `pot`
 * @param {Object} pot - Catalog as returned by po.parse()
 * @returns {Buffer} The compiled POT file
 */
function compileCanonical(pot) {
    for (let entries of Object.values(pot.translations)) {
        for (let entry of Object.values(entries)) {
            let references = getReferences(entry);
            if (references.length) {
                entry.comments.reference = references.sort(compareReferences).join('\n');
            }
        }
    }
    return po.compile(pot, { sort: compareEntries });
}

function formatCreationDate(date) {
    return date
        .toISOString()
        .replace(/T/, ' ')
        .replace(/:\d+\.\d+Z$/, '+0000');
}

function main() {
    let files = listScanFiles();

    let extracted = [];
    for (let filePath of files) {
        extracted = extracted.concat(extractFromFile(filePath));
    }

    let pot = po.parse(fs.readFileSync(TEMPLATES_POT_PATH));
    let translations = (pot.translations[''] = pot.translations[''] || {});

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
        let references = getReferences(entry);
        if (!references.includes(reference)) {
            references.push(reference);
        }
        entry.comments.reference = references.join('\n');
    }

    // xgettext-template does not stamp a creation date (jsxgettext used to). The previous date is
    // kept unless the content changed, so an unchanged tree leaves the file as it was
    let existing = fs.existsSync(POT_PATH) ? fs.readFileSync(POT_PATH) : Buffer.alloc(0);
    pot.headers = pot.headers || {};
    pot.headers['POT-Creation-Date'] = existing.length ? po.parse(existing).headers['POT-Creation-Date'] : '';
    let output = compileCanonical(pot);

    let changed = !output.equals(existing);
    if (changed) {
        pot.headers['POT-Creation-Date'] = formatCreationDate(new Date());
        fs.writeFileSync(POT_PATH, compileCanonical(pot));
    }

    console.log(
        `Extracted ${extracted.length} gettext strings from ${files.length} JS files into ${Path.relative(ROOT_DIR, POT_PATH)}${changed ? '' : ' (unchanged)'}`
    );
}

if (require.main === module) {
    try {
        main();
    } finally {
        // Also on failure, so a broken run does not leave the intermediate file behind
        fs.rmSync(TEMPLATES_POT_PATH, { force: true });
    }
}

// Exported for the gettext coverage test, which walks the same scan set with the same helpers
module.exports = { listScanFiles, parseFile, calleeName, extractFromFile, compareReferences, compileCanonical };
