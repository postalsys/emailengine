'use strict';

// Finds the EENGINE_* environment variables the runtime code reads, for the guardrail that keeps
// ENVIRONMENT.md complete. Pure filesystem read.
//
// A name counts when it appears as a whole string literal ('EENGINE_X', the form readEnvValue(),
// hasEnvValue() and every lookup table take) or as a direct process.env property. Comments are
// stripped first, so a name that only survives in a comment about a removed variable is not
// mistaken for one that is still read. A literal ending in an underscore is a prefix that a
// family of variables is built from (EENGINE_API_TLS_ + CERT, KEY, ...) and is reported as such.

const fs = require('fs');
const pathlib = require('path');

const ROOT = pathlib.join(__dirname, '..', '..');

function sourceFiles() {
    const files = [pathlib.join(ROOT, 'server.js')];
    const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = pathlib.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(full);
            } else if (entry.name.endsWith('.js')) {
                files.push(full);
            }
        }
    };
    for (const dir of ['lib', 'workers', 'bin']) {
        walk(pathlib.join(ROOT, dir));
    }
    return files;
}

// Good enough for this codebase: no regular expression literal or string in lib/ contains `//` or
// `/*` in a way that would swallow a variable name, and a miss here only ever hides a name, which
// the guardrail would then fail to require, never invents one
function stripComments(source) {
    return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\'"`])\/\/.*$/gm, '$1');
}

/**
 * @returns {{ names: Map<string, string[]>, prefixes: Map<string, string[]> }} Each variable and
 *     each prefix, mapped to the files (relative to the repository root) that read it
 */
function scanEnvVars() {
    const names = new Map();
    const prefixes = new Map();

    const add = (map, name, file) => {
        if (!map.has(name)) {
            map.set(name, []);
        }
        if (!map.get(name).includes(file)) {
            map.get(name).push(file);
        }
    };

    for (const file of sourceFiles()) {
        const relative = pathlib.relative(ROOT, file).split(pathlib.sep).join('/');
        const source = stripComments(fs.readFileSync(file, 'utf-8'));

        for (const match of source.matchAll(/(['"`])(EENGINE_[A-Z0-9_]+)\1/g)) {
            const name = match[2];
            add(name.endsWith('_') ? prefixes : names, name, relative);
        }
        for (const match of source.matchAll(/process\.env\.(EENGINE_[A-Z0-9_]+)/g)) {
            add(names, match[1], relative);
        }
    }

    return { names, prefixes };
}

module.exports = { scanEnvVars, ROOT };
