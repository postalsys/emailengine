'use strict';

// Tripwire: every EENGINE_* environment variable the runtime code reads is listed in ENVIRONMENT.md.
//
// About forty variables used to be read in code and documented nowhere in the repository, among
// them EENGINE_REDIS_PREFIX, EENGINE_WEBHOOK_TIMEOUT and EENGINE_CORS_ORIGIN, so an operator could
// only find them by reading the source. A variable added from now on fails here until it has an
// entry, and one that is documented but no longer read fails too, so the reference cannot describe
// knobs that do nothing. Pure filesystem read.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { scanEnvVars, ROOT } = require('./helpers/env-var-scan');

const DOC = fs.readFileSync(pathlib.join(ROOT, 'ENVIRONMENT.md'), 'utf-8');

// Names that appear in the code as a string but are not variables of their own (a `_FILE` form
// spelled out in a message, a member of a documented prefix family), name -> reason. Empty today:
// the scanner strips comments, which is where such names have lived so far.
const NOT_VARIABLES = new Map();

// The table rows of the document, by the variable in their first cell
function documentedNames() {
    const names = new Set();
    for (const match of DOC.matchAll(/^\|\s*`(EENGINE_[A-Z0-9_]+\*?)`\s*\|/gm)) {
        names.add(match[1]);
    }
    return names;
}

test('every EENGINE_* variable the code reads is documented in ENVIRONMENT.md', () => {
    const documented = documentedNames();
    const { names, prefixes } = scanEnvVars();

    const missing = [];
    for (const [name, files] of names) {
        if (NOT_VARIABLES.has(name) || documented.has(name)) {
            continue;
        }
        missing.push(`${name} (read in ${files.join(', ')})`);
    }
    for (const [prefix, files] of prefixes) {
        if (!documented.has(`${prefix}*`)) {
            missing.push(`${prefix}* (variable family built in ${files.join(', ')})`);
        }
    }

    assert.deepEqual(missing, [], `Add these to ENVIRONMENT.md:\n${missing.join('\n')}`);
});

test('ENVIRONMENT.md documents no variable the code no longer reads', () => {
    const { names, prefixes } = scanEnvVars();
    const stale = [...documentedNames()].filter(name => (name.endsWith('*') ? !prefixes.has(name.slice(0, -1)) : !names.has(name)));
    assert.deepEqual(stale, [], `These are documented but nothing reads them:\n${stale.join('\n')}`);
});

test('every exception is still needed', () => {
    const { names } = scanEnvVars();
    for (const name of NOT_VARIABLES.keys()) {
        assert.ok(names.has(name), `${name} is no longer in the code; drop it from NOT_VARIABLES`);
    }
});

test('the scanner itself finds the three ways a variable is read', () => {
    const { names, prefixes } = scanEnvVars();
    // readEnvValue('...') in a worker
    assert.ok(names.has('EENGINE_WEBHOOK_TIMEOUT'));
    // a name held in a lookup table rather than passed directly
    assert.ok(names.has('EENGINE_SUBMIT_QC'));
    // a family built from a prefix
    assert.ok(prefixes.has('EENGINE_API_TLS_'));
});
