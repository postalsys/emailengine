'use strict';

// Tripwire: every EENGINE_* environment value is read through readEnvValue(), the one helper that gives
// a variable its `<KEY>_FILE` form and trims the value.
//
// A direct process.env read is not a smaller version of that - it is a variable whose documented file
// form silently does nothing. EENGINE_MAX_SIZE was read that way in lib/schemas.js while server.js and
// workers/api.js resolved the same variable through the helper, so EENGINE_MAX_SIZE_FILE raised the
// listener limit and not the validation schema's maximum. Two modules carried private copies of the
// helper that stripped only a trailing newline, so EENGINE_REDIS_FILE and EENGINE_SECRET_FILE behaved
// differently from every other file-backed variable.
//
// Pure filesystem read - no Redis, no server.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const ROOT = pathlib.join(__dirname, '..');

// The two modules that cannot use the helper, because the helper logs: lib/read-env-value.js requires
// lib/logger.js, which requires lib/consts.js, so either one requiring it back would be a cycle. Both
// read variables that decide how the process logs and where its keys live, before there is anything to
// log through, and neither value is a secret that would be handed over in a file.
const EXEMPT_FILES = new Set(['lib/consts.js', 'lib/logger.js']);

// A write, a delete, or the helper's own fallback read
const ALLOWED_CONTEXT = /^\s*(=[^=]|\?\?=)/;

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

test('every EENGINE_* environment value is read through readEnvValue()', () => {
    const offenders = [];

    for (const file of sourceFiles()) {
        const relative = pathlib.relative(ROOT, file).split(pathlib.sep).join('/');
        if (EXEMPT_FILES.has(relative)) {
            continue;
        }

        const content = fs.readFileSync(file, 'utf-8');
        for (const match of content.matchAll(/process\.env\.(EENGINE_[A-Z0-9_]+)/g)) {
            // `delete process.env.X` and `process.env.X = ...` set a value rather than reading one
            const before = content.slice(Math.max(0, match.index - 7), match.index);
            if (/delete\s+$/.test(before) || ALLOWED_CONTEXT.test(content.slice(match.index + match[0].length))) {
                continue;
            }
            const line = content.slice(0, match.index).split('\n').length;
            offenders.push(`${relative}:${line} reads ${match[1]} directly`);
        }
    }

    assert.deepEqual(
        offenders,
        [],
        `These reads bypass readEnvValue(), so the variable's documented <KEY>_FILE form does nothing ` +
            `and the value is not trimmed:\n${offenders.join('\n')}`
    );
});

test('readEnvValue is the only implementation of the file fallback', () => {
    // Two modules used to carry private copies that stripped a trailing newline instead of trimming, so
    // a file with surrounding whitespace produced a different value than every other variable
    const copies = [];
    for (const file of sourceFiles()) {
        const relative = pathlib.relative(ROOT, file).split(pathlib.sep).join('/');
        if (relative === 'lib/read-env-value.js') {
            continue;
        }
        // The copies read the file named by the `_FILE` variable. A presence check against that name
        // is not a copy: lib/tools.js hasEnvValue() does exactly that and defers the read to the helper.
        if (/readFileSync\(process\.env\[/.test(fs.readFileSync(file, 'utf-8'))) {
            copies.push(relative);
        }
    }

    assert.deepEqual(copies, [], `These modules re-implement the <KEY>_FILE fallback instead of calling readEnvValue():\n${copies.join('\n')}`);
});
