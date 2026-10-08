'use strict';

// Guardrail for uiBusyAction() (static/js/ui.js).
//
// The helper takes the action as a function and calls it after marking the button busy, so the
// busy state lasts as long as the request and doubles as the re-entrancy guard. Handing it a
// promise instead type-checks fine and even works: Promise.resolve().then() ignores a
// non-function, the request (already started at the call site) still runs, and the button
// leaves its busy state on the next tick. Nothing looks wrong except that the button never
// shows busy and a second click posts again - which is how the TLS page's Check reachability
// and Request buttons shipped. The helper now throws on a non-function too, but only once
// somebody clicks the button in a browser; this catches it before that. Every call lives in a
// view, static/js only holds the definition.
//
// Pure: reads the templates, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { stripHandlebarsComments } = require('./helpers/hbs-comments');

const ROOT = pathlib.join(__dirname, '..');

// The second argument has to be a function: an arrow, async arrow, function expression, or a
// reference to one passed by name.
const CALL = /\buiBusyAction\(\s*[\w$.]+\s*,\s*([^\n]{0,40})/g;
const FUNCTION_ARG = /^(async\s*)?(\([^)]*\)|[\w$]+)\s*=>|^(async\s+)?function\b|^[\w$]+\s*\)/;

test('every uiBusyAction() call passes the action as a function', () => {
    let calls = 0;
    const offenders = [];
    for (const file of listFiles(pathlib.join(ROOT, 'views'), '.hbs')) {
        const source = stripHandlebarsComments(fs.readFileSync(file, 'utf-8'));
        for (const match of source.matchAll(CALL)) {
            calls++;
            if (!FUNCTION_ARG.test(match[1])) {
                const line = source.slice(0, match.index).split('\n').length;
                offenders.push(`${pathlib.relative(ROOT, file)}:${line}: ${match[0].trim()}`);
            }
        }
    }

    assert.ok(calls > 0, 'no uiBusyAction() calls found, the pattern no longer matches anything');
    assert.deepEqual(offenders, [], 'uiBusyAction() needs `() => request()`, not the request promise itself');
});
