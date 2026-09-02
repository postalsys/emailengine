'use strict';

// Tripwire for a Handlebars footgun that produces silently broken markup.
//
// Handlebars merges a partial's hash params into the CALLER'S context, and a partial has no
// way to tell the two apart. So a ui/* partial that renders `{{#if id}}id="{{id}}"{{/if}}`
// also picks up an `id` that merely happens to be in scope - and when the surrounding
// context is a row of an {{#each}}, that is the row's own id, emitted once per row.
//
// This is not theoretical: the oauth-apps and webhook-routes list pages both shipped status
// badges stamped with the row's entity id, and the API reference hit it twice while being
// built, each time emitting the operation id on several elements per operation. Duplicate
// ids break getElementById, deep links and label/aria wiring, and nothing fails loudly.
//
// The fix at a call site is to neutralize the param: `{{> ui/badge label="Yes" id=""}}`.
// ui/badge, ui/stat-card and ui/tabs - the ones actually rendered per row - instead take
// `elId`, which a row model cannot shadow; this test covers the remaining partials that
// still read a bare `id`.
//
// SCOPE: a risky call is in scope when the row context can reach it, which is NOT only
// "inside an {{#each}} in the same file". The dominant shape is
// `{{#each rows}}{{> row-partial}}{{/each}}`, where the each lives in the CALLER and the
// risky call sits at depth 0 inside the row partial. Both are checked - an earlier
// file-local version of this test was green over ~0.4% of the surface and would not have
// caught either incident above.
//
// Only `id` is checked. The other inheritable params (class, title, label...) produce
// visible styling or text bugs; a wrong id is invisible until something breaks.
//
// Pure filesystem read - no Redis, no server, exits cleanly on its own.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { stripHandlebarsComments: stripComments } = require('./helpers/hbs-comments');

const ROOT = pathlib.join(__dirname, '..');
const VIEWS = pathlib.join(ROOT, 'views');
const UI_DIR = pathlib.join(VIEWS, 'partials', 'ui');

// Matches both a partial that stamps the id itself and one that forwards it to another
// partial (ui/confirm-modal and ui/delete-modal pass `id=id` down to ui/modal).
const READS_ID = /\{\{#if id\}\}|\{\{id\}\}|\bid=id\b/;

// Any partial invocation, block or inline, with its hash arguments.
const INVOCATION = /\{\{#?>\s*([a-z][a-z0-9/-]*)([\s\S]*?)\}\}/g;

const hbsFiles = dir => listFiles(dir, '.hbs');

// Partial name as Handlebars resolves it, e.g. views/partials/ui/badge.hbs -> "ui/badge"
function partialName(file) {
    const rel = pathlib.relative(pathlib.join(VIEWS, 'partials'), file);
    return rel.startsWith('..')
        ? null
        : rel
              .replace(/\.hbs$/, '')
              .split(pathlib.sep)
              .join('/');
}

// {{#each}} nesting depth as of each line of a source file.
function eachDepths(source) {
    let depth = 0;
    return source.split('\n').map(line => {
        const before = depth;
        depth += (line.match(/\{\{#each\b/g) || []).length;
        depth -= (line.match(/\{\{\/each\}\}/g) || []).length;
        return Math.max(before, depth);
    });
}

test('no ui/* partial can inherit a row id from its context', () => {
    const files = hbsFiles(VIEWS);

    const riskyPartials = new Set(
        fs
            .readdirSync(UI_DIR)
            .filter(name => name.endsWith('.hbs'))
            .filter(name => READS_ID.test(stripComments(fs.readFileSync(pathlib.join(UI_DIR, name), 'utf-8'))))
            .map(name => `ui/${name.replace(/\.hbs$/, '')}`)
    );

    assert.ok(riskyPartials.size, 'expected to find ui/* partials that render an id');

    // Pass 1: which partials are themselves rendered inside an {{#each}} somewhere? Their
    // whole body executes with a row as context, so a risky call anywhere in them counts.
    const rowRendered = new Set();
    for (const file of files) {
        const source = stripComments(fs.readFileSync(file, 'utf-8'));
        const depths = eachDepths(source);
        let match;
        INVOCATION.lastIndex = 0;
        while ((match = INVOCATION.exec(source))) {
            const line = source.slice(0, match.index).split('\n').length - 1;
            if (depths[line]) {
                rowRendered.add(match[1]);
            }
        }
    }

    // Pass 2: flag risky calls that a row context can reach and that do not neutralize id.
    const leaks = [];
    for (const file of files) {
        const source = stripComments(fs.readFileSync(file, 'utf-8'));
        const depths = eachDepths(source);
        const inRowPartial = rowRendered.has(partialName(file));

        let match;
        INVOCATION.lastIndex = 0;
        while ((match = INVOCATION.exec(source))) {
            const [, name, args] = match;
            if (!riskyPartials.has(name) || /\bid=/.test(args)) {
                continue;
            }

            const line = source.slice(0, match.index).split('\n').length - 1;
            if (depths[line] || inRowPartial) {
                leaks.push(`${pathlib.relative(ROOT, file)}:${line + 1} ${name}${inRowPartial && !depths[line] ? ' (file is rendered per row)' : ''}`);
            }
        }
    }

    assert.deepEqual(leaks, [], `these ui/* calls can inherit a row's id - pass id="" to neutralize it:\n  ${leaks.join('\n  ')}`);
});
