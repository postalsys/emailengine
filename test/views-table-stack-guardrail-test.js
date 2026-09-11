'use strict';

// Guardrail for the ee-table-stack convention (static/css/src/app.tailwind.css, and
// `.claude/rules/admin-ui.md` for the authoring rules).
//
// Below the md breakpoint a table carrying `ee-table-stack` stops being a table: the head is
// hidden and every cell prints its column name from its own `data-label`. A cell that was
// given none renders as a bare value with nothing saying what it is - on a phone an accounts
// row would read "Connection failed" under the account name with no "Status" in front of it.
// The first cell is the exception: it is the row's heading, and the trailing kebab cell is
// marked `ee-stack-actions` instead, so it floats over that heading.
//
// Nothing at runtime notices a missing label, and the desktop table it was copied from looks
// unchanged, so this is the only thing that would catch it.
//
// Pure: reads the templates, nothing else.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');
const { stripHandlebarsComments } = require('./helpers/hbs-comments');

const VIEWS_DIR = pathlib.join(__dirname, '..', 'views');

// <table ...> opening tags whose class list carries ee-table-stack
const STACK_TABLE = /<table\b[^>]*\bclass="[^"]*\bee-table-stack\b[^"]*"[^>]*>/g;

/**
 * The first tbody row of a table, which is the one every other row is generated from -
 * these tables render their rows inside a single {{#each}}. A tbody that holds nothing but a
 * partial include has its rows in that partial (the network page's address list, which the
 * page also re-renders after an IP rescan), so follow it.
 *
 * @param {String} table - the table markup, from its opening tag onwards
 * @returns {String|null} the row's inner markup, or null when no row was found
 */
function firstBodyRow(table) {
    const body = table.match(/<tbody[^>]*>([\s\S]*)/);
    if (!body) {
        return null;
    }
    let markup = body[1];
    const row = markup.match(/<tr\b[^>]*>([\s\S]*?)<\/tr>/);
    if (row) {
        return row[1];
    }
    const include = markup.match(/\{\{>\s*([\w/-]+)\s*\}\}/);
    if (!include) {
        return null;
    }
    const partial = pathlib.join(VIEWS_DIR, 'partials', `${include[1]}.hbs`);
    if (!fs.existsSync(partial)) {
        return null;
    }
    const nested = stripHandlebarsComments(fs.readFileSync(partial, 'utf8')).match(/<tr\b[^>]*>([\s\S]*?)<\/tr>/);
    return nested ? nested[1] : null;
}

test('every ee-table-stack cell says which column it is', async t => {
    const templates = listFiles(VIEWS_DIR, '.hbs');
    assert.ok(templates.length > 100, 'the view tree was found');

    let tables = 0;

    for (let file of templates) {
        const source = stripHandlebarsComments(fs.readFileSync(file, 'utf8'));
        const rel = pathlib.relative(VIEWS_DIR, file);

        let match;
        STACK_TABLE.lastIndex = 0;
        while ((match = STACK_TABLE.exec(source))) {
            const end = source.indexOf('</table>', match.index);
            assert.ok(end > -1, `${rel}: ee-table-stack table is never closed`);
            const table = source.slice(match.index, end);
            tables++;

            const row = firstBodyRow(table);
            assert.ok(row, `${rel}: ee-table-stack table has no tbody row`);

            const cells = row.match(/<td\b[^>]*>/g) || [];
            assert.ok(cells.length > 1, `${rel}: ee-table-stack table row has ${cells.length} cell(s)`);

            cells.forEach((cell, index) => {
                // the first cell is the row heading and carries no label
                if (index === 0) {
                    assert.ok(!/\bdata-label=/.test(cell), `${rel}: the first cell of an ee-table-stack row is the row heading and must carry no data-label`);
                    return;
                }
                const labelled = /\bdata-label="[^"]+"/.test(cell);
                const actions = /\bclass="[^"]*\bee-stack-actions\b/.test(cell);
                assert.ok(
                    labelled || actions,
                    `${rel}: cell ${index + 1} of an ee-table-stack row needs either data-label="<column name>" or ee-stack-actions - ${cell}`
                );
                assert.ok(!(labelled && actions), `${rel}: cell ${index + 1} is the actions cell, so it must not also carry a data-label`);
            });
        }
    }

    assert.ok(tables > 10, `expected the stacked list tables to be found, saw ${tables}`);
    t.diagnostic(`checked ${tables} ee-table-stack tables`);
});
