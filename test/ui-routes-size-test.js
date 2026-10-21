'use strict';

// Size ratchets (tripwires) for the routes-ui.js god file and the lib/ui-routes modules.
//
// lib/routes-ui.js is being decomposed into focused modules under lib/ui-routes/. This
// test asserts the monolith never grows past BUDGET. The ratchet only moves DOWN: after
// each extraction batch lands, lower BUDGET to the file's new line count. That makes any
// future growth of the monolith a failing test, so the file cannot quietly regrow while
// the extraction is in progress (and stays capped afterwards).
//
// Pure filesystem read - no Redis, no server, exits cleanly on its own.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

// Lower this after every extraction batch to the new `wc -l lib/routes-ui.js`.
//
// Raised from 92 to 95 for lib/ui-routes/reference-routes.js, from 95 to 99 for
// lib/ui-routes/suppression-list-routes.js, and from 99 to 103 for
// lib/ui-routes/mcp-consent-routes.js: routes-ui.js is the single registration point
// for the extracted modules, so a NEW module costs it a require, a comment and a call.
// That is the pattern this ratchet exists to encourage, not the handler-code growth it
// exists to block.
//
// Lowered to 74 when lib/ui-routes/tls-config-routes.js took the ACME challenge route with
// it - the last handler body the monolith still carried.
const BUDGET = 74;

test('routes-ui.js stays within the size budget', () => {
    const filePath = pathlib.join(__dirname, '..', 'lib', 'routes-ui.js');
    // Count newlines to match `wc -l` so BUDGET maps directly to that command's output.
    const lineCount = (fs.readFileSync(filePath, 'utf-8').match(/\n/g) || []).length;

    assert.ok(
        lineCount <= BUDGET,
        `lib/routes-ui.js has ${lineCount} lines, exceeding the budget of ${BUDGET}. ` +
            `Extract routes into lib/ui-routes/ instead of growing the monolith. ` +
            `If a deliberate, reviewed increase is required, raise BUDGET in this test.`
    );
});

// Per-module ratchet for lib/ui-routes/: each module is capped at its size when the cap was set,
// so a module does not become the next god file one handler at a time. Lower a cap when a module
// shrinks; raise one only as a reviewed decision. A new module needs an entry, which is the prompt
// to ask whether it should exist.
//
// Size is counted in statements, not lines. The line caps moved with every change that made the
// code easier to read: a comment, a JSDoc block, or splitting one long function into named steps
// (the per-route registration functions cost each module dozens of lines of signatures and closing
// braces). A statement count is blind to all of that and grows with what the cap is about, the
// handler code. Route option objects and joi schemas are expressions, so a schema is not counted.
const MODULE_BUDGETS = {
    'account-routes.js': 630,
    'account-setup.js': 32,
    'admin-config-routes.js': 396,
    'admin-entities-routes.js': 574,
    'ai-options.js': 22,
    'auth-routes.js': 520,
    'connection-security-form.js': 11,
    'dashboard-routes.js': 37,
    'export-routes.js': 49,
    'form-lists.js': 8,
    'gmail-service-auth.js': 12,
    'imap-idle-field.js': 11,
    'internals-routes.js': 146,
    'mcp-consent-routes.js': 87,
    'network-config-routes.js': 121,
    'oauth-config-routes.js': 297,
    'oauth-form-context.js': 3,
    'outlook-subscription-view.js': 15,
    'overridable-fields.js': 16,
    'queue-routes.js': 95,
    'reference-routes.js': 49,
    'route-helpers.js': 162,
    'settings-page.js': 39,
    'sign-in-helpers.js': 16,
    'smtp-test-routes.js': 77,
    'special-use-paths.js': 5,
    'suppression-list-routes.js': 83,
    'tls-config-routes.js': 187,
    'unsubscribe-routes.js': 64
};

// Statements that carry no code of their own: a block is only braces, and a function or class
// declaration is the boundary of code whose statements are counted inside it
const UNCOUNTED = new Set(['BlockStatement', 'EmptyStatement', 'FunctionDeclaration', 'ClassDeclaration']);

function countStatements(source) {
    const ast = acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true });
    let count = 0;
    walk.full(ast, node => {
        if ((node.type.endsWith('Statement') || node.type.endsWith('Declaration')) && !UNCOUNTED.has(node.type)) {
            count++;
        }
    });
    return count;
}

test('statement counting ignores comments and function boundaries', () => {
    const inline = 'function a(x) { if (x) { return 1; } let y = x + 1; return y; }';
    const split =
        '// a comment\n/** JSDoc */\nfunction b(x) { return x + 1; }\nfunction a(x) {\n    if (x) {\n        return 1;\n    }\n    let y = b(x);\n    return y;\n}\n';
    assert.strictEqual(countStatements(inline), 4);
    // the extracted helper costs its one return statement, nothing for its lines
    assert.strictEqual(countStatements(split), 5);
});

test('every lib/ui-routes module stays within its size budget', () => {
    const dir = pathlib.join(__dirname, '..', 'lib', 'ui-routes');
    for (const file of fs.readdirSync(dir).filter(name => name.endsWith('.js'))) {
        assert.ok(file in MODULE_BUDGETS, `lib/ui-routes/${file} has no entry in MODULE_BUDGETS`);
        const statements = countStatements(fs.readFileSync(pathlib.join(dir, file), 'utf-8'));
        assert.ok(
            statements <= MODULE_BUDGETS[file],
            `lib/ui-routes/${file} has ${statements} statements, exceeding its budget of ${MODULE_BUDGETS[file]}. ` +
                `Move code into a focused module or a shared helper instead of growing this one.`
        );
    }
});
