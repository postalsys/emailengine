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

// Per-module ratchet for lib/ui-routes/: each module is capped at its line count when the cap
// was set, so a module does not become the next god file one handler at a time (account-routes
// and admin-entities-routes are already past 2500 lines). Lower a cap when a module shrinks;
// raise one only as a reviewed decision. A new module needs an entry, which is the prompt to
// ask whether it should exist.
const MODULE_BUDGETS = {
    'account-routes.js': 2505,
    'admin-config-routes.js': 1553,
    'admin-entities-routes.js': 2548,
    // 1649 -> 1650 for the require of the shared formBoolean() schema helper
    'auth-routes.js': 1650,
    'dashboard-routes.js': 175,
    'document-store-routes.js': 806,
    'export-routes.js': 207,
    'internals-routes.js': 458,
    'mcp-consent-routes.js': 381,
    'network-config-routes.js': 437,
    'oauth-config-routes.js': 998,
    'reference-routes.js': 198,
    // 658 -> 661 when windowedPageLinks grew a shared pageLink() builder
    'route-helpers.js': 661,
    'settings-page.js': 117,
    'smtp-test-routes.js': 243,
    'suppression-list-routes.js': 310,
    'tls-config-routes.js': 628,
    'unsubscribe-routes.js': 261
};

test('every lib/ui-routes module stays within its size budget', () => {
    const dir = pathlib.join(__dirname, '..', 'lib', 'ui-routes');
    for (const file of fs.readdirSync(dir).filter(name => name.endsWith('.js'))) {
        assert.ok(file in MODULE_BUDGETS, `lib/ui-routes/${file} has no entry in MODULE_BUDGETS`);
        const lineCount = (fs.readFileSync(pathlib.join(dir, file), 'utf-8').match(/\n/g) || []).length;
        assert.ok(
            lineCount <= MODULE_BUDGETS[file],
            `lib/ui-routes/${file} has ${lineCount} lines, exceeding its budget of ${MODULE_BUDGETS[file]}. ` +
                `Move code into a focused module or a shared helper instead of growing this one.`
        );
    }
});
