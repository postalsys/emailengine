'use strict';

// Size ratchet (tripwire) for the routes-ui.js god file.
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
const BUDGET = 1870;

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
