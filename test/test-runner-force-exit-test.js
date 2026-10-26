'use strict';

// The unit tier hangs without --test-force-exit, and the way it hangs is invisible.
//
// Requiring the lib/db chain opens a Redis client and a BullMQ connection that nothing closes, so a
// file whose tests have all passed keeps its process alive; `node --test` waits for every child, so
// one such file stalls the entire tier. Most files work around it themselves through
// test/helpers/redis-teardown.js, but that only covers the files that remember to, and it covered
// nothing when a file put its teardown inside a test that then skipped -
// test/account-revoke-on-delete-test.js skips when Gmail credentials are absent, which is what every
// dependabot pull request looks like (`${{ secrets.X }}` expands to an empty string for a run with no
// access to them), and the unit tier burned its ten-minute job timeout instead of skipping one suite.
//
// Nothing about that failure looks like a failure: the tests pass, no assertion fires, the per-test
// --test-timeout cannot fire because no test is running, and the job is killed with no summary. So
// this asserts the flag rather than trying to police the pattern in ~200 test files, because the flag
// is what makes the whole class impossible - the misplaced teardown and the entirely missing one, in
// both tiers, in files nobody has written yet.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const pathlib = require('path');
const { spawn } = require('child_process');
const { once } = require('events');

const { EXIT_SAFE_V8_FLAGS } = require('./run-tests');

const RUNNER = pathlib.join(__dirname, 'run-tests.js');
const FLAG = '--test-force-exit';

test('the test runner forces the process to exit', async t => {
    const runner = fs.readFileSync(RUNNER, 'utf8');

    await t.test(`spawns node --test with ${FLAG}`, () => {
        // Matched inside the spawn argument list rather than anywhere in the file, so the flag being
        // mentioned in a comment cannot satisfy this. Anchored on the leading '--test' because
        // run-tests.js also spawns process.execPath to boot the server for the integration tier.
        const spawnCall = runner.match(/spawn\(\s*process\.execPath,\s*\['--test'([^\]]*)\]/);

        assert.ok(spawnCall, "could not find the `spawn(process.execPath, ['--test', ...])` call that runs the tests in test/run-tests.js");
        assert.ok(
            spawnCall[1].includes(`'${FLAG}'`),
            `test/run-tests.js must pass ${FLAG} to node --test. Without it, one test file that leaves a ` +
                `Redis handle open stalls the whole tier until the CI job times out, with every test reported as passing.`
        );
    });

    await t.test('both tiers go through that one spawn', () => {
        // The flag is passed once, so it only covers both tiers while there is exactly one place that
        // starts the runner. A second spawn would silently opt its tier out.
        const spawnCount = [...runner.matchAll(/spawn\(\s*process\.execPath,\s*\['--test'/g)].length;

        assert.strictEqual(spawnCount, 1, `expected exactly one node --test spawn in test/run-tests.js, found ${spawnCount} - each one needs ${FLAG}`);
    });
});

// What --test-force-exit's process.exit() can deadlock on in Node 24 (see EXIT_SAFE_V8_FLAGS in
// test/run-tests.js). The hang needs a background compile to coincide with the exit, so no test can
// make it happen on demand; what can be pinned is that the flags are passed and reach the process
// of every test file, which is the one that exits
test('the test runner turns off the background compiles an exit can deadlock on', async t => {
    await t.test('the flags are part of the node --test spawn', () => {
        const spawnCall = fs.readFileSync(RUNNER, 'utf8').match(/spawn\(\s*process\.execPath,\s*\['--test'([^\]]*)\]/);
        assert.ok(spawnCall && spawnCall[1].includes('...EXIT_SAFE_V8_FLAGS'), 'test/run-tests.js must pass EXIT_SAFE_V8_FLAGS to node --test');
        assert.deepStrictEqual(EXIT_SAFE_V8_FLAGS, ['--no-concurrent-recompilation', '--no-concurrent-sparkplug']);
    });

    await t.test('node --test hands them on to each test file', async t => {
        const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-v8-flags-'));
        t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
        const file = pathlib.join(dir, 'flags-test.js');
        fs.writeFileSync(
            file,
            `require('node:test')('flags', () => { for (const flag of ${JSON.stringify(EXIT_SAFE_V8_FLAGS)}) if (!process.execArgv.includes(flag)) throw new Error('missing ' + flag); });\n`
        );

        const env = { ...process.env };
        // a nested run of its own, see test/test-runner-stall-watchdog-test.js
        delete env.NODE_TEST_CONTEXT;
        delete env.NODE_TEST_WORKER_ID;
        const child = spawn(process.execPath, ['--test', '--test-force-exit', ...EXIT_SAFE_V8_FLAGS, file], { stdio: 'ignore', env });
        const [code] = await once(child, 'exit');
        assert.strictEqual(code, 0, 'a test file ran without the flags');
    });
});
