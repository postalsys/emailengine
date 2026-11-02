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

const { EXIT_SAFE_V8_FLAGS, DRAIN_RESULTS_FLAGS } = require('./run-tests');

const RUNNER = pathlib.join(__dirname, 'run-tests.js');
const FLAG = '--test-force-exit';
// The argument list of the spawn that runs the tests. Anchored on the leading '--test' because
// run-tests.js also spawns process.execPath to boot the server for the integration tier
const SPAWN_CALL = /spawn\(\s*process\.execPath,\s*\['--test'([^\]]*)\]/;

test('the test runner forces the process to exit', async t => {
    const runner = fs.readFileSync(RUNNER, 'utf8');

    await t.test(`spawns node --test with ${FLAG}`, () => {
        // Matched inside the spawn argument list rather than anywhere in the file, so the flag being
        // mentioned in a comment cannot satisfy this
        const spawnCall = runner.match(SPAWN_CALL);

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
        const spawnCall = fs.readFileSync(RUNNER, 'utf8').match(SPAWN_CALL);
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

// What --test-force-exit discarded when it ended a process: results still in its stdout write queue
// (test/helpers/drain-results.js, measurements in .claude/rules/testing.md)
test('every test file writes its results out before the forced exit', async t => {
    await t.test('the drain is part of the node --test spawn', () => {
        const spawnCall = fs.readFileSync(RUNNER, 'utf8').match(SPAWN_CALL);
        assert.ok(spawnCall && spawnCall[1].includes('...DRAIN_RESULTS_FLAGS'), 'test/run-tests.js must pass DRAIN_RESULTS_FLAGS to node --test');
        assert.ok(fs.existsSync(DRAIN_RESULTS_FLAGS[1]));
    });

    await t.test('files of many results running at once report all of them', async t => {
        const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-drain-'));
        t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
        // Run together, as the tier runs them: the loss came with a runner too busy to keep reading
        const files = Array.from({ length: 8 }, (_, i) => pathlib.join(dir, `many-${i}-test.js`));
        for (const file of files) {
            fs.writeFileSync(
                file,
                `const test = require('node:test');\nfor (let i = 0; i < 200; i++) {\n    test('t' + i, async t => {\n        await t.test('a', () => {});\n        await t.test('b', () => {});\n    });\n}\n`
            );
        }
        const env = { ...process.env };
        // a nested run of its own, see test/test-runner-stall-watchdog-test.js
        delete env.NODE_TEST_CONTEXT;
        delete env.NODE_TEST_WORKER_ID;
        const child = spawn(process.execPath, ['--test', '--test-force-exit', ...DRAIN_RESULTS_FLAGS, '--test-reporter=tap', ...files], {
            stdio: ['ignore', 'pipe', 'ignore'],
            env
        });
        let stdout = '';
        child.stdout.on('data', chunk => (stdout += chunk));
        // A nested run that stops is reported as that, not as this test running out of time
        const timer = setTimeout(() => child.kill('SIGKILL'), 45000);
        // 'close', not 'exit', so the whole of stdout has been read
        const [code, signal] = await once(child, 'close');
        clearTimeout(timer);
        assert.equal(signal, null, 'the nested run finished within 45 s');
        assert.equal(code, 0);
        assert.equal((stdout.match(/^\s*(not )?ok \d+ /gm) || []).length, files.length * 600);
    });
});

// The wrapper itself, in a process of its own: 4MB is far more than any pipe holds, so most of it is
// still in the write queue when process.exit() runs
test('process.exit() under the drain helper', async t => {
    const script = "process.stdout.write('x'.repeat(4 * 1024 * 1024)); process.exit(3);";

    await t.test('waits for queued stdout and keeps the exit code', async () => {
        const child = spawn(process.execPath, [...DRAIN_RESULTS_FLAGS, '-e', script], { stdio: ['ignore', 'pipe', 'ignore'] });
        let bytes = 0;
        child.stdout.on('data', chunk => (bytes += chunk.length));
        const [code] = await once(child, 'close');
        assert.equal(code, 3);
        assert.equal(bytes, 4 * 1024 * 1024);
    });

    await t.test('still ends the process when the reader stops reading', async () => {
        const child = spawn(process.execPath, [...DRAIN_RESULTS_FLAGS, '-e', script], { stdio: ['ignore', 'pipe', 'ignore'] });
        // never read, so the pipe stays full and the queued write never completes
        child.stdout.pause();
        const timer = setTimeout(() => child.kill('SIGKILL'), 30000);
        const [code, signal] = await once(child, 'exit');
        clearTimeout(timer);
        assert.equal(signal, null, 'the process ended on its own within 30 s');
        assert.equal(code, 3);
        child.stdout.destroy();
    });
});
