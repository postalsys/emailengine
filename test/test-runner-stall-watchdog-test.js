'use strict';

// The unit tier died on master at 7e6808be with no summary, no failing assertion and no file named:
// the job was killed at its ten minute limit, roughly nine minutes after the last line of output.
// Both of the runner's existing guards were already in place and neither applies to what happened.
//
// --test-timeout cuts short a test that hangs, and a `before`/`after` hook that never resolves with
// it. --test-force-exit ends a run whose tests have all finished but whose file processes stay alive
// on an open Redis or BullMQ handle. What is left in between is a test file that BLOCKS ITS EVENT
// LOOP: the per-test timeout is a timer inside that same process, so a blocked loop is precisely the
// state in which it cannot fire, and because the run never finishes, --test-force-exit never gets a
// turn either. `node --test` waits on the child for as long as CI allows.
//
// So the runner carries a third guard, test/helpers/stall-reporter.js, which rides along as a second
// reporter: a reporter runs inside the runner process, whose own event loop is healthy while a
// child's is not, and it is the only thing there that knows which files have reported. This asserts
// the behaviour that matters - that a blocked file is given up on, and that the report names the file
// that blocked rather than the ones that merely finished last.

const test = require('node:test');
const assert = require('node:assert').strict;
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const pathlib = require('path');

const PROJECT_ROOT = pathlib.join(__dirname, '..');
const REPORTER = pathlib.join(__dirname, 'helpers', 'stall-reporter.js');

// Parks the thread instead of spinning on the CPU, so the fixture reproduces a blocked event loop
// without burning a core, and releases itself so nothing is left running after the test.
const BLOCKED_FIXTURE = `'use strict';
const { test } = require('node:test');
test('blocks the event loop', () => {
    const shared = new Int32Array(new SharedArrayBuffer(4));
    Atomics.wait(shared, 0, 0, 15000);
});
`;

const HEALTHY_FIXTURE = `'use strict';
const { test } = require('node:test');
test('finishes immediately', () => {});
`;

// Runs node --test over the two fixtures with the watchdog attached, under a hard deadline so a
// regression fails this test instead of hanging the tier it is trying to protect.
function runWithWatchdog(files, { stallTimeout, deadline }) {
    return new Promise(resolve => {
        const child = spawn(
            process.execPath,
            [
                '--test',
                '--test-force-exit',
                // Deliberately shorter than the fixture's block: this asserts that the watchdog is
                // what ends the run, not the per-test timeout, which cannot fire on a blocked loop.
                '--test-timeout=4000',
                `--test-reporter=${REPORTER}`,
                '--test-reporter-destination=stdout',
                ...files
            ],
            {
                cwd: PROJECT_ROOT,
                stdio: ['ignore', 'pipe', 'pipe'],
                env: (() => {
                    // This file is itself running under `node --test`, and Node refuses to start a
                    // nested runner ("run() is being called recursively") on the strength of these
                    // two variables alone, printing a warning and running nothing. Clearing them is
                    // what makes the child a real, independent run.
                    const env = { ...process.env, NODE_ENV: 'test', EE_TEST_FILES: JSON.stringify(files), EE_TEST_STALL_TIMEOUT: String(stallTimeout) };
                    delete env.NODE_TEST_CONTEXT;
                    delete env.NODE_TEST_WORKER_ID;
                    return env;
                })()
            }
        );

        let stdout = '';
        let stderr = '';
        child.stdout.on('data', chunk => (stdout += chunk));
        child.stderr.on('data', chunk => (stderr += chunk));

        const timer = setTimeout(() => {
            child.kill('SIGKILL');
            resolve({ timedOut: true, stdout, stderr, code: null });
        }, deadline);

        child.on('exit', code => {
            clearTimeout(timer);
            resolve({ timedOut: false, stdout, stderr, code });
        });
    });
}

test('the test runner gives up on a file that blocks its event loop', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-stall-'));
    const blocked = pathlib.join(dir, 'blocked-test.js');
    const healthy = pathlib.join(dir, 'healthy-test.js');
    fs.writeFileSync(blocked, BLOCKED_FIXTURE);
    fs.writeFileSync(healthy, HEALTHY_FIXTURE);

    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const result = await runWithWatchdog([healthy, blocked], { stallTimeout: 2000, deadline: 12000 });

    await t.test('the run ends instead of waiting for the blocked file', () => {
        assert.ok(!result.timedOut, 'the watchdog did not end the run - node --test was still waiting when the deadline expired');
    });

    await t.test('it fails the tier rather than passing quietly', () => {
        // The whole point is that this reaches CI as a failure. A stalled run that exits 0 would be
        // worse than the hang, because nothing would look wrong at all.
        assert.strictEqual(result.code, 1, `expected exit code 1 from a stalled run, got ${result.code}`);
    });

    await t.test('the report names the file that blocked', () => {
        assert.match(result.stderr, /Test run stalled/, 'the stall report was not printed to stderr');
        assert.ok(result.stderr.includes(blocked), `the stall report did not name ${blocked}:\n${result.stderr}`);
    });

    await t.test('it does not accuse a file that finished', () => {
        // The last file to print before a stall is usually an innocent one that simply finished last,
        // which is what made the original incident so hard to read.
        assert.ok(!result.stderr.includes(healthy), `the stall report named a file that had already completed:\n${result.stderr}`);
    });
});

test('the watchdog leaves an ordinary run alone', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-stall-ok-'));
    const healthy = pathlib.join(dir, 'healthy-test.js');
    fs.writeFileSync(healthy, HEALTHY_FIXTURE);

    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    // A generous budget on purpose. Nothing here stalls, so the only thing a short one could do is
    // fire spuriously: this file runs inside the parallel unit tier, where a nested runner competing
    // for the machine can easily be quiet for a couple of seconds before its first event. A tight
    // budget here failed both assertions below exactly once in a tier run, which is the kind of flake
    // a watchdog must not introduce while trying to catch one.
    const result = await runWithWatchdog([healthy], { stallTimeout: 30000, deadline: 20000 });

    await t.test('it still reports the tests', () => {
        // The watchdog extends the spec reporter rather than running beside it, so the ordinary
        // output is its responsibility now: a reporter that reported nothing would be worse than the
        // stall it exists to catch.
        assert.match(result.stdout, /finishes immediately/, `the spec output was lost:\n${result.stdout}`);
        assert.match(result.stdout, /pass 1/, `the run summary was lost:\n${result.stdout}`);
    });

    await t.test('it passes and says nothing', () => {
        assert.strictEqual(result.code, 0, `a healthy run should exit 0, got ${result.code}`);
        assert.doesNotMatch(result.stderr, /Test run stalled/, `the watchdog fired on a healthy run:\n${result.stderr}`);
    });
});

test('the runner wires the stall watchdog in', async t => {
    const runner = fs.readFileSync(pathlib.join(__dirname, 'run-tests.js'), 'utf8');

    await t.test('it attaches the reporter', () => {
        // The helper on its own does nothing: it only ever runs because the runner passes it as a
        // reporter, so that wiring is the thing worth pinning.
        assert.match(
            runner,
            /--test-reporter=\$\{path\.join\(__dirname, 'helpers', 'stall-reporter\.js'\)\}/,
            'test/run-tests.js no longer attaches test/helpers/stall-reporter.js as a reporter'
        );
    });

    await t.test('it stays the only reporter', () => {
        // With --test-force-exit, a second reporter truncates the run summary: the process exits
        // before the reporters have drained and results go missing while `fail 0` is still reported.
        // Measured at 3410 / 3442 / 3452 tests across five identical runs of this suite. A dropped
        // result can be a failing one, so this is a correctness guard, not a tidiness one.
        const reporters = [...runner.matchAll(/--test-reporter=/g)].length;

        assert.strictEqual(
            reporters,
            1,
            `test/run-tests.js must pass exactly one --test-reporter, found ${reporters}. ` +
                `Extend test/helpers/stall-reporter.js instead of adding a second one - with --test-force-exit, two reporters silently drop results from the summary.`
        );
    });

    await t.test('every tier sets a stall budget', () => {
        // A tier with no budget silently opts out: the reporter treats 0 as "no watchdog".
        const tiers = [...runner.matchAll(/^\s{4}(\w+): \{$/gm)].map(match => match[1]);
        const budgets = [...runner.matchAll(/stallTimeout:/g)].length;

        assert.ok(tiers.length >= 2, `expected to find the tier definitions in test/run-tests.js, found ${tiers.join(', ') || 'none'}`);
        assert.strictEqual(budgets, tiers.length, `every tier in test/run-tests.js needs a stallTimeout - found ${tiers.length} tiers but ${budgets} budgets`);
    });
});
