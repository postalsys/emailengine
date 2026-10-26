'use strict';

// A test file must not end its own process under the runner.
//
// Most unit test files load lib/db, whose connections keep the process alive, and used to end it
// with `setTimeout(() => process.exit(), 1000)` after their tests. Under test/run-tests.js that exit
// races the file's results on their way to the runner: Node's own --test-force-exit waits for them
// to drain, an exit of our own does not, and the results it cuts off are just not counted - the run
// still reports every test as passing. Measured with two files of 20000 tests each, such an exit
// left 34194 to 35996 of the 40000 results counted, and armed in a suite's own after-hook it can end
// the process while later suites of the file are still running. test/helpers/exit-standalone.js
// only exits when no runner will.

const test = require('node:test');
const assert = require('node:assert').strict;
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const pathlib = require('path');

const { listFiles } = require('./helpers/list-files');

const TEST_DIR = __dirname;
const EXIT_HELPER = pathlib.join(TEST_DIR, 'helpers', 'exit-standalone.js');

// The files that may end a process: the runner and its helpers, which run outside any test file's
// process, and this file and the helper itself
const MAY_EXIT = new Set(
    [
        'run-tests.js',
        'helpers/exit-standalone.js',
        'helpers/stall-reporter.js',
        'helpers/wait-for-server.js',
        'helpers/flush-redis.js',
        'test-runner-exit-test.js'
    ].map(file => pathlib.join(TEST_DIR, file))
);
// Any spelling of ending the process: process.exit(...), a reference to process.exit passed on, or
// a signal to its own pid. Comment lines are left out, they only explain
const ENDS_PROCESS = /process\.exit\b|process\.kill\(\s*process\.pid/;

test('no test file ends its own process outside test/helpers/exit-standalone.js', () => {
    const offenders = listFiles(TEST_DIR, '.js')
        .filter(file => !MAY_EXIT.has(file))
        .filter(file =>
            fs
                .readFileSync(file, 'utf8')
                .split('\n')
                .some(line => !/^\s*(\/\/|\*)/.test(line) && ENDS_PROCESS.test(line.replace(/'[^']*'|"[^"]*"/g, "''")))
        );
    assert.deepStrictEqual(
        offenders.map(file => pathlib.relative(TEST_DIR, file)),
        [],
        'use exitWhenStandalone() from test/helpers/exit-standalone.js instead'
    );
});

test('the runner hands --test-force-exit to each test file, which is what exitWhenStandalone() reads', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-exit-argv-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const files = ['a-test.js', 'b-test.js'].map(name => pathlib.join(dir, name));
    for (const file of files) {
        fs.writeFileSync(file, `require('node:test')('argv', () => { if (!process.execArgv.includes('--test-force-exit')) throw new Error('no flag'); });\n`);
    }
    const { code } = await runFiles(files);
    assert.strictEqual(code, 0, 'a test file ran without --test-force-exit');
});

const TESTS_PER_FILE = 20000;

// Many results, an open handle like lib/db's connections, and the teardown every such file uses
const fixture = `'use strict';
const { test, after } = require('node:test');
const exitWhenStandalone = require(${JSON.stringify(EXIT_HELPER)});
after(() => exitWhenStandalone());
setInterval(() => {}, 1 << 30);
for (let i = 0; i < ${TESTS_PER_FILE}; i++) {
    test('a test whose result has to reach the runner ' + i, () => {});
}
`;

function runFiles(files) {
    return new Promise((resolve, reject) => {
        const env = { ...process.env };
        // a nested run of its own, see test/test-runner-stall-watchdog-test.js
        delete env.NODE_TEST_CONTEXT;
        delete env.NODE_TEST_WORKER_ID;
        const child = spawn(process.execPath, ['--test', '--test-force-exit', '--test-reporter=tap', ...files], { stdio: ['ignore', 'pipe', 'pipe'], env });
        let stdout = '';
        child.stdout.on('data', chunk => (stdout += chunk));
        // below the unit tier's stall timeout, and reported as what it is
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
        }, 45000);
        child.on('error', reject);
        // 'close', not 'exit': 'exit' can fire while the child's stdout is still being read, and
        // the run summary is the last thing on it
        child.on('close', code => {
            clearTimeout(timer);
            if (timedOut) {
                return reject(new Error('the nested run did not finish within 45 s'));
            }
            resolve({ code, counted: Number((stdout.match(/^# tests (\d+)$/m) || [])[1]) });
        });
    });
}

test('the results of every file reach the runner, also when it drains them slowly', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-exit-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const files = ['first-test.js', 'second-test.js'].map(name => pathlib.join(dir, name));
    files.forEach(file => fs.writeFileSync(file, fixture));

    const { code, counted } = await runFiles(files);
    assert.strictEqual(code, 0);
    // Node's own forced exit can still drop a few dozen of 40000 on its own; an exit of ours a
    // second after the tests dropped about one in ten
    assert.ok(counted >= 2 * TESTS_PER_FILE * 0.99, `${counted} of ${2 * TESTS_PER_FILE} results reached the runner`);
});
