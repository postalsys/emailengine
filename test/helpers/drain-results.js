'use strict';

// Preloaded into every test file's process by test/run-tests.js (DRAIN_RESULTS_FLAGS) so that the
// file's results all reach the runner, the "lost results" of .claude/rules/testing.md, which has the
// measurements. Under --test-force-exit Node calls process.exit() as soon as its reporter stream has
// unpiped from stdout, which only means every result was handed to stdout.write(): with the runner
// reading slowly the pipe fills, the rest waits in the process's own write queue, and the exit
// discarded it (up to 60KB of a 570KB file in a Linux container). The exit therefore waits for that
// queue to empty first. Waiting before the exit instead (a root after() hook) and a blocking stdout
// each passed locally and lost results in CI, because neither covers what is written after them.

const { isMainThread } = require('node:worker_threads');

// Only in a file's own process, which node --test marks with NODE_TEST_CONTEXT: --require loads this
// into the runner process too, and into a file's worker threads, whose stdout is not the file's
if (process.env.NODE_TEST_CONTEXT && isMainThread) {
    const exit = process.exit;
    process.exit = function (code) {
        if (!process.stdout.writableLength) {
            return exit.call(process, code);
        }
        // a write's callback runs once everything queued before it is written, or the pipe failed
        process.stdout.write('', () => exit.call(process, code));
    };
}
