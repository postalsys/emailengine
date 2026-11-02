'use strict';

// Preloaded by test/run-tests.js (DRAIN_RESULTS_FLAGS) into the runner and every test file's main
// thread, so that every result reaches the runner: the "lost results" of .claude/rules/testing.md,
// which has the measurements. Under --test-force-exit Node calls process.exit() as soon as its
// reporter stream has unpiped from stdout, which only means everything was handed to stdout.write():
// with the reader slow, the pipe fills, the rest waits in the process's own write queue, and the exit
// discarded it. The exit therefore waits for that queue to empty first.

const { isMainThread } = require('node:worker_threads');

// How long an exit waits for stdout before ending the process anyway: a reader that is alive but has
// stopped reading must not keep a process, the stall watchdog's own exit included, from ending
const FLUSH_TIMEOUT = 10 * 1000;

// Not in a worker thread, where process.exit() ends only the thread and stdout is not the process's
if (isMainThread) {
    const exit = process.exit;
    process.exit = function (code) {
        if (!process.stdout.writableLength) {
            return exit.call(process, code);
        }
        const timer = setTimeout(() => exit.call(process, code), FLUSH_TIMEOUT);
        // a write's callback runs once everything queued before it is written, or the pipe failed
        process.stdout.write('', () => {
            clearTimeout(timer);
            exit.call(process, code);
        });
    };
}
