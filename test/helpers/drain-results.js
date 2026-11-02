'use strict';

// Preloaded into every test file's process by test/run-tests.js (DRAIN_RESULTS_FLAGS) so that the
// file's results all reach the runner, the "lost results" of .claude/rules/testing.md, which has the
// measurements. Under --test-force-exit Node ends a file's process as soon as its reporter stream has
// unpiped from stdout, and results the reporter had not written out by then were lost. A root after()
// hook holds the root back until the reporter has caught up: it yields the event loop until stdout
// has had nothing pending for QUIET_TURNS turns in a row, then waits for it to flush. It counts turns,
// not time, because a loaded machine gives the process less time and the reporter's own callbacks
// are what has to run first.
//
// stdout is deliberately left non-blocking: blocking it lost results in CI where this wait did not,
// and a blocking write to a full pipe freezes the file's event loop, --test-timeout included.

// Consecutive turns with nothing pending on stdout before the reporter counts as caught up
const QUIET_TURNS = 20;

// Only in a file's own process, which node --test marks with NODE_TEST_CONTEXT: --require loads this
// into the runner process too, where a root hook turns the runner into a test of its own and its
// reporter stops attributing the files' events (the whole tier stalled)
if (process.env.NODE_TEST_CONTEXT) {
    const { after } = require('node:test');
    after(
        () =>
            new Promise(resolve => {
                let quiet = 0;
                const turn = () => {
                    if (process.stdout.writableLength) {
                        // backed up: wait for the pipe instead of spinning, then count again
                        quiet = 0;
                        process.stdout.once('drain', turn);
                        return;
                    }
                    if (++quiet >= QUIET_TURNS) {
                        process.stdout.write('', () => resolve());
                        return;
                    }
                    setImmediate(turn);
                };
                setImmediate(turn);
            })
    );
}
