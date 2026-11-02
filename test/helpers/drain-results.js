'use strict';

// Preloaded into every test file's process by test/run-tests.js (DRAIN_RESULTS_FLAGS) so that the
// file's results all reach the runner, the "lost results" of .claude/rules/testing.md.
//
// Under --test-force-exit, Node ends a file's process once its reporter stream has unpiped from
// stdout (lib/internal/test_runner/test.js, the root's forceExit branch), which only means the
// results were handed to stdout.write(). Two things keep what is left from being discarded:
//   - stdout is made blocking, so a write is in the kernel before it returns. A stdout pipe is
//     non-blocking on macOS, and with the runner reading slowly the rest waited in libuv's queue
//   - a root after() hook yields the event loop until stdout has had nothing pending for
//     QUIET_TURNS turns in a row, so the reporter has caught up before the exit starts. Blocking
//     alone still lost 150 of 4800 results once on a loaded Linux CI runner; the wait alone passed
//     there
//
// Measured with a file of 600 results, 16 copies at once on macOS: as it was, 20 runs of 48 arrived
// short (down to 555); with the wait, none of 80; blocking, none of 80. In a Linux container with
// 2 CPUs: as it was, 37 of 40 short; with either or both, none. A result lost anyway fails the run,
// see test/helpers/stall-reporter.js.

// Consecutive turns with nothing pending on stdout before the reporter counts as caught up
const QUIET_TURNS = 20;

// Only in a file's own process, which node --test marks with NODE_TEST_CONTEXT: --require loads this
// into the runner process too, which reads every file's output and must not block on its own, and
// where a root hook turned the runner into a test of its own and stalled the tier
if (process.env.NODE_TEST_CONTEXT) {
    const handle = process.stdout._handle;
    if (handle && typeof handle.setBlocking === 'function') {
        handle.setBlocking(true);
    }

    const { after } = require('node:test');
    after(
        () =>
            new Promise(resolve => {
                let quiet = 0;
                const turn = () => {
                    quiet = process.stdout.writableLength ? 0 : quiet + 1;
                    if (quiet >= QUIET_TURNS) {
                        process.stdout.write('', () => resolve());
                        return;
                    }
                    setImmediate(turn);
                };
                setImmediate(turn);
            })
    );
}
