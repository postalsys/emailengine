'use strict';

// Preloaded into every test file's process by test/run-tests.js (DRAIN_RESULTS_FLAGS). Under
// --test-force-exit a file's process exits as soon as its last test ends, and whatever results its
// reporter had not written out yet went with it, which is the "lost results" of
// .claude/rules/testing.md. A root after() hook keeps the file alive until its reporter has caught
// up: it yields the event loop until stdout has had nothing pending for QUIET_TURNS turns in a row,
// then waits for stdout to flush.
//
// Measured with a file of 600 results, 16 copies running at once: with no hook 11 of 80 runs arrived
// short (down to 555), a flush alone did no better, a flush after a fixed 100 ms still lost results in
// 11 of 80, and this lost none in 80. It counts event loop turns, not time, because a loaded machine
// gives the process less of it: the reporter's own callbacks are what has to run first. The
// lost-results re-run in test/run-tests.js stays as the safety net.

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
