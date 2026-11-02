'use strict';

// Preloaded into every test file's process by test/run-tests.js (DRAIN_RESULTS_FLAGS) so that the
// file's results all reach the runner, the "lost results" of .claude/rules/testing.md.
//
// Under --test-force-exit, Node ends a file's process once its reporter stream has unpiped from
// stdout, which only means the results were handed to stdout.write(). A stdout pipe is non-blocking
// on Linux and macOS, so under load, with the runner reading slowly and the pipe buffer full, the
// rest waits in libuv's queue, and process.exit() discards it. Making stdout blocking puts every
// write into the kernel before it returns, so nothing is left queued to discard.
//
// Measured with a file of 600 results, 16 copies running at once: as it was, 20 runs of 48 arrived
// short (down to 555); with stdout blocking, none of 80. A result lost anyway fails the run, see
// test/helpers/stall-reporter.js.

// Only in a file's own process, which node --test marks with NODE_TEST_CONTEXT: --require loads this
// into the runner process too, which reads every file's output and must not block on its own
const handle = process.stdout._handle;
if (process.env.NODE_TEST_CONTEXT && handle && typeof handle.setBlocking === 'function') {
    handle.setBlocking(true);
}
