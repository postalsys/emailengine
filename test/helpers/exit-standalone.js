'use strict';

// Ends a test file's process that requiring lib/db left alive, but only when nothing else will.
//
// test/run-tests.js runs every tier with --test-force-exit, which node:test passes on to each test
// file's process, and Node's own forced exit waits for the file's results to reach the runner
// before it ends the process. An exit of our own a second after the last test does not wait: when
// the runner drains a file's results slowly (a loaded machine), it cuts them off, and the results
// that never arrived are simply not counted - the run still passes. Measured with two files of
// 20000 tests each: 34194 to 35996 of the 40000 results counted with such an exit, 40000 without
// it (test/test-runner-exit-test.js keeps that so). A bare `node --test <file>` has no forced exit,
// so there the delayed exit is what keeps the file from hanging on its open connections.

const FORCE_EXITED = process.execArgv.includes('--test-force-exit');

/**
 * @param {number} [delay] - How long to let the file's own teardown finish first, in ms
 */
module.exports = function exitWhenStandalone(delay = 1000) {
    if (!FORCE_EXITED) {
        setTimeout(() => process.exit(), delay).unref();
    }
};
