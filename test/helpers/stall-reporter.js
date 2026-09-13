'use strict';

// The `node --test` reporter the runner uses: the stock spec reporter, plus a watchdog that notices
// when a run has stopped making progress and says which files it was still waiting for.
//
// The per-test `--test-timeout` and `--test-force-exit` between them cover almost everything, and
// each covers a case the other cannot:
//
//   - a test that hangs, and a `before`/`after` hook that never resolves, are both cut short by
//     --test-timeout (verified on Node 24: the hook is reported as the test timing out)
//   - a file whose tests all finished but whose process stays alive on an open Redis or BullMQ
//     handle is ended by --test-force-exit, which acts once the run itself has finished
//
// What neither can reach is a test file whose EVENT LOOP IS BLOCKED - a synchronous loop, or a
// thread parked in Atomics.wait. --test-timeout is a timer inside that same process, so a blocked
// loop is exactly the state in which it cannot fire, and the run never finishes so --test-force-exit
// never gets its turn. `node --test` then waits on that child forever. That is not hypothetical: it
// killed the unit tier on master at 7e6808be, which already had both flags, and the job was killed
// at its ten minute limit having printed no summary and naming no file.
//
// The runner's own event loop is healthy in that state, which is why the watchdog works from inside
// a reporter. It watches for a stretch of complete silence across every file running in parallel,
// then prints the files that never reported completion and ends the run non-zero.
//
// Deliberately silence-based rather than a per-file deadline: files run in parallel and a file is
// only slow in the company of others, so "nothing at all happened for N seconds" is the signal that
// does not need to know how long any individual file should take.
//
// It WRAPS the spec reporter rather than running beside it as a second `--test-reporter`, and that
// is load-bearing: with --test-force-exit, two reporters truncate the run summary. Measured on this
// suite with a second reporter that did nothing but `yield ''`, the tier reported 3410 / 3442 / 3452
// tests across five otherwise identical runs, all with `fail 0` - the process exits as soon as the
// run finishes and the reporters have not finished draining, so results go missing silently. Since a
// dropped result could just as easily be a failing one, this must stay a single reporter.

const { spec } = require('node:test/reporters');
const { Transform } = require('node:stream');
const fs = require('node:fs');

// How long to let queued spec output reach the pipe before exiting on a stall. Generous because it
// only ever runs once, on a run that has already been silent for a minute.
const STDOUT_FLUSH_GRACE_MS = 500;

// The files the run was given, as run-tests.js listed them. The file-level `test:complete` event
// carries the same relative path as its `name`, which is what lets outstanding files be named rather
// than merely counted.
function expectedFiles() {
    try {
        const parsed = JSON.parse(process.env.EE_TEST_FILES || '[]');
        return Array.isArray(parsed) ? parsed : [];
    } catch (err) {
        return [];
    }
}

// Composes the spec reporter rather than extending it. `new spec()` returns its own object, so a
// subclass's `super()` call replaces `this` with that object and every subclass method - including
// the _transform override this needs - is silently dropped. The failure is quiet: the reporter still
// renders perfectly, it just never tracks anything. So this is a Transform of its own that forwards
// each event to an internal spec instance and republishes whatever that writes.
class StallAwareSpecReporter extends Transform {
    constructor(options) {
        super({ ...options, writableObjectMode: true });

        this.inner = new spec();
        this.inner.on('data', chunk => this.push(chunk));

        this.outstanding = new Set(expectedFiles());
        this.lastEvent = Date.now();
        this.stallMs = Number(process.env.EE_TEST_STALL_TIMEOUT) || 0;
        this.watchdog = null;

        if (this.stallMs > 0) {
            this.watchdog = setInterval(() => this.checkForStall(), 1000);
            // The runner is kept alive by the child it is waiting on, so this timer does not need to
            // hold the loop open - and must not, or it would delay the exit of a clean run.
            this.watchdog.unref();
        }
    }

    checkForStall() {
        if (Date.now() - this.lastEvent < this.stallMs) {
            return;
        }

        clearInterval(this.watchdog);

        // Written with writeSync, not console.error: the report has to survive the process.exit()
        // below, and it goes to stderr so it cannot be confused with the spec output on stdout.
        const waiting = [...this.outstanding];
        const detail = waiting.length ? waiting.map(file => `  - ${file}`).join('\n') : '  (none - the run stalled after every file had reported)';

        fs.writeSync(
            2,
            `\nTest run stalled: no test events for ${Math.round(this.stallMs / 1000)}s.\n` +
                `Still waiting on ${waiting.length} file(s):\n${detail}\n\n` +
                `A file gets here by blocking its event loop, which is the one state --test-timeout\n` +
                `cannot interrupt and --test-force-exit never gets to see. Run the file above on its\n` +
                `own to reproduce. Its process may outlive this one; it is not reaped from here.\n`
        );

        // Non-zero so the tier fails, rather than the run being killed later by a CI job timeout with
        // nothing printed at all.
        //
        // Not immediately, though: process.stdout is asynchronous when it is a pipe, and
        // process.exit() discards whatever is still buffered there. `node --test` holds spec output
        // until the run reaches that file in order, so on a stall there is often nothing queued at
        // all - but where there is, this is what lets it land.
        setTimeout(() => process.exit(1), STDOUT_FLUSH_GRACE_MS);
    }

    _transform(event, encoding, callback) {
        this.lastEvent = Date.now();

        // The file-level result: `node --test` reports each file as a top-level test whose name is
        // the path it was given on the command line.
        if (event && event.type === 'test:complete' && event.data && event.data.nesting === 0) {
            this.outstanding.delete(event.data.name);
        }

        this.inner.write(event, callback);
    }

    _flush(callback) {
        if (this.watchdog) {
            clearInterval(this.watchdog);
        }
        this.inner.end();
        this.inner.on('end', callback);
    }
}

module.exports = StallAwareSpecReporter;
