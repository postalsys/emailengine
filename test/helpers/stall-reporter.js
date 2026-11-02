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
//
// It also guards against a result lost on its way from a file's process to the runner. Seen once, on
// 2026-11-02 in the unit tier on macOS: a suite of test/views-csp-guardrail-test.js printed a
// subtest's start and nothing more, 28 subtests and the suite's own result never arrived, the file's
// later tests reported as usual, and the run said `fail 0` with 29 tests fewer than the next run.
// Every test, skipped or todo ones included, reports `test:start` and then `test:pass` or `test:fail`
// (checked on Node 20, 22 and 24). So a test still open once every event of the run has arrived is a
// lost result. The decision is made at the end of the run, not when the file's own `test:complete`
// arrives: on Node 20.19.0 in CI that event came before the last suite's own start and pass events,
// which arrived a second later, and a check at that point reported two results as lost that the
// summary then counted. A lost result fails the run rather than count as passed. test/run-tests.js
// keeps it from happening (test/helpers/drain-results.js); this is what tells when it does anyway.

const { spec } = require('node:test/reporters');
const { Transform } = require('node:stream');
const fs = require('node:fs');
const pathlib = require('node:path');

// How long to let queued spec output reach the pipe before exiting on a stall. Generous because it
// only ever runs once, on a run that has already been silent for a minute.
const STDOUT_FLUSH_GRACE_MS = 500;

// One key per file however it was spelled: the runner reports a file by its real path, while the
// list the run was given can go through a symlink (macOS keeps its temp directory behind one)
const fileKeys = new Map();
function fileKey(file) {
    let key = fileKeys.get(file);
    if (!key) {
        const resolved = pathlib.resolve(file);
        try {
            key = fs.realpathSync(resolved);
        } catch (err) {
            key = resolved;
        }
        // a few hundred files per run, each resolved once instead of on every event
        fileKeys.set(file, key);
    }
    return key;
}

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
// renders perfectly, it just never tracks anything. So this is a Transform of its own that hands
// each event to an internal spec instance and republishes what that renders.
//
// It calls the instance's _transform and _flush directly, in step with its own, instead of writing
// to it as a stream and relaying its 'data' events. The relay adds a stream hop, and on Node 20 the
// --test-force-exit exit arrives before that hop drains: every run lost its summary (no pass or
// fail line, no failing-tests list) while the per-test lines still printed. Node 22 and 24 happened
// to drain in time. The spec reporter of every supported Node answers both through the callback,
// so the output is identical.
class StallAwareSpecReporter extends Transform {
    constructor(options) {
        super({ ...options, writableObjectMode: true });

        this.inner = new spec();

        // keyed by resolved path, which is how the runner reports a file; the value is the name the
        // run was given, which is what a report prints
        this.outstanding = new Map(expectedFiles().map(file => [fileKey(file), file]));
        // the same, never pruned: a file that completed is still named by the given name in a report
        this.names = new Map(this.outstanding);
        // the file-level result is reported under the name the run was given, as a test of its own
        this.fileNames = new Set(this.outstanding.values());
        // What each file has reported so far, keyed by its resolved path: when it started, how many
        // of its tests finished, and the last one. A stall report says which state a stuck file is
        // in: its tests all reported and its process never exited, or one of them never finished
        this.progress = new Map();
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
        const waiting = [...this.outstanding.keys()];
        const detail = waiting.length
            ? waiting.map(key => `  - ${this.outstanding.get(key)}${this.describeProgress(key)}`).join('\n')
            : '  (none - the run stalled after every file had reported)';

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

    // One line on how far a stuck file got, read off the events it reported
    describeProgress(key) {
        const progress = this.progress.get(key);
        if (!progress) {
            return '\n      not started';
        }
        const ago = at => `${Math.round((Date.now() - at) / 1000)}s ago`;
        if (!progress.finished) {
            return `\n      started ${ago(progress.startedAt)}, no test reported yet (a test is blocked, or the file is still loading)`;
        }
        return (
            `\n      started ${ago(progress.startedAt)}, ${progress.finished} test(s) reported, the last ${ago(progress.lastAt)}: "${progress.lastName}"` +
            `\n      if that was its last test, the tests are done and the process did not exit` +
            `\n      (on Node 24 that can be process.exit() deadlocking, see EXIT_SAFE_V8_FLAGS in test/run-tests.js)`
        );
    }

    // A file's own result is reported as a test named after the file: by the path the run was given
    // (Node 22+), or by its absolute path, the same as its `file` (Node 20)
    isFileResult(data) {
        return data.name === data.file || this.fileNames.has(data.name);
    }

    track(event) {
        const data = event && event.data;
        if (!data || !data.file) {
            return;
        }
        const key = fileKey(data.file);
        let progress = this.progress.get(key);
        if (!progress) {
            // `open`: tests that started and have not reported, by name within their nesting level,
            // counted because a loop can give several tests one name
            progress = { startedAt: Date.now(), finished: 0, lastName: null, lastAt: 0, open: new Map() };
            this.progress.set(key, progress);
        }
        const started = event.type === 'test:start';
        const finished = event.type === 'test:pass' || event.type === 'test:fail';
        if ((!started && !finished) || this.isFileResult(data)) {
            return;
        }
        const id = `${data.nesting}:${data.name}`;
        if (started) {
            progress.open.set(id, (progress.open.get(id) || 0) + 1);
            return;
        }
        progress.finished++;
        progress.lastName = data.name;
        progress.lastAt = Date.now();
        const left = (progress.open.get(id) || 0) - 1;
        if (left > 0) {
            progress.open.set(id, left);
        } else {
            progress.open.delete(id);
        }
    }

    // Once every event of the run has arrived, a test still open never reported: its result was lost
    // between the file's process and the runner
    droppedResults() {
        const dropped = [];
        for (const [key, progress] of this.progress) {
            if (progress.open.size) {
                dropped.push({ file: this.names.get(key) || key, names: [...progress.open.keys()] });
            }
        }
        return dropped;
    }

    // The run fails through the exit code: the summary prints as usual, it just cannot be trusted,
    // which the report next to it says. The exit code survives
    // --test-force-exit also when it is set this late (verified on Node 20, 22 and 24: the forced
    // exit takes process.exitCode)
    reportDroppedResults(dropped) {
        const detail = dropped.map(entry => `  - ${entry.file}:\n` + entry.names.map(name => `      ${name}`).join('\n')).join('\n');
        const heading = `\nResults lost: ${dropped.length} file(s) ended with tests that started and never reported, so the summary is incomplete:\n${detail}\n`;
        process.exitCode = 1;
        fs.writeSync(
            2,
            `${heading}The run fails rather than count them as passed; a lost result can be a failing one.\n` +
                `See the note on lost results in test/helpers/stall-reporter.js.\n`
        );
    }

    forward(err, output, callback) {
        if (output) {
            this.push(output);
        }
        callback(err);
    }

    _transform(event, encoding, callback) {
        this.lastEvent = Date.now();

        // The file-level result: `node --test` reports each file as a top-level test whose name is
        // the path it was given on the command line.
        if (event && event.type === 'test:complete' && event.data && event.data.nesting === 0) {
            // top-level tests are nesting 0 too; only a file's own result names one of the files
            if (this.isFileResult(event.data)) {
                this.outstanding.delete(fileKey(event.data.name));
            }
        }
        this.track(event);

        this.inner._transform(event, encoding, (err, output) => this.forward(err, output, callback));
    }

    _flush(callback) {
        if (this.watchdog) {
            clearInterval(this.watchdog);
        }
        const dropped = this.droppedResults();
        if (dropped.length) {
            this.reportDroppedResults(dropped);
        }
        this.inner._flush((err, output) => this.forward(err, output, callback));
    }
}

module.exports = StallAwareSpecReporter;
