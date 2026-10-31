'use strict';

// Polls the /health endpoint until the API server reports ready (HTTP 200).
// The /health route only succeeds once all IMAP workers are up and Redis is
// responding, so this replaces a fixed startup delay. Used in-process by
// test/run-tests.js and as a standalone command by
// test/dovecot/run-dovecot-tests.sh. Helper modules live outside the *-test.js
// patterns so the test runner never executes them as test files.

const config = require('@zone-eu/wild-config');
const { fetch } = require('undici');

const POLL_INTERVAL = 500;
const TIMEOUT = 120 * 1000;

// `child` is the spawned server process, when the caller has one. Without it a server that
// crashed on boot was only noticed after the whole two minute timeout, and a stale listener on
// the same port could answer /health in its place.
function exitDescription(child) {
    if (!child) {
        return null;
    }
    if (child.exitCode !== null) {
        return `exit code ${child.exitCode}`;
    }
    if (child.signalCode !== null) {
        return `signal ${child.signalCode}`;
    }
    return null;
}

// `url` and `timeout` default to the test server from the config; the multi-instance fleet passes
// each instance's own (test/helpers/instance-fleet.js), and `quiet` keeps a fleet's starts out of the
// run output
async function waitForServer({ child, url = `http://127.0.0.1:${config.api.port}/health`, timeout = TIMEOUT, quiet = false } = {}) {
    let started = Date.now();
    while (Date.now() - started < timeout) {
        let ready = false;
        try {
            let res = await fetch(url);
            ready = res.ok;
            // consume the body so the keep-alive socket can be reused between polls
            await res.body?.cancel();
        } catch (err) {
            // server is not listening yet, keep polling
        }

        // Checked after the probe too: a 200 may have come from the process that has just died
        let exited = exitDescription(child);
        if (exited) {
            throw new Error(`Server process exited (${exited}) before ${url} became ready`);
        }

        if (ready) {
            if (!quiet) {
                console.log(`Server is ready at ${url} (waited ${((Date.now() - started) / 1000).toFixed(1)}s)`);
            }
            return;
        }
        await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
    }
    throw new Error(`Server did not become ready at ${url} within ${timeout / 1000}s`);
}

module.exports = { waitForServer };

if (require.main === module) {
    waitForServer().catch(err => {
        console.error(err.message);
        process.exit(1);
    });
}
