'use strict';

// Polls the /health endpoint until the API server reports ready (HTTP 200).
// The /health route only succeeds once all IMAP workers are up and Redis is
// responding, so this replaces the fixed startup delay previously used by the
// Grunt test task. Helper modules live outside the *-test.js patterns so the
// test runner never executes them as test files.

const config = require('@zone-eu/wild-config');
const { fetch } = require('undici');

const POLL_INTERVAL = 500;
const TIMEOUT = 120 * 1000;

const url = `http://127.0.0.1:${config.api.port}/health`;

async function main() {
    let started = Date.now();
    while (Date.now() - started < TIMEOUT) {
        try {
            let res = await fetch(url);
            if (res.ok) {
                console.log(`Server is ready at ${url} (waited ${((Date.now() - started) / 1000).toFixed(1)}s)`);
                return;
            }
            // consume the body so the keep-alive socket can be reused between polls
            await res.body?.cancel();
        } catch (err) {
            // server is not listening yet, keep polling
        }
        await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
    }
    throw new Error(`Server did not become ready at ${url} within ${TIMEOUT / 1000}s`);
}

main().catch(err => {
    console.error(err.message);
    process.exit(1);
});
