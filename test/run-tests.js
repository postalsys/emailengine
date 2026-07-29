#!/usr/bin/env node
'use strict';

// Runs one of the two test tiers described in .claude/rules/testing.md:
//
//   node test/run-tests.js unit         flush Redis, then run test/*-test.js in parallel
//   node test/run-tests.js integration  flush Redis, boot a live server, then run
//                                       test/integration/*-test.js serially against it
//
// NODE_ENV is defaulted below before anything requires the config: @zone-eu/wild-config picks the
// Redis database from it, so without it the development database would be flushed instead of the
// test one. The dovecot and e2e tiers orchestrate themselves (test/dovecot/run-dovecot-tests.sh and
// the Playwright webServer block) and do not go through here.

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');

const { flushRedis } = require('./helpers/flush-redis');
const { waitForServer } = require('./helpers/wait-for-server');

const PROJECT_ROOT = path.join(__dirname, '..');

// Per-test timeout for both tiers. Some IMAP and OAuth2 flows in the integration tier legitimately
// take minutes against live providers.
const TEST_TIMEOUT = 180000;

const TIERS = {
    unit: {
        dir: 'test',
        // Default --test concurrency: the unit suite is verified to pass in parallel
        args: []
    },
    integration: {
        dir: 'test/integration',
        // Serial - every file talks to the same live server and the same Redis database
        args: ['--test-concurrency=1'],
        // Presence of this field is what makes the tier boot a server
        serverEnv: {
            // Short Gmail fallback-poll interval so gmail-polling-test can exercise the poller
            // quickly. Harmless for push-based Gmail accounts in api-test: notifications keep
            // resetting the timer, and a stray fallback sync is coalesced/idempotent.
            EENGINE_GMAIL_FALLBACK_POLL_INTERVAL: '15000'
        }
    }
};

// Non-recursive and sorted, matching the shell globs these tiers have always used
// (`test/*-test.js`, `test/integration/*-test.js`). Resolved here rather than handed to
// `node --test` as a glob because glob expansion only landed in Node 22 and package.json declares
// engines >=20.x. The *-test.js suffix is what keeps test/helpers/* and
// test/integration/test-config.js from being executed as tests.
function findTestFiles(dir) {
    let files = fs
        .readdirSync(path.join(PROJECT_ROOT, dir))
        .filter(name => name.endsWith('-test.js'))
        .sort()
        .map(name => path.join(dir, name));

    if (!files.length) {
        // `node --test` with no file arguments falls back to its own recursive discovery, so an
        // empty list would silently run a different suite instead of failing
        throw new Error(`No *-test.js files found in ${dir}`);
    }

    return files;
}

let server = null;

// Runs as an exit hook, so the server is reaped even when the tests fail or the run is interrupted.
// Without it a failed integration run leaves a listener on port 7077 that answers /health and
// silently serves stale code to the next run. EmailEngine's workers are worker_threads rather than
// child processes, so killing the one process takes the whole server down with it.
function stopServer() {
    if (!server) {
        return;
    }
    let proc = server;
    server = null;
    try {
        proc.kill('SIGKILL');
    } catch (err) {
        // already gone
    }
}

function startServer(env) {
    server = spawn(process.execPath, ['server.js'], {
        cwd: PROJECT_ROOT,
        stdio: ['ignore', 'inherit', 'inherit'],
        env: { ...process.env, ...env }
    });
    server.on('exit', () => {
        server = null;
    });
    // Do not hold the event loop open - stopServer() owns the teardown
    server.unref();

    process.on('exit', stopServer);
    // A signal with no listener at all terminates the process without firing the exit hook
    process.on('SIGINT', () => process.exit(130));
    process.on('SIGTERM', () => process.exit(143));
}

async function main() {
    let name = process.argv[2];
    let tier = TIERS[name];
    if (!tier) {
        console.error(`Usage: node test/run-tests.js <${Object.keys(TIERS).join('|')}>`);
        process.exitCode = 1;
        return;
    }

    let files = findTestFiles(tier.dir);

    await flushRedis();

    if (tier.serverEnv) {
        startServer(tier.serverEnv);
        await waitForServer();
    }

    let runner = spawn(process.execPath, ['--test', `--test-timeout=${TEST_TIMEOUT}`, ...tier.args, ...files], {
        cwd: PROJECT_ROOT,
        stdio: 'inherit'
    });

    // A child killed by a signal reports code=null; treat that as a failure
    let [code, signal] = await once(runner, 'exit');
    process.exitCode = signal ? 1 : code;
}

main().catch(err => {
    console.error(err.stack || err.message);
    process.exitCode = 1;
});
