'use strict';

// bin/emailengine.js command dispatch (WORK-17). The CLI opens a Redis connection on load, so a
// branch that neither exits nor starts anything leaves a process that hangs forever with no
// output; and the catch-all branch used to start the whole server for any mistyped command.
// Runs the real CLI in a child Node process (the same binary running the tests, no shell).

const test = require('node:test');
const assert = require('node:assert').strict;
const { spawnSync } = require('node:child_process');
const Path = require('path');

const CLI = Path.join(__dirname, '..', 'bin', 'emailengine.js');

function runCli(args) {
    const result = spawnSync(process.execPath, [CLI, ...args], {
        env: Object.assign({}, process.env, { NODE_ENV: 'test' }),
        encoding: 'utf8',
        // A hang is the failure being tested for; a generous bound turns it into a clear one
        timeout: 20000
    });
    assert.notEqual(result.signal, 'SIGTERM', `"emailengine ${args.join(' ')}" did not exit`);
    return result;
}

test('an unknown command is refused instead of starting the server', () => {
    const result = runCli(['no-such-command']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unknown command: no-such-command/);
});

test('an unknown tokens subcommand exits with usage', () => {
    const result = runCli(['tokens', 'frobnicate']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unknown tokens command: frobnicate/);
    assert.match(result.stderr, /issue/, 'the tokens usage is shown');
});

test('a tokens import that cannot be decoded exits with an error', () => {
    // 0xc1 is the one byte msgpack never assigns, so decoding it always throws
    const result = runCli(['tokens', 'import', '--token', Buffer.from([0xc1]).toString('base64url')]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Unable to decode token data/);
});
