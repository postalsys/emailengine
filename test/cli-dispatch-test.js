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

// `tokens issue` used to accept only `mcp` of the two MCP scopes, and minted it with no permissions
// record - the "full = no record" level the admin form and the consent prompt both dropped, because a
// consent given for today's tools must not grow to include a tool shipped next release.
test('tokens issue mints an MCP scope with the explicit grants the UI mints', async t => {
    const { mcpGrantsFor } = require('../lib/token-permission-view');
    const msgpack = require('../lib/msgpack');

    const issue = args => {
        const result = runCli(['tokens', 'issue', '--description', 'cli-scope-test', ...args]);
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.trim();
    };

    const stored = token => {
        const result = runCli(['tokens', 'export', '--token', token]);
        assert.equal(result.status, 0, result.stderr);
        return msgpack.decode(Buffer.from(result.stdout.trim(), 'base64url'));
    };

    await t.test('mcp-manage is accepted, with the grants of the level named', () => {
        const tokenData = stored(issue(['--scope', 'mcp-manage:administer']));
        assert.deepEqual(tokenData.scopes, ['mcp-manage']);
        assert.deepEqual(tokenData.permissions, mcpGrantsFor({ manage: 'administer' }).permissions);
    });

    // There is no consent prompt here to show what a level allows, so the one thing an implicit
    // default must not do is pick the widest one
    await t.test('an MCP scope with no level is refused rather than defaulted', () => {
        for (const scope of ['mcp-manage', 'mcp']) {
            const result = runCli(['tokens', 'issue', '--scope', scope]);
            assert.equal(result.status, 1, scope);
            assert.match(result.stderr, new RegExp(`Scope "${scope}" needs an access level`), scope);
        }
    });

    await t.test('asking for a scope and declining it in the same breath is refused', () => {
        const result = runCli(['tokens', 'issue', '--scope', 'mcp:none']);
        assert.equal(result.status, 1);
        assert.match(result.stderr, /Unknown mcp access level: none/);
    });

    await t.test('a level after a colon mints that level, management first', () => {
        const tokenData = stored(issue(['--scope', 'mcp:read', '--scope', 'mcp-manage:observe']));
        assert.deepEqual(tokenData.scopes, ['mcp-manage', 'mcp']);
        assert.deepEqual(tokenData.permissions, mcpGrantsFor({ manage: 'observe', mail: 'read' }).permissions);
    });

    await t.test('an unknown level is refused by name', () => {
        const result = runCli(['tokens', 'issue', '--scope', 'mcp-manage:root']);
        assert.equal(result.status, 1);
        assert.match(result.stderr, /Unknown mcp-manage access level: root/);
        assert.match(result.stderr, /observe/);
    });

    await t.test('a level on a scope that has none is refused', () => {
        const result = runCli(['tokens', 'issue', '--scope', 'api:read']);
        assert.equal(result.status, 1);
        assert.match(result.stderr, /does not take an access level/);
    });

    await t.test('an MCP scope cannot ride along with a REST scope', () => {
        // One permissions record covers the whole token, so a level's pair list would narrow the
        // REST API too. The admin form hides the level editor for the same reason.
        const result = runCli(['tokens', 'issue', '--scope', 'api', '--scope', 'mcp:read']);
        assert.equal(result.status, 1);
        assert.match(result.stderr, /cannot be combined/);
    });

    await t.test('a non-MCP scope is unchanged and carries no permissions record', () => {
        const tokenData = stored(issue(['--scope', 'api']));
        assert.deepEqual(tokenData.scopes, ['api']);
        assert.equal(tokenData.permissions, undefined);
    });
});
