'use strict';

// The global fatal handlers must always exit, and must leave the process alive for at least one
// timer turn first. That window is what lets Node emit 'rejectionHandled' when a handler turns up
// a microtask after a rejection was already reported, and that late-handler line is the only
// thing separating a genuinely missing catch from a handler that lost a race.
//
// The window used to exist only when error tracking was off. With a hook installed, the exit was
// taken straight off the flush promise, so a resolved flush exited in a microtask - losing the
// diagnostic on exactly the installations that report the most crashes.
//
// The window itself is what is asserted here, not the race that motivated it: whether
// 'rejectionHandled' wins its race depends on how the child's stdio is set up, so it is not
// stable enough to assert, while "a 1 ms timer still fires" is exactly the guarantee the
// diagnostic rests on and is stable. Both run in a child process, because the code under test
// calls process.exit().

const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const PROBE_PATH = path.join(__dirname, 'helpers', 'fatal-probe.js');

function runProbe(mode) {
    const result = spawnSync(process.execPath, [PROBE_PATH, mode], {
        encoding: 'utf8',
        env: Object.assign({}, process.env, { EENGINE_LOG_LEVEL: 'trace' })
    });

    const messages = (result.stdout || '')
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
            try {
                return JSON.parse(line).msg;
            } catch {
                return null;
            }
        })
        .filter(Boolean);

    return { status: result.status, messages };
}

test('a fatal rejection exits with code 2 after a grace window', async t => {
    await t.test('without an error tracking hook', () => {
        const { status, messages } = runProbe('plain');
        assert.strictEqual(status, 2, 'exits with the unhandledRejection code');
        assert.ok(messages.includes('unhandledRejection'), 'reports the rejection');
        assert.ok(messages.includes('still-alive-marker'), 'stays alive for a timer turn before exiting');
    });

    await t.test('with an error tracking hook that flushes immediately', () => {
        const { status, messages } = runProbe('flush');
        assert.strictEqual(status, 2, 'exits with the unhandledRejection code');
        assert.ok(messages.includes('unhandledRejection'), 'reports the rejection');
        assert.ok(
            messages.includes('still-alive-marker'),
            'stays alive for a timer turn even when the flush resolves immediately - exiting straight off the flush promise skipped this window'
        );
    });
});
