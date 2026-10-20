'use strict';

// The fields the heartbeat log lines carry and the per-thread event loop delay gauge values,
// computed in lib/thread-diagnostics.js from what server.js knows about a thread.

const test = require('node:test');
const assert = require('node:assert').strict;

const { heartbeatDiagnostics, eventLoopDelaySeries } = require('../lib/thread-diagnostics');

test('heartbeatDiagnostics()', async t => {
    await t.test('an account worker with a reading', () => {
        assert.deepEqual(
            heartbeatDiagnostics({
                now: 100000,
                lastHeartbeat: 37600,
                accounts: 250,
                threadInfo: { threadId: 3, eventLoopDelay: { max: 1234.6, p99: 900 } }
            }),
            { timeSinceHeartbeat: '62s', accounts: 250, lastEventLoopDelay: '1235ms' }
        );
    });

    await t.test('a thread without accounts or a reading reports only what is known', () => {
        assert.deepEqual(heartbeatDiagnostics({ now: 100000, lastHeartbeat: 69000, threadInfo: { threadId: 4, eventLoopDelay: null } }), {
            timeSinceHeartbeat: '31s'
        });
        assert.deepEqual(heartbeatDiagnostics({ now: 100000 }), {});
    });

    await t.test('an account worker with no accounts still reports the zero', () => {
        assert.equal(heartbeatDiagnostics({ now: 1, accounts: 0 }).accounts, 0);
    });
});

test('eventLoopDelaySeries() converts readings to seconds and skips threads without one', () => {
    assert.deepEqual(
        eventLoopDelaySeries([
            { type: 'main', threadId: 0, eventLoopDelay: { max: 250, p99: 40 } },
            { type: 'imap', threadId: 7, eventLoopDelay: null },
            { type: 'imap', threadId: 8, resourceUsageError: { error: 'Timeout' } }
        ]),
        [{ labels: { type: 'main', thread: '0' }, max: 0.25, p99: 0.04 }]
    );
    assert.deepEqual(eventLoopDelaySeries(null), []);
});
