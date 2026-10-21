'use strict';

// lib/queue-stats.js against stand-ins for the two BullMQ getters it uses, so the payload shape the
// /v1/stats and queue settings routes publish, and the failed count /metrics reports, are pinned
// without a queue to put into each state.

const test = require('node:test');
const assert = require('node:assert').strict;

const { queueStats, COUNTED_STATES } = require('../lib/queue-stats');

function fakeQueue({ counts = {}, paused = false } = {}) {
    const calls = [];
    return {
        calls,
        async getJobCounts(...states) {
            calls.push(states);
            return Object.fromEntries(states.map(state => [state, counts[state] ?? 0]));
        },
        async isPaused() {
            return paused;
        }
    };
}

test('queueStats()', async t => {
    await t.test('counts the pending states and totals them', async () => {
        const queue = fakeQueue({ counts: { active: 2, delayed: 5, waiting: 7, failed: 100, completed: 40 } });
        assert.deepEqual(await queueStats(queue), { paused: 0, isPaused: false, active: 2, delayed: 5, waiting: 7, total: 14 });
        // completed and failed are retained separately and must not be asked for, or counted
        assert.deepEqual(queue.calls, [COUNTED_STATES]);
    });

    await t.test('a paused queue keeps its jobs in waiting and reports a zero paused count', async () => {
        const stats = await queueStats(fakeQueue({ counts: { waiting: 3 }, paused: true }));
        assert.equal(stats.isPaused, true);
        assert.equal(stats.paused, 0);
        assert.equal(stats.waiting, 3);
        assert.equal(stats.total, 3);
    });

    await t.test('missing or non-numeric counts read as zero', async () => {
        const queue = {
            async getJobCounts() {
                return { active: '4', delayed: undefined, waiting: 'x' };
            },
            async isPaused() {
                return undefined;
            }
        };
        assert.deepEqual(await queueStats(queue), { paused: 0, isPaused: false, active: 4, delayed: 0, waiting: 0, total: 4 });
    });

    await t.test('a failing getter rejects instead of reporting zeroes', async () => {
        const queue = fakeQueue();
        queue.getJobCounts = async () => {
            throw new Error('OOM command not allowed');
        };
        await assert.rejects(queueStats(queue), /OOM/);
    });
});

test('queueStats() with the failed count', async t => {
    await t.test('reads it in the same getJobCounts call, outside the total', async () => {
        const queue = fakeQueue({ counts: { failed: 12, waiting: 3 } });
        const stats = await queueStats(queue, { failed: true });
        assert.equal(stats.failed, 12);
        assert.equal(stats.total, 3, 'a failed job is not pending work');
        assert.deepEqual(queue.calls, [COUNTED_STATES.concat('failed')], 'one read for both');
    });

    await t.test('an empty queue reports zero', async () => {
        assert.equal((await queueStats(fakeQueue(), { failed: true })).failed, 0);
    });

    await t.test('without the option the published shape has no failed key', async () => {
        assert.ok(!('failed' in (await queueStats(fakeQueue({ counts: { failed: 5 } })))));
    });
});
