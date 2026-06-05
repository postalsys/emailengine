'use strict';

// Regression tests for lib/reject-worker-calls.js. When a worker thread terminates,
// the main thread must reject the pending cross-thread calls routed to it instead of
// leaving them to hang until their individual timeouts fire.

const test = require('node:test');
const assert = require('node:assert').strict;

const { rejectWorkerCalls } = require('../lib/reject-worker-calls');

// Build a callQueue entry shaped like the ones server.js stores.
function makeEntry(worker) {
    const entry = {
        worker,
        rejectedWith: undefined,
        timerCleared: false
    };
    entry.timer = setTimeout(() => {}, 60 * 1000);
    entry.reject = err => {
        clearTimeout(entry.timer);
        entry.timerCleared = true;
        entry.rejectedWith = err;
    };
    return entry;
}

test('rejectWorkerCalls() rejects only the dead worker entries and removes them', () => {
    const workerA = { threadId: 1 };
    const workerB = { threadId: 2 };

    const callQueue = new Map();
    callQueue.set('a1', makeEntry(workerA));
    callQueue.set('a2', makeEntry(workerA));
    callQueue.set('b1', makeEntry(workerB));

    const err = new Error('Worker terminated');

    const rejected = rejectWorkerCalls(callQueue, workerA, err);

    assert.strictEqual(rejected, 2, 'should report both workerA calls rejected');
    assert.strictEqual(callQueue.size, 1, 'only the surviving workerB call should remain');
    assert.ok(callQueue.has('b1'), 'workerB call must be untouched');

    const survivor = callQueue.get('b1');
    assert.strictEqual(survivor.rejectedWith, undefined, 'workerB call must not be rejected');
    clearTimeout(survivor.timer);
});

test('rejectWorkerCalls() forwards the shared error and clears timers', () => {
    const worker = { threadId: 7 };
    const entry = makeEntry(worker);

    const callQueue = new Map([['mid', entry]]);
    const err = new Error('Worker terminated');

    rejectWorkerCalls(callQueue, worker, err);

    assert.strictEqual(entry.rejectedWith, err, 'entry should be rejected with the provided error');
    assert.strictEqual(entry.timerCleared, true, 'the entry timeout should be cleared on rejection');
});

test('rejectWorkerCalls() keeps cleaning up after a rejection callback throws', () => {
    const worker = { threadId: 9 };

    const throwing = makeEntry(worker);
    throwing.reject = () => {
        clearTimeout(throwing.timer);
        throw new Error('synchronous failure in rejection handler');
    };
    const healthy = makeEntry(worker);

    const callQueue = new Map([
        ['bad', throwing],
        ['good', healthy]
    ]);

    const rejected = rejectWorkerCalls(callQueue, worker, new Error('Worker terminated'));

    assert.strictEqual(rejected, 2, 'both entries should be counted even when one throws');
    assert.strictEqual(callQueue.size, 0, 'all matching entries should be removed');
    assert.ok(healthy.rejectedWith, 'the second entry must still be rejected');
});

test('rejectWorkerCalls() returns 0 when no entries match', () => {
    const worker = { threadId: 1 };
    const other = { threadId: 2 };

    const entry = makeEntry(other);
    const callQueue = new Map([['mid', entry]]);

    const rejected = rejectWorkerCalls(callQueue, worker, new Error('Worker terminated'));

    assert.strictEqual(rejected, 0, 'no calls should be rejected');
    assert.strictEqual(callQueue.size, 1, 'the unrelated entry should remain');
    clearTimeout(entry.timer);
});
