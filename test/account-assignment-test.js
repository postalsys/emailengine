'use strict';

// Regression tests for lib/account-assignment.js. Sentry EMAILENGINE-COMMUNITY-8: an IMAP worker
// exited while the `assign` call to it was in flight. Its exit handler had already dropped the
// worker's account set, so the rollback threw "Cannot read properties of undefined (reading
// 'delete')", which ended the pass and stranded the accounts that had failed before it.

const test = require('node:test');
const assert = require('node:assert').strict;

const { pickLeastLoadedWorker, rollbackAssignment, releaseWorkerAccounts, requeueFailedAccounts } = require('../lib/account-assignment');

function makeState(workers) {
    return {
        workerAssigned: new WeakMap(workers.map(worker => [worker, new Set()])),
        assigned: new Map(),
        unassigned: new Set(),
        workerLoadMap: new Map(workers.map(worker => [worker, 0])),
        availableWorkers: new Set(workers)
    };
}

// What assignAccounts() records before it calls the worker
function trackAssignment(state, account, worker) {
    if (!state.workerAssigned.has(worker)) {
        state.workerAssigned.set(worker, new Set());
    }
    state.workerAssigned.get(worker).add(account);
    state.assigned.set(account, worker);
    state.unassigned.delete(account);
    state.workerLoadMap.set(worker, (state.workerLoadMap.get(worker) || 0) + 1);
}

// The worker exit handler in server.js
function workerExited(state, worker) {
    state.availableWorkers.delete(worker);
    return releaseWorkerAccounts(state, worker);
}

test('a worker exiting while its assign call is in flight', async t => {
    await t.test('rolls back without throwing and requeues the account once', () => {
        const [dead, alive] = [{ threadId: 1 }, { threadId: 2 }];
        const state = makeState([dead, alive]);
        trackAssignment(state, 'acc1', dead);

        assert.deepEqual(workerExited(state, dead), new Set(['acc1']));
        assert.doesNotThrow(() => rollbackAssignment(state, 'acc1', dead, true));

        requeueFailedAccounts(state, ['acc1']);
        assert.deepEqual(state.unassigned, new Set(['acc1']));
        assert.equal(state.assigned.has('acc1'), false);
    });

    await t.test('an account the same pass assigned again is not also left unassigned', () => {
        const [dead, alive] = [{ threadId: 1 }, { threadId: 2 }];
        const state = makeState([dead, alive]);
        trackAssignment(state, 'acc1', dead);
        workerExited(state, dead);
        rollbackAssignment(state, 'acc1', dead, true);

        // the exit handler requeued it into the Set being iterated, so the pass visits it again
        assert.ok(state.unassigned.has('acc1'));
        trackAssignment(state, 'acc1', alive);

        requeueFailedAccounts(state, ['acc1']);
        assert.equal(state.unassigned.has('acc1'), false);
        assert.equal(state.assigned.get('acc1'), alive);
    });

    await t.test('the next pick skips the exited worker', () => {
        const [dead, alive] = [{ threadId: 1 }, { threadId: 2 }];
        const state = makeState([dead, alive]);
        state.workerLoadMap.set(alive, 5);
        workerExited(state, dead);

        assert.equal(pickLeastLoadedWorker(state.availableWorkers, state.workerLoadMap, 1), alive);
    });
});

test('rollbackAssignment() reverts the load it counted, and only that', () => {
    const worker = { threadId: 1 };
    const state = makeState([worker]);
    trackAssignment(state, 'acc1', worker);
    trackAssignment(state, 'acc2', worker);

    rollbackAssignment(state, 'acc1', worker, true);
    rollbackAssignment(state, 'acc2', worker, false);

    assert.equal(state.workerLoadMap.get(worker), 1);
    assert.equal(state.workerAssigned.get(worker).size, 0);
    assert.equal(state.assigned.size, 0);
});

test('pickLeastLoadedWorker()', async t => {
    await t.test('prefers the least loaded worker below the target, else the least loaded one', () => {
        const [a, b] = [{ threadId: 1 }, { threadId: 2 }];
        const state = makeState([a, b]);
        state.workerLoadMap.set(a, 5);
        state.workerLoadMap.set(b, 4);

        assert.equal(pickLeastLoadedWorker(state.availableWorkers, state.workerLoadMap, 10), b);
        assert.equal(pickLeastLoadedWorker(state.availableWorkers, state.workerLoadMap, 2), b);
    });

    await t.test('picks up a worker that started during the pass', () => {
        const old = { threadId: 1 };
        const state = makeState([old]);
        state.workerLoadMap.set(old, 3);
        const replacement = { threadId: 2 };
        state.availableWorkers.add(replacement);

        assert.equal(pickLeastLoadedWorker(state.availableWorkers, state.workerLoadMap, 10), replacement);
    });
});

test('releaseWorkerAccounts() returns null for a worker with no accounts tracked', () => {
    const state = makeState([]);
    assert.equal(releaseWorkerAccounts(state, { threadId: 1 }), null);
});
