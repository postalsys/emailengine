'use strict';

// Regression tests for lib/account-assignment.js. Sentry EMAILENGINE-COMMUNITY-8: an IMAP worker
// exited while the `assign` call to it was in flight. Its exit handler had already dropped the
// worker's account set, so the rollback threw "Cannot read properties of undefined (reading
// 'delete')", which ended the pass and stranded the accounts that had failed before it.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    pickLeastLoadedWorker,
    rollbackAssignment,
    rollbackFailedAssignment,
    releaseWorkerAccounts,
    forgetAccount,
    shouldRequeueFailedAssignment,
    planRebalance
} = require('../lib/account-assignment');
const { mapConcurrent } = require('../lib/utils/map-concurrent');

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
        let stillOurs;
        assert.doesNotThrow(() => {
            stillOurs = rollbackFailedAssignment(state, 'acc1', dead, true);
        });

        // The exit handler requeued it already, so the pass leaves it be
        assert.equal(stillOurs, false);
        assert.deepEqual(state.unassigned, new Set(['acc1']));
        assert.equal(state.assigned.has('acc1'), false);
    });

    await t.test('the next pick skips the exited worker', () => {
        const [dead, alive] = [{ threadId: 1 }, { threadId: 2 }];
        const state = makeState([dead, alive]);
        state.workerLoadMap.set(alive, 5);
        workerExited(state, dead);

        assert.equal(pickLeastLoadedWorker(state.availableWorkers, state.workerLoadMap, 1), alive);
    });
});

// The coordinator handing an account to another instance (or the account being deleted) while the
// assign call to a worker is in flight, through stopServingAccount() and forgetAccount() in
// server.js. The pass used to requeue the failure after the release, and the old instance went on
// to connect an account it no longer owned
test('an account released while its assign call was in flight is not requeued', () => {
    const worker = { threadId: 1 };
    const state = makeState([worker]);
    trackAssignment(state, 'acc1', worker);

    assert.equal(forgetAccount(state, 'acc1'), worker, 'the worker is told to unassign it');
    assert.equal(rollbackFailedAssignment(state, 'acc1', worker, true), false, 'the pass does not requeue it');
    assert.equal(state.workerLoadMap.get(worker), 0);
    assert.equal(state.unassigned.has('acc1'), false);
});

test('a failed assignment still ours is requeued, and a release before the retry takes it out again', () => {
    const worker = { threadId: 1 };
    const state = makeState([worker]);
    trackAssignment(state, 'acc1', worker);

    assert.equal(rollbackFailedAssignment(state, 'acc1', worker, true), true);
    // What assignAccounts() does with it: back to unassigned at once, where a release finds it
    state.unassigned.add('acc1');
    assert.equal(forgetAccount(state, 'acc1'), null);
    assert.equal(state.unassigned.has('acc1'), false);
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

function assign(state, worker, accounts) {
    for (const account of accounts) {
        state.workerAssigned.get(worker).add(account);
        state.assigned.set(account, worker);
    }
}

test('forgetAccount() drops a deleted account from every record, including `assigned` (WORK-8)', () => {
    const w1 = { threadId: 1 };
    const state = makeState([w1]);
    assign(state, w1, ['a', 'b']);

    assert.equal(forgetAccount(state, 'a'), w1, 'returns the worker to send the cleanup to');
    assert.equal(state.assigned.has('a'), false, 'a deleted account must not stay routed to its worker');
    assert.deepEqual([...state.workerAssigned.get(w1)], ['b']);

    forgetAccount(state, 'b');
    assert.equal(state.workerAssigned.has(w1), false, 'an emptied account set is dropped');
});

test('forgetAccount() handles an unassigned account and the state before the first load', () => {
    const state = makeState([]);
    state.unassigned.add('a');
    assert.equal(forgetAccount(state, 'a'), null);
    assert.equal(state.unassigned.has('a'), false);

    assert.equal(forgetAccount(Object.assign(state, { unassigned: false }), 'b'), null);
});

test('shouldRequeueFailedAssignment() drops an account that no longer exists (WORK-15)', async () => {
    const notFound = Object.assign(new Error('Account record was not found'), { statusCode: 404 });
    assert.equal(await shouldRequeueFailedAssignment(notFound, 'a', async () => true), false, 'the worker said it is gone');

    const timeout = Object.assign(new Error('Request timed out'), { code: 'Timeout', statusCode: 504 });
    assert.equal(await shouldRequeueFailedAssignment(timeout, 'a', async () => false), false, 'deleted while the pass ran');
    assert.equal(await shouldRequeueFailedAssignment(timeout, 'a', async () => true), true, 'a transient failure is retried');
    assert.equal(
        await shouldRequeueFailedAssignment(timeout, 'a', async () => {
            throw new Error('Redis down');
        }),
        true,
        'an unknown membership keeps the account'
    );
});

test('planRebalance() gives a late worker its share from the most loaded workers (WORK-7)', () => {
    const [w1, w2, w3] = [{ threadId: 1 }, { threadId: 2 }, { threadId: 3 }];
    const state = makeState([w1, w2, w3]);
    // The failsafe reassignment spread w3's accounts over the survivors before w3 came back
    assign(state, w1, ['a1', 'a2', 'a3', 'a4', 'a5']);
    assign(state, w2, ['b1', 'b2', 'b3', 'b4']);

    const moves = planRebalance(state, w3);
    assert.equal(moves.length, 3, 'nine accounts over three workers is three each');
    assert.deepEqual(
        moves.map(move => move.worker.threadId),
        [1, 1, 2],
        'accounts come from whichever worker holds the most'
    );
    for (const { account, worker } of moves) {
        assert.equal(state.assigned.get(account), worker, 'each move names the account and its current worker');
    }
});

test('planRebalance() leaves a balanced fleet alone', () => {
    const [w1, w2] = [{ threadId: 1 }, { threadId: 2 }];
    const state = makeState([w1, w2]);
    assert.deepEqual(planRebalance(state, w2), [], 'nothing to move without accounts');

    assign(state, w1, ['a1']);
    assert.deepEqual(planRebalance(state, w2), [], 'moving the only account would only move the imbalance');

    assign(state, w2, ['b1']);
    assert.deepEqual(planRebalance(state, w2), []);
    assert.deepEqual(planRebalance(state, { threadId: 9 }), [], 'an unknown worker gets nothing');
});

test('mapConcurrent() bounds the calls in flight and keeps the results in item order', async () => {
    let inFlight = 0;
    let peak = 0;
    const results = await mapConcurrent([50, 10, 30, 20, 40], 2, async (delay, index) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise(resolve => setTimeout(resolve, delay / 10));
        inFlight--;
        return { delay, index };
    });
    assert.deepStrictEqual(
        results.map(r => r.delay),
        [50, 10, 30, 20, 40]
    );
    assert.strictEqual(peak, 2, 'never more than the limit in flight');
});

test('mapConcurrent() rejects with the first failure once the calls in flight have settled', async () => {
    let settled = 0;
    await assert.rejects(
        mapConcurrent([1, 2, 3, 4], 2, async item => {
            await new Promise(resolve => setTimeout(resolve, 5));
            settled++;
            if (item === 1) {
                throw new Error('first failure');
            }
        }),
        /first failure/
    );
    assert.strictEqual(settled, 2, 'the call already in flight finished, nothing new was started');
    assert.deepStrictEqual(await mapConcurrent([], 4, async () => 1), []);
});

test('assignRetryDelay', async t => {
    const { assignRetryDelay, QUICK_ASSIGN_RETRIES, SLOW_ASSIGN_RETRY_DELAY } = require('../lib/account-assignment');

    await t.test('quick retries step up first', () => {
        assert.deepStrictEqual([1, 2, 3].map(assignRetryDelay), [5000, 10000, 15000]);
    });

    await t.test('never gives up: a slow retry follows for as long as accounts stay unassigned', () => {
        for (let retry = QUICK_ASSIGN_RETRIES + 1; retry < QUICK_ASSIGN_RETRIES + 50; retry++) {
            assert.strictEqual(assignRetryDelay(retry), SLOW_ASSIGN_RETRY_DELAY);
        }
    });
});
