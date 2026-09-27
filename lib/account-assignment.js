'use strict';

// Bookkeeping shared by assignAccounts() and the IMAP worker exit handler in server.js, kept apart
// so a worker exiting in the middle of an assignment pass can be tested without the main thread.
// The exit handler runs while a pass is awaiting a worker, so the pass cannot assume a worker it
// picked, or that worker's account set, still exists.

/**
 * The least loaded running worker below `targetPerWorker`, else the least loaded running one
 * @param {Set<Object>} availableWorkers
 * @param {Map<Object, number>} workerLoadMap - worker -> accounts counted in this pass
 * @param {number} targetPerWorker
 * @returns {Object|undefined}
 */
function pickLeastLoadedWorker(availableWorkers, workerLoadMap, targetPerWorker) {
    const byLoad = Array.from(availableWorkers).sort((a, b) => (workerLoadMap.get(a) || 0) - (workerLoadMap.get(b) || 0));
    return byLoad.find(worker => (workerLoadMap.get(worker) || 0) < targetPerWorker) || byLoad[0];
}

/**
 * Undoes the bookkeeping for an account whose `assign` call failed. The worker's account set is
 * already gone when the worker exited while the call was in flight
 * @param {Object} state - `workerAssigned`, `assigned` and `workerLoadMap`
 * @param {string} account
 * @param {Object} worker
 * @param {boolean} countedLoad - Whether the account was counted in workerLoadMap
 */
function rollbackAssignment({ workerAssigned, assigned, workerLoadMap }, account, worker, countedLoad) {
    workerAssigned.get(worker)?.delete(account);
    assigned.delete(account);
    if (countedLoad) {
        workerLoadMap.set(worker, workerLoadMap.get(worker) - 1);
    }
}

/**
 * Moves the accounts of an exited worker back to unassigned
 * @param {Object} state - `workerAssigned`, `assigned` and `unassigned`
 * @param {Object} worker
 * @returns {Set<string>|null} The accounts released, null when the worker had none tracked
 */
function releaseWorkerAccounts({ workerAssigned, assigned, unassigned }, worker) {
    const accounts = workerAssigned.get(worker);
    if (!accounts) {
        return null;
    }
    workerAssigned.delete(worker);
    for (const account of accounts) {
        assigned.delete(account);
        unassigned.add(account);
    }
    return accounts;
}

/**
 * Returns the accounts that failed in a pass to unassigned, except the ones assigned since: the
 * exit handler requeues an account whose worker exited mid-call, and the same pass can pick it up
 * again from there
 * @param {Object} state - `assigned` and `unassigned`
 * @param {string[]} failedAccounts
 */
function requeueFailedAccounts({ assigned, unassigned }, failedAccounts) {
    for (const account of failedAccounts) {
        if (!assigned.has(account)) {
            unassigned.add(account);
        }
    }
}

module.exports = { pickLeastLoadedWorker, rollbackAssignment, releaseWorkerAccounts, requeueFailedAccounts };
