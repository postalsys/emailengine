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

/**
 * Drops every record of a deleted account: from unassigned, from `assigned`, and from the account
 * set of the worker that held it. Leaving it in `assigned` kept a deleted account routed to a
 * worker (possibly an exited one) for the life of the process and inflated the per-worker target
 * of every later assignment pass
 * @param {Object} state - `workerAssigned`, `assigned` and `unassigned` (false before the first load)
 * @param {string} account
 * @returns {Object|null} The worker that held the account, for the cleanup call, or null
 */
function forgetAccount({ workerAssigned, assigned, unassigned }, account) {
    if (unassigned) {
        unassigned.delete(account);
    }
    if (!assigned.has(account)) {
        return null;
    }
    const worker = assigned.get(account);
    assigned.delete(account);
    const accounts = workerAssigned.get(worker);
    if (accounts) {
        accounts.delete(account);
        if (!accounts.size) {
            workerAssigned.delete(worker);
        }
    }
    return worker;
}

/**
 * Whether an account whose `assign` call failed goes back to unassigned. An account that no longer
 * exists fails deterministically on every pass, so it is dropped instead: either the worker said so
 * (404), or the account is no longer registered, which also covers a delete that raced the pass.
 * A failed membership check keeps the account, a lost retry costs more than a wasted one
 * @param {Error} err - The error the assign call failed with
 * @param {string} account
 * @param {Function} isRegistered - async account -> boolean
 * @returns {Promise<boolean>}
 */
async function shouldRequeueFailedAssignment(err, account, isRegistered) {
    if (err && err.statusCode === 404) {
        return false;
    }
    try {
        return !!(await isRegistered(account));
    } catch {
        return true;
    }
}

/**
 * Picks accounts to move onto a worker that joined after the fleet was already serving them (a
 * worker that restarted after the failsafe reassignment gave its accounts to the survivors).
 * Takes from the most loaded workers until the newcomer holds its fair share
 * @param {Object} state - `workerAssigned` and `availableWorkers`
 * @param {Object} targetWorker - The worker that joined
 * @returns {Array<{account: string, worker: Object}>} Accounts to move, with their current worker
 */
function planRebalance({ workerAssigned, availableWorkers }, targetWorker) {
    const loads = new Map();
    let total = 0;
    for (const worker of availableWorkers) {
        const size = workerAssigned.get(worker)?.size || 0;
        loads.set(worker, size);
        total += size;
    }
    if (!loads.has(targetWorker) || loads.size < 2) {
        return [];
    }

    const share = Math.floor(total / loads.size);
    const taken = new Map();
    const moves = [];
    while (loads.get(targetWorker) < share) {
        let donor = null;
        for (const [worker, size] of loads) {
            if (worker !== targetWorker && (!donor || size > loads.get(donor))) {
                donor = worker;
            }
        }
        // Stop once moving an account would only shift the imbalance to the donor
        if (!donor || loads.get(donor) - 1 < loads.get(targetWorker) + 1) {
            break;
        }
        if (!taken.has(donor)) {
            taken.set(donor, workerAssigned.get(donor).values());
        }
        const next = taken.get(donor).next();
        if (next.done) {
            break;
        }
        moves.push({ account: next.value, worker: donor });
        loads.set(donor, loads.get(donor) - 1);
        loads.set(targetWorker, loads.get(targetWorker) + 1);
    }
    return moves;
}

/**
 * Runs `fn` over `items` with at most `limit` calls in flight and resolves with the results in
 * item order once every call has settled. Rejects with the first failure, like Promise.all, but
 * only after the calls already in flight have settled, so a caller never has calls outstanding
 * it does not know about
 * @param {Array} items
 * @param {number} limit - Calls in flight at once
 * @param {Function} fn - async (item, index) -> result
 * @returns {Promise<Array>}
 */
async function mapConcurrent(items, limit, fn) {
    const results = new Array(items.length);
    let next = 0;
    let failure = null;
    const runner = async () => {
        while (next < items.length && !failure) {
            const index = next++;
            try {
                results[index] = await fn(items[index], index);
            } catch (err) {
                failure = failure || err;
            }
        }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, runner));
    if (failure) {
        throw failure;
    }
    return results;
}

module.exports = {
    pickLeastLoadedWorker,
    rollbackAssignment,
    releaseWorkerAccounts,
    requeueFailedAccounts,
    forgetAccount,
    shouldRequeueFailedAssignment,
    planRebalance,
    mapConcurrent
};
