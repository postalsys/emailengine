'use strict';

// Which instance should own an account, and what one instance has to do about it. Pure: the
// coordinator (lib/cluster/coordinator.js) feeds it what it read from Redis and carries out the plan.
//
// Placement is rendezvous hashing over the instances that are ready to take accounts. Every
// instance computes the same answer from the same membership, and adding or removing one instance
// moves only the accounts that hash to it, about 1/N of them.
//
// Ownership itself lives in Redis (cluster:own:<account>). The plan never assumes an account is
// free: it claims only an account whose recorded owner is missing or dead, and it gives up an
// account it owns only when the instance placement prefers is ready to take it.

const { getRendezvousScore } = require('../utils/rendezvous');

/**
 * Rendezvous score of an instance for an account; the highest score wins. The same scoring that
 * ranks the IMAP workers inside an instance
 * @param {string} account
 * @param {string} instanceId
 * @returns {number}
 */
function placementScore(account, instanceId) {
    return getRendezvousScore(account, instanceId);
}

/**
 * The instance placement prefers for an account
 * @param {string} account
 * @param {string[]} candidates - Ids of the instances that take accounts, at least one
 * @returns {string|null}
 */
function desiredOwner(account, candidates) {
    let best = null;
    let bestScore = -1;
    for (const id of candidates) {
        const score = placementScore(account, id);
        // A tie (one in four billion) is broken by id, so every instance still agrees
        if (score > bestScore || (score === bestScore && id < best)) {
            best = id;
            bestScore = score;
        }
    }
    return best;
}

/**
 * Plans one ownership pass of one instance.
 *
 * @param {Object} input
 * @param {string} input.me - This instance
 * @param {string[]} input.accounts - Accounts to consider (all of them, or the ones an event named)
 * @param {Map<string, string|null>} input.owners - Recorded owner of each account
 * @param {Set<string>} input.live - Ids of every live instance, ready or not
 * @param {string[]} input.candidates - Ids of the live instances that take accounts
 * @param {Set<string>} input.held - Accounts this instance has claimed and serves
 * @param {Map<string, number>} input.unownedSince - When this instance first saw an account
 *   without a live owner that another instance should take; updated in place
 * @param {number} input.now - Milliseconds
 * @param {number} input.orphanGrace - How long an account may stay without a live owner before
 *   any instance takes it, whatever placement says
 * @param {number} input.handoffLimit - Accounts this instance may give up in one pass
 * @returns {{ claim: Array<{account: string, expected: string}>, release: Array<{account: string, to: string}>, drop: string[] }}
 *   claim: take over, provided the owner is still `expected` ('' for none);
 *   release: stop serving and clear the owner record, `to` is where it should go;
 *   drop: stop serving without touching the record, another live instance owns it
 */
function planPass(input) {
    const { me, accounts, owners, live, candidates, held, unownedSince, now, orphanGrace, handoffLimit } = input;
    const plan = { claim: [], release: [], drop: [] };

    // An instance that is not taking accounts (still starting, or leaving) plans nothing new
    const taking = candidates.includes(me);
    let handoffBudget = Math.max(0, handoffLimit || 0);

    for (const account of accounts) {
        const owner = owners.get(account) || null;
        const ownerLive = !!owner && live.has(owner);
        // Hashed only where it decides something: most accounts in a settled cluster have a live
        // owner and need no placement at all
        const desired = () => (taking ? desiredOwner(account, candidates) : null);

        if (owner === me) {
            unownedSince.delete(account);
            if (!held.has(account)) {
                // Recorded as ours by an earlier run of this instance id; claiming it again records
                // this run, which is what tells the API the account has not connected yet
                if (taking) {
                    plan.claim.push({ account, expected: me });
                }
            } else if (handoffBudget > 0) {
                const target = desired();
                if (target && target !== me) {
                    plan.release.push({ account, to: target });
                    handoffBudget--;
                }
            }
            continue;
        }

        if (ownerLive) {
            unownedSince.delete(account);
            if (held.has(account)) {
                // Another live instance holds the record: serving it here as well would sync it twice
                plan.drop.push(account);
            }
            continue;
        }

        // No owner, or an owner that is gone
        if (held.has(account)) {
            // Can only be a record removed under us (the account was deleted, or an operator
            // cleared it). Stop serving; a later pass claims it again if the account still exists
            plan.drop.push(account);
            continue;
        }

        if (!taking) {
            continue;
        }

        if (desired() === me) {
            unownedSince.delete(account);
            plan.claim.push({ account, expected: owner || '' });
            continue;
        }

        // Another instance should take it. If it does not within the grace period (it is wedged,
        // or keeps failing to claim), take it here: placement moves it on later if it recovers
        const since = unownedSince.get(account);
        if (!since) {
            unownedSince.set(account, now);
        } else if (now - since >= orphanGrace) {
            unownedSince.delete(account);
            plan.claim.push({ account, expected: owner || '' });
        }
    }

    return plan;
}

module.exports = { placementScore, desiredOwner, planPass };
