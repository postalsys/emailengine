'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// Gives a test's stand-in lock a withLock() that behaves like ioredfour's: acquire through the
// fake's own waitAcquireLock() (or acquireLock() for { wait: false }), reject with an
// ELOCKNOTACQUIRED error when that answers success: false, run the function, release in every case
// and never let a failed release change the result. Tests keep scripting acquisition the way they
// did, and code that moved to withLock() still goes through what they script.

function withFakeWithLock(lock) {
    lock.withLock = async (id, ttl, waitTtl, fn, opts) => {
        const held = opts && opts.wait === false ? await lock.acquireLock(id, ttl) : await lock.waitAcquireLock(id, ttl, waitTtl);
        if (!held || !held.success) {
            const err = new Error('Lock is held by someone else');
            err.code = 'ELOCKNOTACQUIRED';
            throw err;
        }
        try {
            return await fn(held, new AbortController().signal);
        } finally {
            try {
                await lock.releaseLock(held);
            } catch (err) {
                // the lock expires on its own
            }
        }
    };
    return lock;
}

module.exports = { withFakeWithLock };
