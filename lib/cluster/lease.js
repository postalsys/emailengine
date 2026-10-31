'use strict';

// The ownership lease as the worker threads see it.
//
// An instance owns its accounts only while its heartbeat in Redis is alive. The main thread renews
// the heartbeat; the IMAP workers have no Redis view of it, so the main thread publishes the
// result in shared memory: until when the lease is known to hold, and a generation that moves
// whenever the instance has lost it (fenced) and given its accounts up.
//
// A worker about to announce something (a webhook) checks the lease first. A process that was
// frozen or stalled past its heartbeat may have lost its accounts to another instance in the
// meantime, and its workers run on as soon as it is thawed. They wait for the main thread to
// renew: a renewal that succeeds proves the heartbeat never expired, so nobody took over and the
// announcement goes out; a fence means another instance owns the account now and announces it
// itself, so the worker drops it rather than send a second copy.
//
// Times are on the process's monotonic clock (performance.timeOrigin + performance.now(), the
// same in every thread of a process), so a wall clock step cannot extend a lease.

const SLOT_VALID_UNTIL = 0;
const SLOT_GENERATION = 1;

let workerLease = null;

function monotonicNow() {
    return Math.floor(performance.timeOrigin + performance.now());
}

/** A new lease, for the main thread to hand to its workers */
function createLeaseBuffer() {
    return new SharedArrayBuffer(BigInt64Array.BYTES_PER_ELEMENT * 2);
}

class LeaseView {
    constructor(buffer) {
        this.slots = new BigInt64Array(buffer);
    }

    validUntil() {
        return Number(Atomics.load(this.slots, SLOT_VALID_UNTIL));
    }

    generation() {
        return Number(Atomics.load(this.slots, SLOT_GENERATION));
    }

    isValid(now = monotonicNow()) {
        return now < this.validUntil();
    }

    // Writers (main thread only)

    extend(validUntil) {
        Atomics.store(this.slots, SLOT_VALID_UNTIL, BigInt(Math.floor(validUntil)));
    }

    revoke() {
        Atomics.store(this.slots, SLOT_VALID_UNTIL, 0n);
        Atomics.add(this.slots, SLOT_GENERATION, 1n);
    }
}

/**
 * Waits until the lease holds. Resolves true when it does (at once, normally), false when the
 * instance was fenced while waiting or nothing was decided within `timeout`
 * @param {LeaseView|null} view - null when no lease applies (a worker outside the cluster)
 * @param {Object} [opts]
 * @param {number} [opts.timeout]
 * @param {number} [opts.interval]
 * @returns {Promise<boolean>}
 */
async function waitForLease(view, { timeout = 30000, interval = 50 } = {}) {
    if (!view || view.isValid()) {
        return true;
    }
    const generation = view.generation();
    const deadline = monotonicNow() + timeout;
    while (monotonicNow() < deadline) {
        await new Promise(resolve => setTimeout(resolve, interval));
        if (view.generation() !== generation) {
            return false;
        }
        if (view.isValid()) {
            return true;
        }
    }
    return false;
}

/** Called once by a worker thread with the buffer from its workerData */
function setWorkerLease(buffer) {
    workerLease = buffer ? new LeaseView(buffer) : null;
}

/** The lease of this worker thread, null when it has none */
function getWorkerLease() {
    return workerLease;
}

module.exports = { createLeaseBuffer, LeaseView, waitForLease, setWorkerLease, getWorkerLease, monotonicNow };
