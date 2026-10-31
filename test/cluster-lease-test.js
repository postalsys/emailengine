'use strict';

// The ownership lease the main thread shares with its workers (lib/cluster/lease.js). A worker
// announces an event only while the lease holds, waits while the main thread renews it, and drops
// the event once the instance was fenced.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Worker } = require('node:worker_threads');

const { createLeaseBuffer, LeaseView, waitForLease, monotonicNow } = require('../lib/cluster/lease');

test('LeaseView', async t => {
    await t.test('a new lease is not valid until extended', () => {
        const lease = new LeaseView(createLeaseBuffer());
        assert.equal(lease.isValid(), false);
        lease.extend(monotonicNow() + 1000);
        assert.equal(lease.isValid(), true);
    });

    await t.test('expires on its own', () => {
        const lease = new LeaseView(createLeaseBuffer());
        const now = monotonicNow();
        lease.extend(now + 100);
        assert.equal(lease.isValid(now + 99), true);
        assert.equal(lease.isValid(now + 100), false);
    });

    await t.test('revoke() ends it and moves the generation', () => {
        const lease = new LeaseView(createLeaseBuffer());
        lease.extend(monotonicNow() + 10000);
        const generation = lease.generation();
        lease.revoke();
        assert.equal(lease.isValid(), false);
        assert.equal(lease.generation(), generation + 1);
    });
});

test('waitForLease()', async t => {
    await t.test('resolves at once without a lease (a worker outside the cluster)', async () => {
        assert.equal(await waitForLease(null), true);
    });

    await t.test('resolves at once while the lease holds', async () => {
        const lease = new LeaseView(createLeaseBuffer());
        lease.extend(monotonicNow() + 10000);
        assert.equal(await waitForLease(lease, { timeout: 10 }), true);
    });

    await t.test('waits for a renewal and then goes ahead', async () => {
        const lease = new LeaseView(createLeaseBuffer());
        setTimeout(() => lease.extend(monotonicNow() + 10000), 60);
        const started = Date.now();
        assert.equal(await waitForLease(lease, { timeout: 2000, interval: 10 }), true);
        assert.ok(Date.now() - started >= 50);
    });

    await t.test('gives up when the instance is fenced while it waits', async () => {
        const lease = new LeaseView(createLeaseBuffer());
        setTimeout(() => {
            lease.revoke();
            // A later registration extends the lease again, but the event belongs to the lost run
            lease.extend(monotonicNow() + 10000);
        }, 40);
        assert.equal(await waitForLease(lease, { timeout: 2000, interval: 10 }), false);
    });

    await t.test('a suspended lease holds announcements and lets them go once extended again', async () => {
        const lease = new LeaseView(createLeaseBuffer());
        lease.extend(monotonicNow() + 10000);
        lease.suspend();
        setTimeout(() => lease.extend(monotonicNow() + 10000), 40);
        assert.equal(await waitForLease(lease, { timeout: 2000, interval: 10 }), true);
    });

    await t.test('gives up when nothing is decided in time', async () => {
        const lease = new LeaseView(createLeaseBuffer());
        assert.equal(await waitForLease(lease, { timeout: 50, interval: 10 }), false);
    });
});

test('a worker thread sees what the main thread writes', async () => {
    const buffer = createLeaseBuffer();
    const lease = new LeaseView(buffer);
    const worker = new Worker(
        `
        const { workerData, parentPort } = require('node:worker_threads');
        const { setWorkerLease, getWorkerLease, waitForLease } = require(${JSON.stringify(require.resolve('../lib/cluster/lease'))});
        setWorkerLease(workerData.buffer);
        parentPort.postMessage('waiting');
        waitForLease(getWorkerLease(), { timeout: 5000, interval: 10 }).then(result => parentPort.postMessage(result));
        `,
        { eval: true, workerData: { buffer } }
    );
    const messages = [];
    const done = new Promise((resolve, reject) => {
        worker.on('message', message => {
            messages.push(message);
            if (message === 'waiting') {
                setTimeout(() => lease.extend(monotonicNow() + 10000), 50);
            } else {
                resolve();
            }
        });
        worker.on('error', reject);
    });
    await done;
    await worker.terminate();
    assert.deepEqual(messages, ['waiting', true]);
});
