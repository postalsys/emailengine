'use strict';

// Startup recovery of interrupted exports (Export.markInterruptedAsFailed() in lib/export.js) runs
// in every export worker as it starts, so the exports it finds may belong to a sibling worker that
// is processing them right now. It used to ignore BullMQ's refusal to remove a locked job and go on
// to fail the export, drop its pending messages and delete its file under the worker that owned
// it. These tests hold a real BullMQ lock through a real Worker, against the test Redis.
//
// No other unit test adds jobs to the export queue, so the worker here only ever fetches the job
// its own test added.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const pathlib = require('path');
const { Worker } = require('bullmq');

// Set before anything opens a connection: Export.markInterruptedAsFailed() walks the one global
// set of active exports, and another export suite running at the same time against the same
// database handled this suite's records with its own (real) queue lookup
process.env.EENGINE_REDIS_PREFIX = 'test_export_recovery';

const { redis, queueConf, exportQueue } = require('../lib/db');
const { EXPORT_LOCK_DURATION, EXPORT_STALLED_INTERVAL } = require('../lib/consts');
const logger = require('../lib/logger');
const { Export, generateExportId, getExportKey, getExportQueueKey, buildActiveEntry, ACTIVE_EXPORTS_KEY } = require('../lib/export');
const registerRedisTeardown = require('./helpers/redis-teardown');
const exitWhenStandalone = require('./helpers/exit-standalone');

const ACCOUNT = `export-ownership-${process.pid}`;
const createdKeys = new Set();
const createdEntries = new Set();
const createdJobs = new Set();

let worker;
let dir;

registerRedisTeardown(redis, async () => {
    if (worker) {
        await worker.close(true);
    }
    for (const jobId of createdJobs) {
        // A job still holding a test lock cannot be removed through BullMQ, so drop the lock first
        await redis.del(`${exportQueue.toKey(jobId)}:lock`);
        const job = await exportQueue.getJob(jobId);
        if (job) {
            await job.remove().catch(() => {});
        }
    }
    if (createdKeys.size) {
        await redis.del(...createdKeys);
    }
    for (const entry of createdEntries) {
        await redis.srem(ACTIVE_EXPORTS_KEY, entry);
    }
    if (dir) {
        await fs.promises.rm(dir, { recursive: true, force: true });
    }
});

// An export in the state the worker leaves it while it runs: a record, an active-set entry, a
// pending message and an output file. With `job`, its BullMQ job is queued too.
async function seedExport({ status = 'processing', job = true } = {}) {
    const exportId = generateExportId();
    const filePath = pathlib.join(dir, `${exportId}.ndjson.gz`);
    await fs.promises.writeFile(filePath, 'export bytes');

    const key = getExportKey(ACCOUNT, exportId);
    const queueKey = getExportQueueKey(ACCOUNT, exportId);
    createdKeys.add(key);
    createdKeys.add(queueKey);
    await redis.hset(key, { exportId, account: ACCOUNT, status, filePath, isEncrypted: '0' });
    await redis.expire(key, 600);
    await redis.zadd(queueKey, 1, 'message awaiting export');

    const entry = buildActiveEntry(ACCOUNT, exportId);
    createdEntries.add(entry);
    await redis.sadd(ACTIVE_EXPORTS_KEY, entry);

    if (job) {
        await exportQueue.add('export', { account: ACCOUNT, exportId }, { jobId: exportId });
        createdJobs.add(exportId);
    }

    return { exportId, filePath, key, queueKey };
}

async function snapshot({ exportId, filePath, key, queueKey }) {
    const job = await exportQueue.getJob(exportId);
    return {
        status: await redis.hget(key, 'status'),
        pending: await redis.zcard(queueKey),
        fileExists: fs.existsSync(filePath),
        jobState: job ? await job.getState() : null
    };
}

// Takes the next job off the export queue the way a running export worker does, holding its lock
async function takeJob(token) {
    return await worker.getNextJob(token, { block: false });
}

// Records what recovery logs, so a refused removal can be told from a successful one
function captureLogs() {
    const lines = [];
    const info = logger.info;
    logger.info = function (entry, ...rest) {
        lines.push(entry);
        return info.call(this, entry, ...rest);
    };
    return { lines, restore: () => (logger.info = info) };
}

test('Export.markInterruptedAsFailed() and live exports', async t => {
    dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-ownership-'));
    worker = new Worker('export', null, { ...queueConf, autorun: false, lockDuration: 60 * 1000 });
    worker.on('error', () => {});

    await t.test('an export a live worker holds is left to that worker', async () => {
        const seeded = await seedExport();
        const job = await takeJob('live-worker');
        assert.equal(job.id, seeded.exportId);

        const logs = captureLogs();
        try {
            await Export.markInterruptedAsFailed();
        } finally {
            logs.restore();
        }

        assert.deepEqual(await snapshot(seeded), { status: 'processing', pending: 1, fileExists: true, jobState: 'active' });
        assert.ok((await redis.pttl(`${exportQueue.toKey(seeded.exportId)}:lock`)) > 0, 'the owner still holds its lock');
        assert.ok(await redis.sismember(ACTIVE_EXPORTS_KEY, buildActiveEntry(ACCOUNT, seeded.exportId)), 'the export keeps its concurrency slot');
        assert.deepEqual(
            logs.lines.filter(line => line && line.exportId === seeded.exportId),
            [],
            'nothing is removed, so nothing is reported as removed'
        );

        await job.moveToCompleted({}, 'live-worker', false);
    });

    await t.test('a queued export a worker has just taken is not failed before it starts', async () => {
        // Its record still says queued, but the job is no longer waiting: the worker took it and
        // has not called startProcessing() yet
        const seeded = await seedExport({ status: 'queued' });
        const job = await takeJob('starting-worker');
        assert.equal(job.id, seeded.exportId);

        await Export.markInterruptedAsFailed();

        assert.deepEqual(await snapshot(seeded), { status: 'queued', pending: 1, fileExists: true, jobState: 'active' });

        await job.moveToCompleted({}, 'starting-worker', false);
    });

    await t.test('an export whose job went back to waiting is left to run again', async () => {
        // A worker died mid-export and BullMQ's stalled check put the job back in the queue before
        // this worker started. However long that took, the export runs again rather than failing
        const seeded = await seedExport();

        await Export.markInterruptedAsFailed();

        assert.deepEqual(await snapshot(seeded), { status: 'processing', pending: 1, fileExists: true, jobState: 'waiting' });

        // Taken off the queue so the tests below fetch their own job
        const job = await takeJob('drain');
        assert.equal(job.id, seeded.exportId);
        await job.moveToCompleted({}, 'drain', false);
    });

    await t.test('an export whose job is gone or finished is failed and cleaned up', async () => {
        const finished = await seedExport();
        const job = await takeJob('dead-worker');
        assert.equal(job.id, finished.exportId);
        await job.moveToFailed(new Error('worker gave up'), 'dead-worker', false);
        const jobless = await seedExport({ job: false });

        const logs = captureLogs();
        try {
            await Export.markInterruptedAsFailed();
        } finally {
            logs.restore();
        }

        assert.deepEqual(await snapshot(finished), { status: 'failed', pending: 0, fileExists: false, jobState: null });
        assert.deepEqual(await snapshot(jobless), { status: 'failed', pending: 0, fileExists: false, jobState: null });
        assert.ok(!(await redis.sismember(ACTIVE_EXPORTS_KEY, buildActiveEntry(ACCOUNT, finished.exportId))), 'the concurrency slot is released');
        assert.ok(
            logs.lines.some(line => line && line.exportId === finished.exportId && line.msg === 'Removed interrupted export job from queue'),
            'the removal is logged'
        );
    });

    await t.test('a cancelled export is cleaned up, unless a worker holds it', async () => {
        // Running a cancelled export's job would reset it to processing, so its waiting job is
        // removed; a worker already holding one sees the cancellation itself
        // removed outright rather than kept as failed: a cancelled export was asked to go
        const waiting = await seedExport({ status: 'cancelled' });
        await Export.markInterruptedAsFailed();
        assert.deepEqual(await snapshot(waiting), { status: null, pending: 0, fileExists: false, jobState: null });

        const held = await seedExport({ status: 'cancelled' });
        const job = await takeJob('cancel-holder');
        assert.equal(job.id, held.exportId);

        const logs = captureLogs();
        try {
            await Export.markInterruptedAsFailed();
        } finally {
            logs.restore();
        }

        assert.deepEqual(await snapshot(held), { status: 'cancelled', pending: 1, fileExists: true, jobState: 'active' });
        assert.deepEqual(
            logs.lines.filter(line => line && line.exportId === held.exportId).map(line => line.msg),
            ['Kept an interrupted export, its job could not be removed'],
            'a refused removal is not reported as a removal'
        );

        await job.moveToCompleted({}, 'cancel-holder', false);
    });

    await t.test('a worker that takes the job between inspection and cleanup keeps it', async () => {
        // The cancelled export's job is waiting when recovery looks it up and active by the time
        // recovery removes it. A state check before the removal would have passed; only the
        // removal itself can tell
        const seeded = await seedExport({ status: 'cancelled' });
        const getJob = exportQueue.getJob;
        let taken;
        exportQueue.getJob = async function (id) {
            const found = await getJob.call(this, id);
            if (id === seeded.exportId && !taken) {
                assert.equal(await found.getState(), 'waiting');
                taken = await takeJob('racing-worker');
            }
            return found;
        };
        try {
            await Export.markInterruptedAsFailed();
        } finally {
            exportQueue.getJob = getJob;
        }

        assert.equal(taken && taken.id, seeded.exportId);
        assert.deepEqual(await snapshot(seeded), { status: 'cancelled', pending: 1, fileExists: true, jobState: 'active' });

        await taken.moveToCompleted({}, 'racing-worker', false);
    });

    await t.test('any other removal failure keeps the export too', async () => {
        const seeded = await seedExport({ status: 'cancelled' });
        const getJob = exportQueue.getJob;
        exportQueue.getJob = async function (id) {
            const found = await getJob.call(this, id);
            if (id === seeded.exportId) {
                found.remove = async () => {
                    throw new Error('OOM command not allowed when used memory > maxmemory');
                };
            }
            return found;
        };
        try {
            await Export.markInterruptedAsFailed();
        } finally {
            exportQueue.getJob = getJob;
        }

        assert.deepEqual(await snapshot(seeded), { status: 'cancelled', pending: 1, fileExists: true, jobState: 'waiting' });

        const job = await takeJob('drain-cancelled');
        await job.moveToCompleted({}, 'drain-cancelled', false);
    });
});

test('an export left by a worker that died is run again within minutes', () => {
    // Recovery leaves an export with a live job to the queue, so how soon an export of a crashed
    // worker runs again is the lock duration plus at most one stalled check. BullMQ renews the lock every half
    // of its duration, which a check more frequent than that would not survive
    assert.ok(EXPORT_STALLED_INTERVAL <= EXPORT_LOCK_DURATION / 2, 'the stalled check runs at least as often as the lock is renewed');
    assert.ok(EXPORT_LOCK_DURATION + EXPORT_STALLED_INTERVAL <= 3 * 60 * 1000, 'about three minutes from a crash to a restart');
});

exitWhenStandalone();
