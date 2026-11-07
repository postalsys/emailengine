'use strict';

// Regression tests for the export worker's file handling and bookkeeping, against the test Redis
// db (config/test.toml -> db 13). Keys use a unique account id so a parallel run cannot collide.
//
// - openExportOutput(): the output file used to be opened before the encryption key was derived
//   and before pipeline() attached any error handling, so an open failure in that window was an
//   unlistened 'error' that crashed the export worker (ROBUST-3), and setup failures after the
//   open leaked the descriptor (WORK-11).
// - Export.queueMessage(): a retried folder counted its already-queued messages again (DELIV-19).
// - Export.markInterruptedAsFailed(): unlinked the stored filePath without the ownership check the
//   delete and download routes apply (DELIV-16), and failed queued exports whose job still waited.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const pathlib = require('path');
const zlib = require('zlib');

// Set before anything opens a connection: Export.markInterruptedAsFailed() walks the one global
// set of active exports, and another export suite running at the same time against the same
// database handled this suite's records with its own (real) queue lookup
process.env.EENGINE_REDIS_PREFIX = 'test_export_robustness';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { Export, openExportOutput, generateExportId, getExportKey, getExportQueueKey, buildActiveEntry, ACTIVE_EXPORTS_KEY } = require('../lib/export');
const registerRedisTeardown = require('./helpers/redis-teardown');

const ACCOUNT = `export-robustness-${process.pid}`;
const createdKeys = new Set();
const createdEntries = new Set();

registerRedisTeardown(redis, async () => {
    if (createdKeys.size) {
        await redis.del(...createdKeys);
    }
    for (const entry of createdEntries) {
        await redis.srem(ACTIVE_EXPORTS_KEY, entry);
    }
});

test('openExportOutput()', async t => {
    await t.test('an unwritable path is reported as a stream error, not an uncaught one', async () => {
        const uncaught = [];
        const onUncaught = err => uncaught.push(err);
        process.on('uncaughtException', onUncaught);
        try {
            const missingDir = pathlib.join(os.tmpdir(), `ee-export-missing-${process.pid}-${Date.now()}`);
            // Encrypted, so the key derivation runs; the file must not be open while it does
            const output = await openExportOutput(pathlib.join(missingDir, 'out.ndjson.gz.enc'), 'test-secret');

            await new Promise(resolve => setTimeout(resolve, 50));

            assert.deepStrictEqual(uncaught, [], 'nothing reaches the global handler');
            assert.ok(output.error(), 'the open failure is recorded');
            assert.strictEqual(output.error().code, 'ENOENT');
        } finally {
            process.removeListener('uncaughtException', onUncaught);
        }
    });

    await t.test('writes a readable gzip file and destroy() releases the descriptor', async () => {
        const dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-out-'));
        try {
            const filePath = pathlib.join(dir, 'out.ndjson.gz');
            const output = await openExportOutput(filePath, null);
            output.input.end('{"a":1}\n');
            await new Promise((resolve, reject) => {
                output.output.once('finish', resolve);
                output.output.once('error', reject);
            });
            assert.strictEqual(zlib.gunzipSync(await fs.promises.readFile(filePath)).toString(), '{"a":1}\n');

            // An early exit before anything was written closes the file too
            const abandoned = await openExportOutput(pathlib.join(dir, 'abandoned.ndjson.gz'), null);
            await new Promise(resolve => abandoned.output.once('open', resolve));
            abandoned.destroy();
            await new Promise(resolve => abandoned.output.once('close', resolve));
            assert.strictEqual(abandoned.output.closed, true);
        } finally {
            await fs.promises.rm(dir, { recursive: true, force: true });
        }
    });
});

test('Export.queueMessage() counts a message once when its folder is retried', async () => {
    const exportId = generateExportId();
    const exportKey = getExportKey(ACCOUNT, exportId);
    createdKeys.add(exportKey);
    createdKeys.add(getExportQueueKey(ACCOUNT, exportId));

    await redis.hset(exportKey, { exportId, account: ACCOUNT, messagesQueued: 0 });
    await redis.expire(exportKey, 600);

    const message = { folder: 'INBOX', messageId: 'msg-1', uid: 1, size: 10, date: Date.now() };

    assert.strictEqual(await Export.queueMessage(ACCOUNT, exportId, message), true);
    // The retry of a folder whose first attempt failed after queueing this message
    assert.strictEqual(await Export.queueMessage(ACCOUNT, exportId, message), false);
    await Export.queueMessage(ACCOUNT, exportId, Object.assign({}, message, { messageId: 'msg-2', uid: 2 }));

    assert.strictEqual(await redis.hget(exportKey, 'messagesQueued'), '2');
    assert.strictEqual(await redis.zcard(getExportQueueKey(ACCOUNT, exportId)), 2);
});

test('Export.queueMessages() queues a page in one pipeline with the same counting', async () => {
    const exportId = generateExportId();
    const exportKey = getExportKey(ACCOUNT, exportId);
    createdKeys.add(exportKey);
    createdKeys.add(getExportQueueKey(ACCOUNT, exportId));

    await redis.hset(exportKey, { exportId, account: ACCOUNT, messagesQueued: 0 });
    await redis.expire(exportKey, 600);

    const page = Array.from({ length: 50 }, (v, i) => ({ folder: 'INBOX', messageId: `msg-${i}`, uid: i + 1, size: 10, date: Date.now() }));

    assert.strictEqual(await Export.queueMessages(ACCOUNT, exportId, page), 50);
    // a retried folder queues the same page again, and only new members count
    assert.strictEqual(
        await Export.queueMessages(ACCOUNT, exportId, page.slice(40).concat({ folder: 'INBOX', messageId: 'msg-new', uid: 99, date: Date.now() })),
        1
    );
    assert.strictEqual(await Export.queueMessages(ACCOUNT, exportId, []), 0);

    assert.strictEqual(await redis.hget(exportKey, 'messagesQueued'), '51');
    assert.strictEqual(await redis.zcard(getExportQueueKey(ACCOUNT, exportId)), 51);
    assert.ok((await redis.pttl(getExportQueueKey(ACCOUNT, exportId))) > 0, 'the queue takes the record expiry');
});

test('Export.incrementCounters() adds a batch of progress at once', async () => {
    const exportId = generateExportId();
    const exportKey = getExportKey(ACCOUNT, exportId);
    createdKeys.add(exportKey);

    await redis.hset(exportKey, { exportId, account: ACCOUNT, messagesExported: 2, bytesWritten: 100, messagesSkipped: 1 });
    await Export.incrementCounters(ACCOUNT, exportId, { exported: 3, bytesWritten: 250, skipped: 2 });
    await Export.incrementCounters(ACCOUNT, exportId, { exported: 0, bytesWritten: 0, skipped: 0 });

    assert.deepStrictEqual(await redis.hmget(exportKey, 'messagesExported', 'bytesWritten', 'messagesSkipped'), ['5', '350', '3']);
});

test('Export.markInterruptedAsFailed() unlinks only the export file itself', async () => {
    const dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-recovery-'));
    try {
        const own = generateExportId();
        const ownPath = pathlib.join(dir, `${own}.ndjson.gz`);
        await fs.promises.writeFile(ownPath, 'own');

        const foreign = generateExportId();
        const foreignPath = pathlib.join(dir, 'not-an-export.txt');
        await fs.promises.writeFile(foreignPath, 'keep');

        for (const [exportId, filePath] of [
            [own, ownPath],
            [foreign, foreignPath]
        ]) {
            const key = getExportKey(ACCOUNT, exportId);
            createdKeys.add(key);
            createdKeys.add(getExportQueueKey(ACCOUNT, exportId));
            await redis.hset(key, { exportId, account: ACCOUNT, status: 'processing', filePath });
            await redis.expire(key, 600);
            const entry = buildActiveEntry(ACCOUNT, exportId);
            createdEntries.add(entry);
            await redis.sadd(ACTIVE_EXPORTS_KEY, entry);
        }

        await Export.markInterruptedAsFailed();

        await assert.rejects(fs.promises.access(ownPath), 'the interrupted export file is removed');
        assert.strictEqual(await fs.promises.readFile(foreignPath, 'utf8'), 'keep', 'a foreign stored path is left alone');
        assert.strictEqual(await redis.hget(getExportKey(ACCOUNT, foreign), 'status'), 'failed', 'the record is still failed');
    } finally {
        await fs.promises.rm(dir, { recursive: true, force: true });
    }
});

test('Export.markInterruptedAsFailed() leaves a queued export whose job is still waiting', async () => {
    // A restart used to fail every export that had not started yet, although its job was still in
    // the queue and the export worker would have run it
    const { exportQueue } = require('../lib/db');
    const getJob = exportQueue.getJob;
    const states = new Map();
    const removed = new Set();
    exportQueue.getJob = async id =>
        states.has(id)
            ? {
                  getState: async () => states.get(id),
                  remove: async () => {
                      removed.add(id);
                  }
              }
            : null;
    try {
        const exports = {};
        for (const [name, status, state] of [
            ['waiting', 'queued', 'waiting'],
            ['delayed', 'queued', 'delayed'],
            ['jobFailed', 'queued', 'failed'],
            ['jobless', 'queued', null],
            ['processing', 'processing', 'waiting']
        ]) {
            const exportId = generateExportId();
            if (state) {
                states.set(exportId, state);
            }
            const key = getExportKey(ACCOUNT, exportId);
            createdKeys.add(key);
            createdKeys.add(getExportQueueKey(ACCOUNT, exportId));
            await redis.hset(key, { exportId, account: ACCOUNT, status });
            await redis.expire(key, 600);
            const entry = buildActiveEntry(ACCOUNT, exportId);
            createdEntries.add(entry);
            await redis.sadd(ACTIVE_EXPORTS_KEY, entry);
            exports[name] = exportId;
        }

        await Export.markInterruptedAsFailed();

        for (const name of ['waiting', 'delayed']) {
            assert.strictEqual(await redis.hget(getExportKey(ACCOUNT, exports[name]), 'status'), 'queued', `${name}: left for the export worker`);
            assert.ok(!removed.has(exports[name]), `${name}: its job stays in the queue`);
        }
        for (const name of ['jobFailed', 'jobless']) {
            assert.strictEqual(await redis.hget(getExportKey(ACCOUNT, exports[name]), 'status'), 'failed', `${name}: failed as before`);
        }
        assert.ok(removed.has(exports.jobFailed), 'a finished job is removed with its export');
        // A processing export whose job is back in the queue (a stalled-job check) runs again
        // rather than failing (test/export-recovery-ownership-test.js has the live cases)
        assert.strictEqual(await redis.hget(getExportKey(ACCOUNT, exports.processing), 'status'), 'processing');
        assert.ok(!removed.has(exports.processing));
    } finally {
        exportQueue.getJob = getJob;
        // The exports left queued would otherwise count against the account in the tests below
        for (const entry of createdEntries) {
            await redis.srem(ACTIVE_EXPORTS_KEY, entry);
        }
    }
});

test('Export.create() gives the concurrency slot back when a step after taking it fails', async () => {
    // Only a failed queue add released the slot. An unwritable export path failed earlier and left
    // an entry in the active set on every attempt, so the account's exports answered 429 until the
    // sweeper caught up.
    const accountKey = `${REDIS_PREFIX}iad:${ACCOUNT}`;
    createdKeys.add(accountKey);
    await redis.hset(accountKey, 'account', ACCOUNT);

    const dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-create-'));
    const blocker = pathlib.join(dir, 'not-a-directory');
    await fs.promises.writeFile(blocker, 'x');

    const previous = process.env.EENGINE_EXPORT_PATH;
    process.env.EENGINE_EXPORT_PATH = pathlib.join(blocker, 'exports');
    try {
        await assert.rejects(Export.create(ACCOUNT, { folders: ['INBOX'], startDate: Date.now() - 1000, endDate: Date.now() }));

        const members = await redis.smembers(ACTIVE_EXPORTS_KEY);
        assert.deepStrictEqual(
            members.filter(entry => entry.startsWith(`${ACCOUNT}:`)),
            [],
            'no active entry is left behind for the account'
        );
    } finally {
        if (previous === undefined) {
            delete process.env.EENGINE_EXPORT_PATH;
        } else {
            process.env.EENGINE_EXPORT_PATH = previous;
        }
        await fs.promises.rm(dir, { recursive: true, force: true });
    }
});

// Account deletion and the export listing find an account's exports through a per-account index
// instead of a scan of the whole keyspace, so creating and deleting an export has to keep it current
test('Export.create() adds the export to the account index and Export.delete() removes it', async () => {
    const { getExportIndexKey } = require('../lib/export');
    const accountKey = `${REDIS_PREFIX}iad:${ACCOUNT}`;
    createdKeys.add(accountKey);
    createdKeys.add(getExportIndexKey(ACCOUNT));
    await redis.hset(accountKey, 'account', ACCOUNT);

    const dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-index-'));
    const previous = process.env.EENGINE_EXPORT_PATH;
    process.env.EENGINE_EXPORT_PATH = dir;
    let created;
    try {
        created = await Export.create(ACCOUNT, { folders: ['INBOX'], startDate: Date.now() - 1000, endDate: Date.now() });
        createdKeys.add(getExportKey(ACCOUNT, created.exportId));
        createdKeys.add(getExportQueueKey(ACCOUNT, created.exportId));
        assert.deepStrictEqual(await redis.smembers(getExportIndexKey(ACCOUNT)), [created.exportId]);
        // no expiry of its own: an export's retention restarts when it completes, and an index that
        // expired with it first dropped an export that outlived it from account deletion
        assert.strictEqual(await redis.ttl(getExportIndexKey(ACCOUNT)), -1);

        // ids of records that expired are pruned when the index is read
        await redis.sadd(getExportIndexKey(ACCOUNT), 'exp_expired000000000000000');
        await Export.list(ACCOUNT);
        assert.strictEqual(await redis.sismember(getExportIndexKey(ACCOUNT), 'exp_expired000000000000000'), 0);

        assert.strictEqual(await Export.delete(ACCOUNT, created.exportId), true);
        assert.deepStrictEqual(await redis.smembers(getExportIndexKey(ACCOUNT)), []);
    } finally {
        if (previous === undefined) {
            delete process.env.EENGINE_EXPORT_PATH;
        } else {
            process.env.EENGINE_EXPORT_PATH = previous;
        }
        if (created) {
            await redis.srem(ACTIVE_EXPORTS_KEY, buildActiveEntry(ACCOUNT, created.exportId));
        }
        await fs.promises.rm(dir, { recursive: true, force: true });
    }
});

// Deleting a running export only marks it cancelled. A worker past its last cancellation check used
// to finish it through complete() or fail(), and a restart turned it into a failed export, so the
// record and the file of an export that was asked to go stayed for the whole retention window.
for (const finish of ['complete', 'fail']) {
    test(`a cancelled export that reaches ${finish}() is removed with its file and index entry`, async () => {
        const { getExportIndexKey, exportFilePath } = require('../lib/export');
        const exportId = generateExportId();
        const dir = await fs.promises.mkdtemp(pathlib.join(os.tmpdir(), 'ee-export-cancelled-'));
        const filePath = exportFilePath(exportId, { filePath: pathlib.join(dir, 'placeholder') });
        await fs.promises.writeFile(filePath, 'partial archive');
        createdKeys.add(getExportKey(ACCOUNT, exportId));
        createdKeys.add(getExportIndexKey(ACCOUNT));
        await redis.hmset(getExportKey(ACCOUNT, exportId), { exportId, account: ACCOUNT, status: 'cancelled', filePath });
        await redis.sadd(getExportIndexKey(ACCOUNT), exportId);
        try {
            if (finish === 'complete') {
                await Export.complete(ACCOUNT, exportId);
            } else {
                await Export.fail(ACCOUNT, exportId, 'boom');
            }
            assert.strictEqual(await redis.exists(getExportKey(ACCOUNT, exportId)), 0);
            assert.strictEqual(fs.existsSync(filePath), false);
            assert.strictEqual(await redis.sismember(getExportIndexKey(ACCOUNT), exportId), 0);
        } finally {
            await fs.promises.rm(dir, { recursive: true, force: true });
        }
    });
}

test('an export that was not cancelled still completes', async () => {
    const exportId = generateExportId();
    createdKeys.add(getExportKey(ACCOUNT, exportId));
    await redis.hmset(getExportKey(ACCOUNT, exportId), { exportId, account: ACCOUNT, status: 'processing' });
    await Export.complete(ACCOUNT, exportId);
    assert.strictEqual(await redis.hget(getExportKey(ACCOUNT, exportId), 'status'), 'completed');
});
