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
//   delete and download routes apply (DELIV-16).

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const pathlib = require('path');
const zlib = require('zlib');

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
