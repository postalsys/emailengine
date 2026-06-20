'use strict';

// Unit tests for lib/redis-scan-delete.js, the SCAN-based bulk deleter used by
// account deletion (and other prefix cleanups). The critical property is
// blast-radius safety: it must delete ONLY keys matching the supplied glob and
// never touch keys outside the pattern - a wrong-prefix delete here would wipe
// unrelated accounts' data. It must also report an accurate deleted-key count
// across the batched pipeline path (a mid-stream batch flush at
// REDIS_BATCH_DELETE_SIZE plus the final flush on stream end).

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const redisScanDelete = require('../lib/redis-scan-delete');
const { REDIS_BATCH_DELETE_SIZE } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Unique namespace so the test never collides with (or deletes) other keys in
// the shared test database.
const NS = `rsd-test:${crypto.randomBytes(8).toString('hex')}`;

// Silent logger stub - redisScanDelete only calls trace/error.
const logger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {}
};

async function seed(keys) {
    const pipeline = redis.pipeline();
    for (const key of keys) {
        pipeline.set(key, '1');
    }
    await pipeline.exec();
}

registerRedisTeardown(redis, async () => {
    // Best-effort cleanup of anything this test created.
    const leftover = await redis.keys(`${NS}*`);
    if (leftover.length) {
        await redis.del(...leftover);
    }
});

test('redisScanDelete', async t => {
    await t.test('deletes only keys matching the glob and leaves others intact', async () => {
        const matchKeys = [`${NS}:match:a`, `${NS}:match:b`, `${NS}:match:c`];
        const keepKeys = [`${NS}:keep:a`, `${NS}:keep:b`];
        await seed([...matchKeys, ...keepKeys]);

        const deleted = await redisScanDelete(redis, logger, `${NS}:match:*`);

        assert.strictEqual(deleted, matchKeys.length);
        for (const key of matchKeys) {
            assert.strictEqual(await redis.exists(key), 0, `${key} should be deleted`);
        }
        for (const key of keepKeys) {
            assert.strictEqual(await redis.exists(key), 1, `${key} must be preserved`);
        }

        // cleanup
        await redis.del(...keepKeys);
    });

    await t.test('returns 0 and deletes nothing when the pattern matches no keys', async () => {
        const deleted = await redisScanDelete(redis, logger, `${NS}:does-not-exist:*`);
        assert.strictEqual(deleted, 0);
    });

    await t.test('does not treat a prefix as a wildcard (exact-glob safety)', async () => {
        // A key whose name is a strict superstring of the deletion namespace of a
        // *different* account must survive. Deleting "acct:1:*" must not remove
        // "acct:10:*" keys.
        await seed([`${NS}:acct:1:x`, `${NS}:acct:1:y`, `${NS}:acct:10:x`, `${NS}:acct:100:x`]);

        const deleted = await redisScanDelete(redis, logger, `${NS}:acct:1:*`);

        assert.strictEqual(deleted, 2);
        assert.strictEqual(await redis.exists(`${NS}:acct:10:x`), 1, 'acct:10 keys must survive deleting acct:1');
        assert.strictEqual(await redis.exists(`${NS}:acct:100:x`), 1, 'acct:100 keys must survive deleting acct:1');

        await redis.del(`${NS}:acct:10:x`, `${NS}:acct:100:x`);
    });

    await t.test('counts every deleted key across the batched pipeline boundary', async () => {
        // Seed more than one batch so both the mid-stream flush (>= REDIS_BATCH_DELETE_SIZE)
        // and the trailing flush on stream end are exercised, and the count covers both.
        const total = REDIS_BATCH_DELETE_SIZE + 50;
        const keys = [];
        for (let i = 0; i < total; i++) {
            keys.push(`${NS}:batch:${i}`);
        }
        await seed(keys);

        const deleted = await redisScanDelete(redis, logger, `${NS}:batch:*`);

        assert.strictEqual(deleted, total);
        assert.strictEqual(await redis.exists(`${NS}:batch:0`), 0);
        assert.strictEqual(await redis.exists(`${NS}:batch:${total - 1}`), 0);
    });

    await t.test('rejects when the scan stream errors', async () => {
        // A redis-like stub whose scanStream emits an error must surface as a rejection.
        const fakeRedis = {
            scanStream() {
                const { Readable } = require('stream');
                const stream = new Readable({ objectMode: true, read() {} });
                process.nextTick(() => stream.emit('error', new Error('boom')));
                return stream;
            },
            pipeline() {
                return { del() {}, exec() {} };
            }
        };

        await assert.rejects(() => redisScanDelete(fakeRedis, logger, 'whatever:*'), /boom/);
    });
});
