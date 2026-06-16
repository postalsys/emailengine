'use strict';

// Unit tests for BaseClient idempotency-key handling - the mechanism that
// prevents duplicate message submissions (X-EE-Idempotency-Key / Idempotency-Key)
// across workers (lib/email-client/base-client.js). A regression causes either
// duplicate sends or false "HIT" cache returns. checkIdempotencyKey /
// updateIdempotencyData / clearIdempotencyData only use this.redis,
// this.runIndex and this.logger, so they are driven through the prototype with a
// fake receiver and the real test Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {} };
const ctx = { redis, runIndex: 1, logger: noopLogger };

const check = (objName, key) => BaseClient.prototype.checkIdempotencyKey.call(ctx, objName, key);
const update = (data, result) => BaseClient.prototype.updateIdempotencyData.call(ctx, data, result);
const clear = (data, err) => BaseClient.prototype.clearIdempotencyData.call(ctx, data, err);

// Unique key per test run so reruns against the same Redis do not collide.
let counter = 0;
const uniqueKey = () => `idem-test-${process.pid}-${counter++}`;

test.after(async () => {
    try {
        const keys = await redis.keys(`${REDIS_PREFIX}idempotency:bucket:*`);
        if (keys.length) {
            await redis.del(keys);
        }
    } catch (err) {
        // ignore
    }
    try {
        await redis.quit();
    } catch (err) {
        // ignore
    }
});

test('BaseClient idempotency handling', async t => {
    await t.test('returns null when no idempotency key is provided', async () => {
        assert.strictEqual(await check('messages', null), null);
        assert.strictEqual(await check('messages', ''), null);
    });

    await t.test('first use of a key is reported as new', async () => {
        const data = await check('messages', uniqueKey());
        assert.ok(data);
        assert.strictEqual(data.status, 'new');
        assert.ok(data.bucketKey, 'a new entry records its bucket key');
    });

    await t.test('a completed operation returns a cached HIT on the second check', async () => {
        const key = uniqueKey();

        const first = await check('messages', key);
        assert.strictEqual(first.status, 'new');

        await update(first, { messageId: 'msg-42', queued: true });

        const second = await check('messages', key);
        assert.strictEqual(second.status, 'completed');
        assert.ok(second.returnValue, 'a completed entry exposes the cached return value');
        assert.strictEqual(second.returnValue.messageId, 'msg-42');
        assert.strictEqual(second.returnValue.queued, true);
        assert.deepStrictEqual(second.returnValue.idempotency, { key, status: 'HIT' });
    });

    await t.test('clearing a failed first attempt lets the key be retried as new', async () => {
        const key = uniqueKey();

        const first = await check('messages', key);
        assert.strictEqual(first.status, 'new');

        // Simulate the operation failing before completion.
        await clear(first, new Error('send failed'));

        // The next attempt must start fresh (not a HIT / not stuck pending).
        const retry = await check('messages', key);
        assert.strictEqual(retry.status, 'new');
    });

    await t.test('namespacing keeps the same key separate across object types', async () => {
        const key = uniqueKey();

        const messagesEntry = await check('messages', key);
        await update(messagesEntry, { scope: 'messages' });

        // Same raw key under a different object namespace must be independent.
        const outboxEntry = await check('outbox', key);
        assert.strictEqual(outboxEntry.status, 'new', 'a different namespace is a different idempotency entry');
    });
});
