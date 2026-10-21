'use strict';

// lib/lock-run.js: every lock in lib/ goes through ioredfour's withLock() by way of runLocked(),
// which only adds what a site does when the lock is not there to take. Against a real lock in the
// test Redis, and a guardrail that keeps lock handling in that one place.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('crypto');
const Lock = require('ioredfour');

const { redis } = require('../lib/db');
const { runLocked, refuseUnavailableLock } = require('../lib/lock-run');
const { createMockLogger } = require('./helpers/mock-logger');
const { listFiles } = require('./helpers/list-files');
const registerRedisTeardown = require('./helpers/redis-teardown');

const lock = new Lock({ redis, namespace: `lock-run-test:${crypto.randomBytes(4).toString('hex')}` });
registerRedisTeardown(redis);

const id = () => `id-${crypto.randomBytes(4).toString('hex')}`;

test('runLocked()', async t => {
    await t.test('runs the section under the lock and releases it', async () => {
        const key = id();
        const result = await runLocked(
            lock,
            key,
            10000,
            1000,
            async held => {
                assert.ok(held.success);
                // the lock is really held meanwhile
                const other = await lock.acquireLock(key, 1000);
                assert.strictEqual(other.success, false);
                return 'done';
            },
            () => assert.fail('the lock was free')
        );
        assert.strictEqual(result, 'done');
        assert.strictEqual((await lock.acquireLock(key, 1000)).success, true, 'released');
    });

    await t.test('a lock someone else holds goes to onUnavailable, without waiting when waitTtl is null', async () => {
        const key = id();
        const holder = await lock.acquireLock(key, 10000);
        let ran = false;
        const started = Date.now();
        const answer = await runLocked(
            lock,
            key,
            10000,
            null,
            async () => {
                ran = true;
            },
            err => `unavailable:${err.code}`
        );
        assert.strictEqual(answer, 'unavailable:ELOCKNOTACQUIRED');
        assert.strictEqual(ran, false);
        assert.ok(Date.now() - started < 1000);
        await lock.releaseLock(holder);
    });

    await t.test('a failure of the section itself is not taken for an unavailable lock', async () => {
        const failure = new Error('section failed');
        await assert.rejects(
            runLocked(
                lock,
                id(),
                10000,
                1000,
                async () => {
                    throw failure;
                },
                () => 'should not be called'
            ),
            err => err === failure
        );
    });

    await t.test('refuseUnavailableLock(): a 500 that carries a Redis code, never the contention code', async () => {
        const logger = createMockLogger();
        const refuse = refuseUnavailableLock(logger, 'Failed to get renewal lock', { account: 'a' });
        assert.throws(
            () => refuse(Object.assign(new Error('held'), { code: 'ELOCKNOTACQUIRED' })),
            err => err.output.statusCode === 500 && err.output.payload.code === undefined
        );
        assert.throws(
            () => refuse(Object.assign(new Error('down'), { code: 'ECONNREFUSED' })),
            err => err.output.payload.code === 'ECONNREFUSED'
        );
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.level, entry.msg]),
            [
                ['warn', 'Failed to get renewal lock, timed out waiting for the current holder'],
                ['error', 'Failed to get renewal lock']
            ]
        );
    });
});

test('locks are taken only through runLocked()', () => {
    const root = path.join(__dirname, '..');
    const offenders = [];
    for (const file of [path.join(root, 'server.js'), ...listFiles(path.join(root, 'lib'), '.js'), ...listFiles(path.join(root, 'workers'), '.js')]) {
        if (file.endsWith(path.join('lib', 'lock-run.js'))) {
            continue;
        }
        const source = fs.readFileSync(file, 'utf-8');
        if (/\.(waitAcquireLock|acquireLock|releaseLock)\(/.test(source)) {
            offenders.push(path.relative(root, file));
        }
    }
    assert.deepStrictEqual(offenders, []);
});
