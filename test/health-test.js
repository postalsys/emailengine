'use strict';

// lib/health.js: the liveness and readiness checks behind /health, /health/live and /health/ready.
// Regression: the IMAP worker count arrives as { workers: N } and used to be compared to a number as
// a whole object, which is never less than anything, so missing workers were never reported.

const test = require('node:test');
const assert = require('node:assert').strict;

const { createHealthChecks } = require('../lib/health');

function fakeRedis(opts = {}) {
    const store = new Map();
    return {
        multi() {
            const ops = [];
            const chain = {
                set(key, value) {
                    ops.push(() => {
                        store.set(key, value);
                        return 'OK';
                    });
                    return chain;
                },
                get(key) {
                    ops.push(() => (opts.corruptGet ? 'other' : store.get(key)));
                    return chain;
                },
                del(key) {
                    ops.push(() => (store.delete(key) ? 1 : 0));
                    return chain;
                },
                async exec() {
                    if (opts.execError) {
                        throw opts.execError;
                    }
                    return ops.map(op => [null, op()]);
                }
            };
            return chain;
        },
        store
    };
}

function checks(overrides = {}) {
    let draining = false;
    const calls = [];
    const redis = overrides.redis || fakeRedis();
    const health = createHealthChecks({
        call: async message => {
            calls.push(message);
            if (overrides.callError) {
                throw overrides.callError;
            }
            return 'answer' in overrides ? overrides.answer : { workers: 4 };
        },
        redis,
        prefix: 'pfx:',
        expectedImapWorkers: 4,
        isDraining: () => draining
    });
    return { health, calls, redis, drain: () => (draining = true) };
}

async function rejectsWith(promise, code) {
    await assert.rejects(promise, err => {
        assert.strictEqual(err.statusCode, 503);
        assert.strictEqual(err.code, code);
        return true;
    });
}

test('health checks', async t => {
    await t.test('ready when every IMAP worker is up and Redis round-trips', async () => {
        const { health, calls, redis } = checks();
        assert.deepStrictEqual(await health.ready(5000), { success: true });
        assert.deepStrictEqual(calls, [{ cmd: 'imapWorkerCount', timeout: 5000 }]);
        // the probe key is removed again
        assert.strictEqual(redis.store.size, 0);
    });

    await t.test('reports missing IMAP workers (regression: object compared to a number)', async () => {
        await rejectsWith(checks({ answer: { workers: 3 } }).health.ready(), 'WorkersUnavailable');
        await rejectsWith(checks({ answer: { workers: 0 } }).health.ready(), 'WorkersUnavailable');
    });

    await t.test('treats an unusable worker count answer as not ready', async () => {
        await rejectsWith(checks({ answer: null }).health.ready(), 'WorkersUnavailable');
        await rejectsWith(checks({ answer: 4 }).health.ready(), 'WorkersUnavailable');
        await rejectsWith(checks({ answer: { workers: 'x' } }).health.ready(), 'WorkersUnavailable');
    });

    await t.test('more workers than configured is still ready', async () => {
        assert.deepStrictEqual(await checks({ answer: { workers: 5 } }).health.ready(), { success: true });
    });

    await t.test('a failed worker RPC is a 503, not a 500', async () => {
        const err = new Error('Timeout');
        err.code = 'Timeout';
        await rejectsWith(checks({ callError: err }).health.ready(), 'WorkerCheckFailed');
    });

    await t.test('a Redis error or a wrong read-back is a 503', async () => {
        await rejectsWith(checks({ redis: fakeRedis({ execError: new Error('OOM command not allowed') }) }).health.ready(), 'DatabaseCheckFailed');
        await rejectsWith(checks({ redis: fakeRedis({ corruptGet: true }) }).health.ready(), 'DatabaseCheckFailed');
    });

    await t.test('draining: not ready, but still alive', async () => {
        const { health, calls, drain } = checks();
        assert.deepStrictEqual(health.live(), { success: true });
        drain();
        await rejectsWith(health.ready(), 'ShuttingDown');
        assert.strictEqual(calls.length, 0, 'no RPC once draining');
        assert.deepStrictEqual(health.live(), { success: true, draining: true });
    });

    await t.test('liveness never touches Redis or the main thread', async () => {
        const { health, calls } = checks({ redis: fakeRedis({ execError: new Error('down') }), callError: new Error('down') });
        assert.deepStrictEqual(health.live(), { success: true });
        assert.strictEqual(calls.length, 0);
    });
});
