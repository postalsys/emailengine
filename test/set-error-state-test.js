'use strict';

// Unit test for BaseClient.setErrorState - the auth-failure tracking and IMAP
// auto-disable safety mechanism (lib/email-client/base-client.js). When an
// account keeps hitting authentication errors past MAX_IMAP_AUTH_FAILURE_TIME
// (default 3 days), IMAP is disabled to stop a reconnect storm. This had no
// coverage. setErrorState only touches `this.redis`, `this.getAccountKey()`,
// `this.setStateVal()`, `this.logger`, `this.account`, `this.state` and
// `this.close()`, so we drive it through the prototype with a fake receiver and
// the real test Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {}, child: () => noopLogger };

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

const createdKeys = new Set();

// Build a fake BaseClient receiver bound to a unique account hash.
function makeCtx(account) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    createdKeys.add(accountKey);
    const ctx = {
        account,
        redis,
        logger: noopLogger,
        state: 'connected',
        closeCalls: 0,
        getAccountKey: () => accountKey,
        setStateVal: async () => {},
        close() {
            this.closeCalls++;
        }
    };
    return { ctx, accountKey };
}

const setErrorState = (ctx, event, data) => BaseClient.prototype.setErrorState.call(ctx, event, data);

registerRedisTeardown(redis, async () => {
    for (const key of createdKeys) {
        try {
            await redis.del(key);
        } catch (err) {
            // ignore
        }
    }
});

test('BaseClient.setErrorState', async t => {
    await t.test('first occurrence initializes the error counter and does not disable IMAP', async () => {
        const { ctx, accountKey } = makeCtx('seterr-first');
        // The account hash must exist for hSetExists to take effect.
        await redis.hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }));

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, true, 'a brand new error is a first occurrence');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '1');
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, false, 'IMAP stays enabled on a first occurrence');
        assert.strictEqual(ctx.closeCalls, 0);
    });

    await t.test('repeat of the same error below the threshold does not disable IMAP', async () => {
        const { ctx, accountKey } = makeCtx('seterr-below');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '1')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - HOUR).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, false, 'matching serverResponseCode is a repeat occurrence');
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, false, 'IMAP stays enabled below the time threshold');
        assert.strictEqual(ctx.closeCalls, 0);
    });

    await t.test('repeat of the same error past the threshold disables IMAP and closes the connection', async () => {
        const { ctx, accountKey } = makeCtx('seterr-disable');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '5')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, false);
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, true, 'IMAP must be disabled past the threshold');
        // The error counters are cleared when IMAP is disabled.
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), null);

        // close() is scheduled with setImmediate.
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 1, 'the connection should be closed after disabling IMAP');
    });

    await t.test('a different error code is treated as a new first occurrence', async () => {
        const { ctx, accountKey } = makeCtx('seterr-changed');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'OLDCODE' }))
            .hset(accountKey, 'lastError:errorCount', '9')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'NEWCODE', response: 'different' });

        assert.strictEqual(isFirst, true, 'a changed error code restarts the counter');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '1');
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, false, 'a fresh error must not immediately disable IMAP');
    });
});
