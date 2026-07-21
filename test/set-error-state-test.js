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
            // The event the stored payload was reported under - the other half of the dedup key.
            .hset(accountKey, 'lastError:event', 'authenticationError')
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
            .hset(accountKey, 'lastError:event', 'authenticationError')
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
            .hset(accountKey, 'lastError:event', 'authenticationError')
            .hset(accountKey, 'lastError:errorCount', '9')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'NEWCODE', response: 'different' });

        assert.strictEqual(isFirst, true, 'a changed error code restarts the counter');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '1');
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, false, 'a fresh error must not immediately disable IMAP');
    });

    await t.test('the same error code under a DIFFERENT event is a new first occurrence', async () => {
        // The dedup key includes the event. Both token-failure branches once reported
        // serverResponseCode 'TokenGenerationError', so a connectError recorded earlier suppressed
        // the authenticationError that followed - withholding the only signal an operator gets that
        // an account needs re-authorization. notify() returns without delivering a webhook whenever
        // this comes back false, so the assertion below is the webhook.
        const { ctx, accountKey } = makeCtx('seterr-event-change');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'TokenGenerationError' }))
            .hset(accountKey, 'lastError:event', 'connectError')
            .hset(accountKey, 'lastError:errorCount', '3')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - HOUR).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'TokenGenerationError', response: 'token rejected' });

        assert.strictEqual(isFirst, true, 'a changed event must report even when the response code is unchanged');
    });

    await t.test('a repeat is still deduped while the account state says "connecting"', async () => {
        // The dedup key must be owned by setErrorState, not read from the shared `state` field.
        // connect() and both API init()s persist 'connecting' immediately before the attempt that
        // fails, so on every pass of the reconnect loop the stored state is 'connecting' and never
        // the event being deduped. Keying on it made every retry a "first occurrence": a webhook per
        // retry, and lastError:first reset each time, so the auth-failure window could never reach
        // its threshold and the auto-disable above could never fire.
        const { ctx, accountKey } = makeCtx('seterr-connecting');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:event', 'authenticationError')
            // What the reconnect loop actually leaves behind before it fails again.
            .hset(accountKey, 'state', 'connecting')
            .hset(accountKey, 'lastError:errorCount', '4')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - HOUR).toISOString())
            .exec();

        const firstSeen = await redis.hget(accountKey, 'lastError:first');
        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, false, 'a retry must not be reported as a new first occurrence');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '5', 'the counter advances instead of resetting');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:first'), firstSeen, 'the auth-failure window start must survive the retry');
    });

    await t.test('an unchanged repeat does not rewrite lastErrorState', async () => {
        // A reconnect loop calls setErrorState() on every attempt. Rewriting byte-identical JSON and
        // broadcasting a state change nothing observed is the write amplification that presented as
        // pinned CPU in 2.73.0, so the repeat path must leave the stored payload alone.
        const { ctx, accountKey } = makeCtx('seterr-no-rewrite');
        await redis
            .multi()
            .hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH', marker: 'original' }))
            .hset(accountKey, 'lastError:event', 'authenticationError')
            .hset(accountKey, 'lastError:errorCount', '2')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - HOUR).toISOString())
            .exec();

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, false);
        const stored = JSON.parse(await redis.hget(accountKey, 'lastErrorState'));
        assert.strictEqual(stored.marker, 'original', 'the stored payload is left untouched on an unchanged repeat');
        // The counter still advances - that is what the auth-failure window measures.
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '3');
    });
});
