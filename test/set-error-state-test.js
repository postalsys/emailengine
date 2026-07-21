'use strict';

// Unit test for BaseClient.setErrorState - the auth-failure tracking and account
// auto-disable safety mechanism (lib/email-client/base-client.js). When an
// account keeps hitting authentication errors past MAX_IMAP_AUTH_FAILURE_TIME
// (default 3 days), the account is parked to stop a reconnect storm.
//
// The marker is the system-owned ACCOUNT_AUTH_FAILURE_DISABLED_KEY field, not
// `imap.disabled`: that key is the operator's "Disable IMAP" checkbox and OAuth2
// accounts have no `imap` object at all, so keying off it made this branch a
// silent no-op for every OAuth2 account.
//
// setErrorState only touches `this.redis`, `this.getAccountKey()`,
// `this.setStateVal()`, `this.logger`, `this.account`, `this.state` and
// `this.close()`, so we drive it through the prototype with a fake receiver and
// the real test Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX, ACCOUNT_AUTH_FAILURE_DISABLED_KEY, ACCOUNT_TOKEN_ERROR_FIRST_KEY } = require('../lib/consts');
const { clearAuthFailurePark, isConnectionBlocked } = require('../lib/account/account-state');

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
const clearAuthFailureState = ctx => BaseClient.prototype.clearAuthFailureState.call(ctx);
const isDisabled = async accountKey => !!(await redis.hget(accountKey, ACCOUNT_AUTH_FAILURE_DISABLED_KEY));

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
    await t.test('first occurrence initializes the error counter and does not disable the account', async () => {
        const { ctx, accountKey } = makeCtx('seterr-first');
        // The account hash must exist for hSetExists to take effect.
        await redis.hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }));

        const isFirst = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(isFirst, true, 'a brand new error is a first occurrence');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '1');
        assert.strictEqual(await isDisabled(accountKey), false, 'the account stays enabled on a first occurrence');
        assert.strictEqual(ctx.closeCalls, 0);
    });

    await t.test('repeat of the same error below the threshold does not disable the account', async () => {
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
        assert.strictEqual(await isDisabled(accountKey), false, 'the account stays enabled below the time threshold');
        assert.strictEqual(ctx.closeCalls, 0);
    });

    await t.test('repeat of the same error past the threshold disables the account and closes the connection', async () => {
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
        assert.strictEqual(await isDisabled(accountKey), true, 'the account must be parked past the threshold');

        // The operator-owned "Disable IMAP" setting must be left alone - the system marker is a
        // separate field precisely so a system park can be cleared without touching operator input.
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, false, 'the operator-owned imap.disabled flag must not be written by the system');

        // The error counters are cleared when the account is parked.
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), null);
        assert.strictEqual(await redis.hget(accountKey, 'lastError:first'), null);

        // close() is scheduled with setImmediate.
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 1, 'the connection should be closed after parking the account');
    });

    await t.test('an OAuth2 account with no imap object is parked, and its counters do not leak', async () => {
        // The regression: the disable branch used to read the `imap` hash field and bail when it
        // was missing, so every OAuth2 account (Gmail API, Outlook Graph, OAuth2-IMAP, Mail.ru)
        // retried forever and never parked - and because the counter reset lived inside that same
        // branch, lastError:first stayed pinned in the past and errorCount grew without bound.
        const { ctx, accountKey } = makeCtx('seterr-oauth2');
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '5')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });
        await new Promise(resolve => setImmediate(resolve));

        assert.strictEqual(await isDisabled(accountKey), true, 'an OAuth2 account must be parked past the threshold');
        assert.strictEqual(await redis.hget(accountKey, 'imap'), null, 'no imap object should be invented for an OAuth2 account');
        assert.strictEqual(ctx.closeCalls, 1);

        // A further identical error must restart the window rather than re-park every time.
        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });
        await new Promise(resolve => setImmediate(resolve));

        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '1', 'the counter restarts instead of growing without bound');
        assert.strictEqual(ctx.closeCalls, 1, 'the account is not re-parked on every subsequent error');
    });

    await t.test('a parked account can be un-parked', async () => {
        // The park gates every connect path, so the clear-on-successful-authentication route
        // inside the email clients is unreachable once it is set. Without this escape hatch the
        // marker is permanently sticky - and unlike imap.disabled it has no checkbox to untick,
        // so the account could only be recovered by direct Redis surgery.
        const { ctx, accountKey } = makeCtx('seterr-unpark');
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '5')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });
        assert.strictEqual(await isDisabled(accountKey), true, 'precondition: the account is parked');

        await clearAuthFailurePark(redis, 'seterr-unpark');

        assert.strictEqual(await isDisabled(accountKey), false, 'an explicit reconnect or re-authorization must lift the park');
        assert.strictEqual(isConnectionBlocked({ oauth2: { provider: 'gmail' } }), false, 'and the connect gates must let it through again');
    });

    await t.test('a sustained token-endpoint failure parks the account even as connectError', async () => {
        // connectError never reaches the authenticationError park switch, so without a separate
        // window a token endpoint that is down rather than rejecting credentials would retry
        // forever against a provider quota shared by every account on the same OAuth2 app.
        const { ctx, accountKey } = makeCtx('seterr-tokenwindow');
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY, new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        await setErrorState(ctx, 'connectError', { serverResponseCode: 'OauthRenewNetworkError', response: 'fetch failed' });
        await new Promise(resolve => setImmediate(resolve));

        assert.strictEqual(await isDisabled(accountKey), true, 'a token endpoint failing for the threshold must park the account');
        assert.strictEqual(await redis.hget(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY), null, 'the window is cleared when the park fires');
        assert.strictEqual(ctx.closeCalls, 1);
    });

    await t.test('the token window opens on the first failure and is not restarted by flapping', async () => {
        // The regression this exists for: setErrorState resets lastError:first whenever
        // serverResponseCode changes, so a provider alternating between error classes could reset
        // the auto-disable window on every flip and never park. The token window must not move.
        const { ctx, accountKey } = makeCtx('seterr-tokenflap');
        await redis.hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }));

        await setErrorState(ctx, 'connectError', { serverResponseCode: 'OauthRenewNetworkError', response: 'fetch failed' });
        const opened = await redis.hget(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY);
        assert.ok(opened, 'the first token failure opens the window');

        // Flap to a different classification, then back
        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'OauthRenewError', response: 'invalid_grant' });
        await setErrorState(ctx, 'connectError', { serverResponseCode: 'OauthRenewNetworkError', response: 'fetch failed' });

        assert.strictEqual(await redis.hget(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY), opened, 'reclassification must not restart the token window');
        assert.strictEqual(await isDisabled(accountKey), false, 'and nothing is parked before the threshold');
    });

    await t.test('a non-token error does not open the token window', async () => {
        // Guards against over-reach: an unreachable mail server is not a token endpoint failure and
        // must keep its existing retry-forever semantics.
        const { ctx, accountKey } = makeCtx('seterr-nontoken');
        await redis.hset(accountKey, 'imap', JSON.stringify({ host: 'imap.test', disabled: false }));

        await setErrorState(ctx, 'connectError', { serverResponseCode: 'ECONNREFUSED', response: 'connection refused' });

        assert.strictEqual(await redis.hget(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY), null, 'a mail server failure must not open the token window');
    });

    await t.test('a successful authentication closes the token window', async () => {
        const { ctx, accountKey } = makeCtx('seterr-tokenclear');
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY, new Date(Date.now() - HOUR).toISOString())
            .exec();

        await clearAuthFailureState(ctx);

        assert.strictEqual(await redis.hget(accountKey, ACCOUNT_TOKEN_ERROR_FIRST_KEY), null, 'recovering must not leave a stale window to park on later');
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
        assert.strictEqual(await isDisabled(accountKey), false, 'a fresh error must not immediately disable the account');
    });
});
