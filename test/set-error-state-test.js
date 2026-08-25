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

const { Account } = require('../lib/account');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createErrorStateClient, accountKeyFor, drainSetImmediate, noopLogger } = require('./helpers/auth-failure');
const { AUTH_FAILURE_DISABLED_FIELD } = require('../lib/consts');

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

const createdKeys = new Set();

// Build a fake BaseClient receiver bound to a unique account hash, registered for cleanup.
function makeCtx(account) {
    const accountKey = accountKeyFor(account);
    createdKeys.add(accountKey);
    return { ctx: createErrorStateClient({ redis, account }), accountKey };
}

const setErrorState = (ctx, event, data) => ctx.setErrorState(event, data);

// Seeds the account hash a subtest needs. The hash must exist at all for hSetExists to write, and
// every case here varies only which credential is present and how old/large the error run is.
async function seed(accountKey, { imap, oauth2, code = 'AUTH', count, ageMs } = {}) {
    const txn = redis.multi().hset(accountKey, 'account', accountKey);
    if (imap !== undefined) {
        txn.hset(accountKey, 'imap', typeof imap === 'string' ? imap : JSON.stringify(imap));
    }
    if (oauth2 !== undefined) {
        txn.hset(accountKey, 'oauth2', JSON.stringify(oauth2));
    }
    if (code) {
        txn.hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: code }));
    }
    if (count !== undefined) {
        txn.hset(accountKey, 'lastError:errorCount', String(count));
    }
    if (ageMs !== undefined) {
        txn.hset(accountKey, 'lastError:first', new Date(Date.now() - ageMs).toISOString());
    }
    await txn.exec();
}

registerRedisTeardown(redis, async () => {
    for (const key of createdKeys) {
        try {
            await redis.del(key);
        } catch (err) {
            // ignore
        }
    }
});

test('BaseClient.isSyncDisabled', async t => {
    // The flag setErrorState() writes is only worth anything if the clients read it. The IMAP
    // client checks it on already-loaded account data; the Gmail and Graph clients call this,
    // because they have to know before they spend a token refresh finding out.
    await t.test('reports a disabled account', async () => {
        const { ctx, accountKey } = makeCtx('syncdis-on');
        await seed(accountKey, { imap: { disabled: true }, code: null });
        assert.strictEqual(await ctx.isSyncDisabled(), true);
    });

    await t.test('reports an enabled account', async () => {
        const { ctx, accountKey } = makeCtx('syncdis-off');
        await seed(accountKey, { imap: { host: 'imap.test', disabled: false }, code: null });
        assert.strictEqual(await ctx.isSyncDisabled(), false);
    });

    await t.test('an account with no imap field is not disabled', async () => {
        const { ctx, accountKey } = makeCtx('syncdis-none');
        await seed(accountKey, { oauth2: { provider: 'gmail' }, code: null });
        assert.strictEqual(await ctx.isSyncDisabled(), false);
    });

    await t.test('an unreadable blob is not treated as a disable', async () => {
        const { ctx, accountKey } = makeCtx('syncdis-bad');
        await seed(accountKey, { imap: 'not json', code: null });
        assert.strictEqual(await ctx.isSyncDisabled(), false, 'a parse failure must not strand the account offline');
    });

    await t.test('what setErrorState disables, isSyncDisabled reports', async () => {
        // The two halves have to agree, including for an OAuth2 account that had no imap field
        // until the disable synthesized one.
        const { ctx, accountKey } = makeCtx('syncdis-roundtrip');
        await seed(accountKey, { oauth2: { provider: 'gmail' }, code: 'OauthRenewError', count: 40, ageMs: 4 * DAY });

        assert.strictEqual(await ctx.isSyncDisabled(), false, 'enabled before the threshold trips');

        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'OauthRenewError', response: 'invalid_grant' });

        assert.strictEqual(await ctx.isSyncDisabled(), true, 'and disabled after');
        await drainSetImmediate();
    });
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

        const shouldNotify = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        // The error itself is a repeat, which is normally suppressed, but the disable is reported:
        // an account going offline until someone re-authenticates it has to reach the operator.
        assert.strictEqual(shouldNotify, true, 'the disable itself is notified');
        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, true, 'IMAP must be disabled past the threshold');
        // The error counters are cleared when IMAP is disabled.
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), null);

        // close() is scheduled with setImmediate.
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 1, 'the connection should be closed after disabling IMAP');
    });

    await t.test('an OAuth2 account past the threshold is disabled even with no imap configuration', async () => {
        const { ctx, accountKey } = makeCtx('seterr-oauth2');
        // An OAuth2 account has no `imap` hash field at all - getImapConfig() builds its connection
        // from the provider table. This is the shape the disable used to skip in silence.
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail', auth: { user: 'user@example.com' } }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'OauthRenewError' }))
            .hset(accountKey, 'lastError:errorCount', '120')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const shouldNotify = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'OauthRenewError', response: 'invalid_grant' });

        const imap = JSON.parse(await redis.hget(accountKey, 'imap'));
        assert.strictEqual(imap.disabled, true, 'an OAuth2 account must be disabled past the threshold');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), null, 'the counters are cleared on disable');

        const lastErrorState = JSON.parse(await redis.hget(accountKey, 'lastErrorState'));
        assert.match(lastErrorState.description, /exceeding the authentication error threshold/);

        // The disable is reported even though the error itself is a repeat, which the caller would
        // otherwise suppress - an account going offline has to reach the operator.
        assert.strictEqual(shouldNotify, true, 'the trip itself is notified');

        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 1, 'the connection should be closed after disabling');
    });

    await t.test('an account with neither imap nor oauth2 is left alone', async () => {
        const { ctx, accountKey } = makeCtx('seterr-nocreds');
        // Half-created accounts must not be marked disabled on their way in.
        await redis
            .multi()
            .hset(accountKey, 'account', 'seterr-nocreds')
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '5')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const shouldNotify = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(await redis.hget(accountKey, 'imap'), null, 'no imap flag is synthesized without a credential to fail against');
        assert.strictEqual(shouldNotify, false, 'nothing was disabled, so nothing extra is reported');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '6', 'the counter keeps running');

        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 0);
    });

    await t.test('an already disabled account is not disabled again', async () => {
        const { ctx, accountKey } = makeCtx('seterr-already');
        await redis
            .multi()
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, 'imap', JSON.stringify({ disabled: true }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'OauthRenewError' }))
            .hset(accountKey, 'lastError:errorCount', '9')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const shouldNotify = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'OauthRenewError', response: 'invalid_grant' });

        assert.strictEqual(shouldNotify, false, 'a repeat on an already disabled account stays quiet');
        assert.strictEqual(await redis.hget(accountKey, 'lastError:errorCount'), '10', 'nothing was reset');

        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 0, 'no second close for an account already disabled');
    });

    await t.test('an unparseable imap blob is left intact rather than replaced with a bare flag', async () => {
        const { ctx, accountKey } = makeCtx('seterr-badblob');
        await redis
            .multi()
            .hset(accountKey, 'imap', 'not json')
            .hset(accountKey, 'oauth2', JSON.stringify({ provider: 'gmail' }))
            .hset(accountKey, 'lastErrorState', JSON.stringify({ serverResponseCode: 'AUTH' }))
            .hset(accountKey, 'lastError:errorCount', '5')
            .hset(accountKey, 'lastError:first', new Date(Date.now() - 4 * DAY).toISOString())
            .exec();

        const shouldNotify = await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

        assert.strictEqual(await redis.hget(accountKey, 'imap'), 'not json', 'the unreadable configuration is preserved');
        assert.strictEqual(shouldNotify, false);
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(ctx.closeCalls, 0);
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

// The other half of the mechanism. `imap.disabled` is both the safety net's park flag and the
// operator's send-only switch, and AUTH_FAILURE_DISABLED_FIELD is the only thing that tells them
// apart - so the writer above and the reader below are tested against the same real Redis hash
// rather than against each other's assumptions.
test('Auth-failure disable recovery', async t => {
    // clearAuthFailureDisable() only needs an account key, a client and a logger. Built on the same
    // key as makeCtx(), so the two halves of the mechanism act on one account hash.
    function makeAccount(account) {
        const { accountKey } = makeCtx(account);
        const accountObject = Object.assign(Object.create(Account.prototype), {
            account,
            redis,
            logger: noopLogger,
            getAccountKey: () => accountKey
        });
        return { accountObject, accountKey };
    }

    const markerOf = accountKey => redis.hget(accountKey, AUTH_FAILURE_DISABLED_FIELD);

    await t.test('what the safety net parks, clearAuthFailureDisable brings back', async () => {
        const { ctx, accountKey } = makeCtx('recover-roundtrip');
        const { accountObject } = makeAccount('recover-roundtrip');

        await seed(accountKey, { oauth2: { provider: 'gmail' }, code: 'OauthRenewError', count: 40, ageMs: 4 * DAY });
        await setErrorState(ctx, 'authenticationError', { serverResponseCode: 'OauthRenewError', response: 'invalid_grant' });
        await drainSetImmediate();

        const disabledAt = await markerOf(accountKey);
        assert.ok(disabledAt, 'the park is marked as ours');
        assert.ok(!Number.isNaN(Date.parse(disabledAt)), 'and stamped with when it happened');

        assert.strictEqual(await accountObject.clearAuthFailureDisable(), true, 'the disable is lifted');
        assert.strictEqual(await ctx.isSyncDisabled(), false, 'and the account may connect again');
        assert.strictEqual(await markerOf(accountKey), null, 'the marker goes with it');
    });

    await t.test('a disable the operator set is left alone', async () => {
        // A send-only account. Re-authorization is routine for one, so lifting this would silently
        // start syncing a mailbox somebody had switched off on purpose.
        const { accountObject, accountKey } = makeAccount('recover-operator');
        await seed(accountKey, { imap: { host: 'imap.test', disabled: true }, code: null });

        assert.strictEqual(await accountObject.clearAuthFailureDisable(), false, 'nothing to lift without the marker');
        assert.strictEqual(JSON.parse(await redis.hget(accountKey, 'imap')).disabled, true, 'the flag survives');
    });

    await t.test('a marker left behind by a manual re-enable is retired', async () => {
        const { accountObject, accountKey } = makeAccount('recover-stale');
        await seed(accountKey, { imap: { host: 'imap.test', disabled: false }, code: null });
        await redis.hset(accountKey, AUTH_FAILURE_DISABLED_FIELD, new Date().toISOString());

        assert.strictEqual(await accountObject.clearAuthFailureDisable(), false, 'an already-enabled account was not lifted by this call');
        assert.strictEqual(await markerOf(accountKey), null, 'but the stale marker cannot survive to authorize a later, deliberate disable');
    });

    await t.test('an unreadable imap blob is not rewritten', async () => {
        const { accountObject, accountKey } = makeAccount('recover-badblob');
        await seed(accountKey, { imap: 'not json', code: null });
        await redis.hset(accountKey, AUTH_FAILURE_DISABLED_FIELD, new Date().toISOString());

        assert.strictEqual(await accountObject.clearAuthFailureDisable(), false);
        assert.strictEqual(await redis.hget(accountKey, 'imap'), 'not json', 'the stored configuration is preserved');
    });
});
