'use strict';

// Unit coverage for the re-authorization recovery Account.create() performs.
//
// When an EXISTING account that is currently non-operational is re-registered - which is what the
// interactive OAuth re-auth redirect and the IMAP re-credentials form both do - create() must
// request a FULL reconnect (cmd:'reconnect'), not an in-place cmd:'update'. cmd:'update' only calls
// reconnect() on the existing client instance, which cannot switch client type (IMAP <-> API) and
// is a no-op against a torn-down connection, so syncing would not resume without a manual
// "Reconnect". Healthy accounts keep cmd:'update' and brand-new accounts keep cmd:'new'.
//
// Re-registration must also lift a disable the auth-failure safety net applied, because a reconnect
// cannot resume an account that is switched off, and this is the only path an OAuth2 account has to
// that flag - create() writes no `imap` field of its own, so the synthesized `{"disabled":true}`
// blob would otherwise survive every re-authorization.
//
// See account-reauth-reconnect-test.js for the sibling Account.update() coverage.

const test = require('node:test');
const assert = require('node:assert').strict;

// Mock the db module before importing account.js so no real Redis/BullMQ connections open.
const mockQueue = { add: async () => ({}), close: async () => {}, on: () => {}, off: () => {} };
function createMockRedis() {
    return {
        status: 'ready',
        hget: async () => null,
        hmget: async (key, ...fields) => fields.map(() => null),
        hset: async () => {},
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async () => ({}),
        get: async () => null,
        set: async () => 'OK',
        exists: async () => 0,
        sMembers: async () => [],
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate() {
            return createMockRedis();
        }
    };
}

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: createMockRedis(),
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        documentsQueue: mockQueue,
        exportQueue: mockQueue,
        getFlowProducer: () => ({}),
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const { Account } = require('../lib/account');
const { createAccountHash, DISABLED_MARKER, DISABLED_AT } = require('./helpers/account-hash');

function createMockLogger() {
    let logger = {};
    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = () => {};
    }
    return logger;
}

// Builds a mock `this` for Account.prototype.create and records every RPC call() it issues.
//
// `stored` is the account hash as it stands before the call, which is what drives the new vs
// existing branch: create() reads it back through the leading hgetall of its own pipeline, so a
// truthy `account` field means an existing account and an empty hash means a fresh one. It is a
// live hash rather than a canned pipeline reply because the recovery path writes to it outside
// that pipeline. `throwOnReconnect` makes the reconnect RPC reject, to exercise the try/catch
// guard around the reconnect dispatch.
//
// The receiver inherits the real prototype: create() delegates to clearAuthFailureDisable() and
// unserializeAccountData(), and a hand-listed set of methods silently breaks the next time it
// grows one more collaborator.
function createCtx(stored, { throwOnReconnect = false } = {}) {
    let calls = [];
    let { hash, writes, commands } = createAccountHash(stored);

    let redis = Object.assign(createMockRedis(), commands);

    let ctx = Object.assign(Object.create(Account.prototype), {
        account: null,
        timeout: 1000,
        logger: createMockLogger(),
        redis,
        getAccountKey: () => 'iad:test',
        serializeAccountData: () => ({}),
        genId: async () => 'generated-id',
        loadAccountData: async () => ({}),
        call: async message => {
            calls.push(message);
            if (message.cmd === 'runIndex') {
                // create() calls runIndex.toString(), so this must be a number
                return 1;
            }
            if (message.cmd === 'reconnect' && throwOnReconnect) {
                throw new Error('worker unavailable');
            }
            return true;
        }
    });

    return { ctx, calls, hash, writes };
}

// An account that already exists, in the given connection state.
function existing(state, extraFields) {
    return Object.assign({ account: 'acc', state }, extraFields);
}

test('Account.create re-auth reconnect gate', async t => {
    await t.test('existing account in authenticationError requests a full reconnect', async () => {
        let { ctx, calls } = createCtx(existing('authenticationError'));

        let res = await Account.prototype.create.call(ctx, { account: 'acc1', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'exactly one reconnect should be requested');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0, 'no in-place update');
        assert.strictEqual(calls.filter(c => c.cmd === 'new').length, 0);
        let reconnect = calls.find(c => c.cmd === 'reconnect');
        assert.strictEqual(reconnect.account, 'acc1');
        assert.strictEqual(reconnect.timeout, 1000);
        assert.strictEqual(res.state, 'existing');
    });

    await t.test('existing account in connectError requests a full reconnect', async () => {
        let { ctx, calls } = createCtx(existing('connectError'));

        await Account.prototype.create.call(ctx, { account: 'acc2', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });

    await t.test('existing healthy (connected) account keeps in-place update', async () => {
        let { ctx, calls } = createCtx(existing('connected'));

        await Account.prototype.create.call(ctx, { account: 'acc3', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1, 'connected account uses cmd:update');
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'healthy account is not torn down');
    });

    await t.test('brand-new account uses cmd:new (no reconnect)', async () => {
        // Nothing stored yet
        let { ctx, calls } = createCtx({});

        let res = await Account.prototype.create.call(ctx, { account: 'acc4', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'new').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
        assert.strictEqual(res.state, 'new');
    });

    await t.test('existing account in unset (sync disabled) keeps cmd:update', async () => {
        // Regression guard: "unset" means the account is not syncing - do not force-connect it.
        // A parked account also reports `unset`, but carries the marker the recovery cases below
        // seed, which is what tells the two apart.
        let { ctx, calls } = createCtx(existing('unset'));

        await Account.prototype.create.call(ctx, { account: 'acc5', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('paused account keeps cmd:update', async () => {
        let { ctx, calls } = createCtx(existing('paused'));

        await Account.prototype.create.call(ctx, { account: 'acc6', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('reconnect dispatch failure does not reject the re-auth', async () => {
        // Credentials are already persisted by the time the reconnect is dispatched, so a failed
        // dispatch must be swallowed (logged) rather than surfaced as a 500 to the user.
        let { ctx, calls } = createCtx(existing('authenticationError'), { throwOnReconnect: true });

        let res;
        await assert.doesNotReject(async () => {
            res = await Account.prototype.create.call(ctx, { account: 'acc7', imapIndexer: 'full' });
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'reconnect was attempted');
        assert.strictEqual(res.state, 'existing', 'create still reports the account as saved');
    });

    await t.test('re-registering a parked account lifts the disable and reconnects', async () => {
        // The reported gap. A parked account does not sit in an error state - the connection gate
        // reports it as `unset`, which the case above deliberately leaves alone - so without
        // lifting the flag here an OAuth2 account stayed off no matter how many times it was
        // re-authorized, and the only way back was a hand-written API call.
        let { ctx, calls, hash } = createCtx(
            existing('unset', {
                imap: JSON.stringify({ disabled: true }),
                [DISABLED_MARKER]: DISABLED_AT
            })
        );

        let res = await Account.prototype.create.call(ctx, { account: 'acc-parked', imapIndexer: 'full' });

        assert.strictEqual(res.state, 'existing');
        assert.strictEqual(JSON.parse(hash.imap).disabled, false, 'the disable flag is lifted');
        assert.ok(!(DISABLED_MARKER in hash), 'and the marker is retired with it');
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'cmd:update is a no-op against a parked account');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });

    await t.test('re-registering a password account with OAuth2 drops its IMAP configuration and reconnects in full', async () => {
        // A password account the safety net parked (or the operator switched off), re-registered
        // with OAuth2 under the same id. getImapConfig() never reads `imap` when there is an OAuth2
        // credential, so the stored configuration is dead - but the Gmail API and Outlook clients
        // honor its `disabled` flag on the way in, and this account has no marker to lift, no badge,
        // and no IMAP card to clear the flag from. The park recorded no marker (it predates it), so
        // the state alone would have kept the in-place update, which cannot switch client types.
        let { ctx, calls, hash, writes } = createCtx(
            existing('unset', { imap: JSON.stringify({ host: 'imap.test', port: 993, auth: { user: 'user' }, disabled: true }) })
        );

        await Account.prototype.create.call(ctx, { account: 'acc-migrated', imapIndexer: 'full', oauth2: { auth: { user: 'user@example.com' } } });

        assert.ok(!('imap' in hash), 'the password configuration does not outlive the credential it belonged to');
        assert.ok(writes.some(w => w.op === 'hdel' && w.field === 'imap'));
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'a client of the new type is assigned');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });

    await t.test('re-registration with OAuth2 leaves a bare disable flag alone', async () => {
        // The flag without a host is not a password configuration: it is the operator's send-only
        // switch on an OAuth2 account, or the safety net's park, and each has its own handling
        let { ctx, hash } = createCtx(existing('connected', { imap: JSON.stringify({ disabled: true }) }));

        await Account.prototype.create.call(ctx, { account: 'acc-bare', imapIndexer: 'full', oauth2: { auth: { user: 'user@example.com' } } });

        assert.strictEqual(JSON.parse(hash.imap).disabled, true);
    });

    await t.test('re-registration does NOT lift a disable the operator set', async () => {
        // imap.disabled is also the send-only switch, and re-authorization is routine for a
        // send-only account. Without the marker this would start syncing a mailbox somebody had
        // deliberately switched off.
        let { ctx, calls, hash, writes } = createCtx(existing('connected', { imap: JSON.stringify({ disabled: true }) }));

        await Account.prototype.create.call(ctx, { account: 'acc-sendonly', imapIndexer: 'full' });

        assert.strictEqual(JSON.parse(hash.imap).disabled, true, 'a send-only account stays send-only');
        assert.deepStrictEqual(writes, [], 'and no single-field write touches the flag or the marker');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('registering an account with imap.disabled turned on retires the marker', async () => {
        // The payload switches a working account off, so the operator now owns the flag and the
        // safety net's bookkeeping about an earlier automatic disable no longer describes it.
        let { ctx, hash } = createCtx(
            existing('connected', {
                imap: JSON.stringify({ host: 'imap.test', disabled: false }),
                [DISABLED_MARKER]: DISABLED_AT
            })
        );

        await Account.prototype.create.call(ctx, {
            account: 'acc-operator-disable',
            imapIndexer: 'full',
            imap: { host: 'imap.test', port: 993, disabled: true }
        });

        assert.ok(!(DISABLED_MARKER in hash), 'the marker cannot outlive an operator decision about the flag');
    });

    await t.test('re-registering a parked account with imap.disabled still set does not resume it', async () => {
        // The payload asks for IMAP to stay off. Nothing may lift it - but nothing takes ownership
        // either, since this write did not turn the flag on, so the park is still recoverable.
        let { ctx, hash } = createCtx(
            existing('unset', {
                imap: JSON.stringify({ host: 'imap.test', disabled: true }),
                [DISABLED_MARKER]: DISABLED_AT
            })
        );

        await Account.prototype.create.call(ctx, {
            account: 'acc-still-off',
            imapIndexer: 'full',
            imap: { host: 'imap.test', port: 993, disabled: true }
        });

        assert.strictEqual(JSON.parse(hash.imap).disabled, true, 'a write asking for IMAP off must never turn it back on');
        assert.strictEqual(hash[DISABLED_MARKER], DISABLED_AT, 'and the park stays recoverable');
    });

    await t.test('IMAP (non-OAuth) account in error state also reconnects', async () => {
        // The gate is provider-agnostic: a fixed-and-resubmitted IMAP account in error state also
        // resumes via a full reconnect.
        let { ctx, calls } = createCtx(existing('authenticationError'));

        await Account.prototype.create.call(ctx, {
            account: 'acc8',
            imapIndexer: 'full',
            imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });
});
