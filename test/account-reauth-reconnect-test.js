'use strict';

// Unit coverage for the two paths that bring a broken account back: the OAuth re-authorization
// reconnect gate in Account.update(), and re-registration through Account.create().
//
// When an API client saves new OAuth credentials for an account that is not operational, a full
// reconnect must be requested so syncing resumes without a manual "Reconnect", and any disable the
// auth-failure safety net applied has to be lifted first - a reconnect cannot resume an account
// that is switched off. The disable is told apart from the operator's own send-only switch by the
// marker field below; they share the `imap.disabled` flag.
//
// The gate is opt-in: it fires only when the caller passes { reauthorized: true }. Account state
// cannot be used to infer re-authorization, because unattended writers (renewAccessToken,
// invalidateAccessToken, the Gmail/Outlook client initialize() paths) persist through update()
// while the stored state is still the error state. A state-only gate re-fired on every token
// renewal and dispatched cmd:'reconnect', rebuilding the client and discarding its backoff, which
// pinned the CPU at ~100%.

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
        multi: () => ({
            exec: async () => [[null, 'OK']],
            hmset() {
                return this;
            },
            hset() {
                return this;
            },
            hdel() {
                return this;
            },
            sadd() {
                return this;
            },
            srem() {
                return this;
            }
        }),
        sMembers: async () => [],
        get: async () => null,
        set: async () => 'OK',
        exists: async () => 0,
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
const mockRedis = createMockRedis();

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: mockRedis,
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

const { Account, isAuthFailureDisabled } = require('../lib/account');
const { AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION } = require('../lib/consts');
const { createAccountHash, DISABLED_MARKER, DISABLED_AT } = require('./helpers/account-hash');

function createMockLogger() {
    let logger = {};
    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = () => {};
    }
    return logger;
}

// Builds a mock `this` for Account.prototype.update and records every RPC call() it issues.
// `lockEvents` records the update lock's lifecycle interleaved with the RPC dispatches, so a test
// can assert the lock is released before update() reaches into the IMAP worker.
function createCtx(oldAccountData, { lockOverrides, stored } = {}) {
    let calls = [];
    let lockEvents = [];
    let lock = Object.assign(
        {
            waitAcquireLock: async key => {
                lockEvents.push({ event: 'acquire', key });
                return { success: true, id: key, index: 1 };
            },
            releaseLock: async held => {
                lockEvents.push({ event: 'release', key: held && held.id });
            }
        },
        lockOverrides || {}
    );

    // The recovery paths read and write account hash fields directly rather than through
    // serializeAccountData, so those subtests hand in the hash they need instead of the blanket
    // stubs of mockRedis.
    let { hash, writes, commands } = createAccountHash(stored);

    // Inherit from the real prototype so update() reaches the real persistUpdate() and
    // dispatchPostUpdateCommands(); only the collaborators below are stubbed.
    let ctx;
    ctx = Object.assign(Object.create(Account.prototype), {
        account: oldAccountData.account,
        timeout: 1000,
        logger: createMockLogger(),
        redis: Object.assign({}, mockRedis, stored ? commands : {}),
        getLock: () => lock,
        getAccountKey: () => `iad:${oldAccountData.account}`,
        serializeAccountData: () => ({}),
        // Where a subtest seeds the account hash, the loaded account is derived from it through the
        // REAL unserializeAccountData - that is what turns the stored `imap` blob into an object and
        // lifts the auth-failure marker onto `_authFailureDisabledAt`, both of which the dispatch
        // gate reads. Hand-deriving them here would let the stub drift from what update() sees.
        loadAccountData: async () => (stored ? Object.assign(Account.prototype.unserializeAccountData.call(ctx, stored), oldAccountData) : oldAccountData),
        call: async message => {
            calls.push(message);
            lockEvents.push({ event: 'call', cmd: message.cmd });
            return true;
        }
    });
    return { ctx, calls, lockEvents, hash, writes };
}

const REAUTHORIZED = { reauthorized: true };

test('Account.update OAuth re-auth reconnect gate', async t => {
    await t.test('re-auth while in authenticationError requests a full reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc1',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc1', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        let reconnects = calls.filter(c => c.cmd === 'reconnect');
        assert.strictEqual(reconnects.length, 1, 'exactly one reconnect should be requested');
        assert.strictEqual(reconnects[0].account, 'acc1');
    });

    await t.test('re-auth lifts the auth-failure disable so the reconnect it requests can land', async () => {
        // setErrorState() switches an account off after a run of authentication failures by
        // setting imap.disabled. A password account is re-enabled when the operator saves new IMAP
        // settings, but an OAuth2 account has none to save - re-authorization is the fix, and
        // without lifting the flag here the reconnect below would bail out on it.
        let { ctx, calls, hash, writes } = createCtx(
            {
                account: 'acc-disabled',
                state: 'authenticationError',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                stored: {
                    imap: JSON.stringify({ disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-disabled', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.strictEqual(JSON.parse(hash.imap).disabled, false, 'the disable flag is lifted');
        assert.ok(!(DISABLED_MARKER in hash), 'and the marker is retired with it');
        assert.deepEqual(
            writes.map(w => `${w.op}:${w.field}`),
            ['hset:imap', `hdel:${DISABLED_MARKER}`],
            'both in one transaction, nothing else touched'
        );
        assert.deepEqual(
            calls.map(c => c.cmd),
            ['reconnect'],
            'and the reconnect is still requested'
        );
    });

    await t.test('re-auth un-parks an account that is no longer in an error state', async () => {
        // The regression this gate was missing. A parked account does not sit in an error state:
        // the connection gate reports it as `unset`, and the Gmail API and Outlook clients persist
        // that on every init. Requiring an error state here meant an API account could never be
        // recovered by re-authorizing it, only by hand-editing imap.disabled through the API.
        let { ctx, calls, hash } = createCtx(
            {
                account: 'acc-parked',
                state: 'unset',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                stored: {
                    imap: JSON.stringify({ disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-parked', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.strictEqual(JSON.parse(hash.imap).disabled, false, 'the disable flag is lifted');
        assert.deepEqual(
            calls.map(c => c.cmd),
            ['reconnect'],
            'un-parking an account is itself a reason to reconnect'
        );
    });

    await t.test('re-auth of a parked account lifts the park before any dispatch, and dispatches once', async () => {
        // A re-authorizing PUT often carries a settings difference as well - any client that echoes
        // GET output back does, since the stored default path never compares equal to the
        // normalized one. That used to dispatch cmd:'update' ahead of the lift, so the worker could
        // read the flag first and leave the account lifted but offline, and then suppress the
        // reconnect because an update had already been sent.
        let { ctx, calls, hash } = createCtx(
            {
                account: 'acc-parked-diff',
                state: 'unset',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                stored: {
                    imap: JSON.stringify({ disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        let seenAtDispatch = [];
        let call = ctx.call;
        ctx.call = async message => {
            seenAtDispatch.push({ cmd: message.cmd, disabled: JSON.parse(hash.imap).disabled, marker: DISABLED_MARKER in hash });
            return call(message);
        };

        await Account.prototype.update.call(ctx, { account: 'acc-parked-diff', path: ['*'], oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.deepEqual(
            calls.map(c => c.cmd),
            ['reconnect'],
            'the full reconnect supersedes the settings update rather than being suppressed by it'
        );
        assert.deepEqual(seenAtDispatch, [{ cmd: 'reconnect', disabled: false, marker: false }], 'and the account was already lifted when it went out');
    });

    await t.test('new IMAP credentials from the flagged route lift the park', async () => {
        // The password-account counterpart of OAuth2 re-authorization, and what the API field's
        // description promises: "save new IMAP settings - and syncing resumes". The documented way
        // to save them is a partial write of `imap.auth`, which persistUpdate() merges the stored
        // `disabled: true` into, so the intent read before the merge says nothing about the flag.
        let { ctx, calls, hash } = createCtx(
            {
                account: 'acc-imap-recred',
                state: 'unset',
                imap: { host: 'imap.test', auth: { user: 'user', pass: 'old' }, disabled: true }
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', auth: { user: 'user', pass: 'old' }, disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        let markerAtDispatch;
        let call = ctx.call;
        ctx.call = async message => {
            markerAtDispatch = DISABLED_MARKER in hash;
            return call(message);
        };

        await Account.prototype.update.call(ctx, { account: 'acc-imap-recred', imap: { partial: true, auth: { user: 'user', pass: 'new' } } }, REAUTHORIZED);

        assert.strictEqual(JSON.parse(hash.imap).disabled, false, 'the disable flag is lifted');
        assert.ok(!(DISABLED_MARKER in hash), 'and the marker retired');
        assert.deepEqual(
            calls.map(c => c.cmd),
            ['update'],
            'the changed settings reconnect the existing client'
        );
        assert.strictEqual(markerAtDispatch, false, 'after the lift, not before it');
    });

    await t.test('unchanged IMAP credentials from the flagged route do not lift the park', async () => {
        let { ctx, hash } = createCtx(
            {
                account: 'acc-imap-same',
                state: 'unset',
                imap: { host: 'imap.test', auth: { user: 'user', pass: 'old' }, disabled: true }
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', auth: { user: 'user', pass: 'old' }, disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-imap-same', imap: { partial: true, auth: { user: 'user', pass: 'old' } } }, REAUTHORIZED);

        assert.strictEqual(JSON.parse(hash.imap).disabled, true, 'restating the stored credentials is not a re-credential');
        assert.strictEqual(hash[DISABLED_MARKER], DISABLED_AT);
    });

    await t.test('re-auth does NOT lift a disable the operator set', async () => {
        // imap.disabled is also the operator's send-only switch. Re-authorization is routine for a
        // send-only account, so without the marker this would silently start syncing a mailbox
        // somebody had deliberately switched off.
        let { ctx, calls, hash, writes } = createCtx(
            {
                account: 'acc-sendonly',
                state: 'authenticationError',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            { stored: { imap: JSON.stringify({ disabled: true }) } }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-sendonly', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.strictEqual(JSON.parse(hash.imap).disabled, true, 'a deliberate disable survives re-authorization');
        assert.deepEqual(writes, [], 'and nothing is written');
        assert.deepEqual(
            calls.map(c => c.cmd),
            ['reconnect'],
            'the error state still earns a reconnect on its own'
        );
    });

    await t.test('re-auth retires a marker left behind by a manual re-enable', async () => {
        // The operator un-checked "Disable IMAP" themselves. The stale marker must go, otherwise it
        // would authorize lifting a later, deliberate disable.
        let { ctx, calls, hash, writes } = createCtx(
            {
                account: 'acc-stale-marker',
                state: 'connected',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', disabled: false }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-stale-marker', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.ok(!(DISABLED_MARKER in hash), 'the stale marker is retired');
        assert.deepEqual(
            writes.map(w => `${w.op}:${w.field}`),
            [`hdel:${DISABLED_MARKER}`],
            'the imap blob itself is left alone'
        );
        assert.deepEqual(calls, [], 'and an account that was never parked earns no reconnect');
    });

    await t.test('re-auth on an account that was never disabled writes nothing extra', async () => {
        let { ctx, calls, writes } = createCtx(
            {
                account: 'acc-enabled',
                state: 'authenticationError',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            { stored: { imap: JSON.stringify({ host: 'imap.test', disabled: false }) } }
        );

        await Account.prototype.update.call(ctx, { account: 'acc-enabled', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.deepEqual(writes, [], 'an account that is not disabled is left untouched');
        assert.deepEqual(
            calls.map(c => c.cmd),
            ['reconnect']
        );
    });

    await t.test('turning imap.disabled on retires the marker', async () => {
        // The operator switching a working account to send-only takes ownership of the flag, so
        // whatever the safety net recorded about an earlier automatic disable no longer describes it.
        let { ctx, hash } = createCtx(
            {
                account: 'acc-operator-disable',
                state: 'connected'
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', disabled: false }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );
        ctx.serializeAccountData = () => ({ imap: JSON.stringify({ host: 'imap.test', disabled: true }) });

        await Account.prototype.update.call(ctx, { account: 'acc-operator-disable', imap: { partial: true, disabled: true } });

        assert.ok(!(DISABLED_MARKER in hash), 'the marker cannot outlive an operator decision about the flag');
    });

    await t.test('restating imap.disabled on a parked account keeps the marker', async () => {
        // The admin edit form submits its "Disable IMAP" checkbox on every save, pre-checked from
        // the stored flag. Reading that restatement as a decision would let an unrelated save turn
        // an automatic park into a deliberate one, taking the page alert, the state badge and
        // "Resume syncing" with it and leaving the account unrecoverable by re-authorization.
        let { ctx, hash } = createCtx(
            {
                account: 'acc-untouched-checkbox',
                state: 'unset'
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );
        ctx.serializeAccountData = () => ({ imap: JSON.stringify({ host: 'imap.test', disabled: true }) });

        await Account.prototype.update.call(ctx, { account: 'acc-untouched-checkbox', imap: { partial: true, disabled: true, sentMailPath: 'Sent' } });

        assert.strictEqual(hash[DISABLED_MARKER], DISABLED_AT, 'a save that changes nothing about the flag leaves the park intact');
        assert.strictEqual(JSON.parse(hash.imap).disabled, true, 'and the account stays switched off');
    });

    await t.test('a partial update that does not name imap.disabled keeps the marker', async () => {
        // persistUpdate() merges the stored blob into a `partial` payload, so `disabled` is present
        // by the time the write happens. Reading the payload after the merge would make every
        // partial update look explicit and quietly disarm the recovery paths.
        let { ctx, hash } = createCtx(
            {
                account: 'acc-partial',
                state: 'connected',
                imap: { host: 'imap.test', disabled: true }
            },
            {
                stored: {
                    imap: JSON.stringify({ host: 'imap.test', disabled: true }),
                    [DISABLED_MARKER]: DISABLED_AT
                }
            }
        );
        ctx.serializeAccountData = () => ({ imap: JSON.stringify({ host: 'imap.test', disabled: true }) });

        await Account.prototype.update.call(ctx, { account: 'acc-partial', imap: { partial: true, resyncDelay: 900 } });

        assert.strictEqual(hash[DISABLED_MARKER], DISABLED_AT, 'the marker survives an update that says nothing about the flag');
    });

    await t.test('re-auth while in connectError requests a full reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc2',
            state: 'connectError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc2', oauth2: { accessToken: 'NEW', refreshToken: 'R0' } }, REAUTHORIZED);

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1);
    });

    await t.test('unflagged credential write in an error state does NOT reconnect (hot-loop regression)', async () => {
        // The regression. renewAccessToken() persists a fresh access token through update() while
        // the stored state is still authenticationError - exactly these inputs. Inferring re-auth
        // from state alone dispatched cmd:'reconnect' here, which rebuilt the IMAPClient, discarded
        // its backoff, and (with invalidateAccessToken backdating the expiry) latched a CPU-pinning
        // loop. Every unattended writer reaches this path, so it must stay silent without the flag.
        let { ctx, calls } = createCtx({
            account: 'acc3',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc3', oauth2: { accessToken: 'NEW', refreshToken: 'R0' } });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'an unflagged credential write must never request a reconnect');
    });

    await t.test('explicitly non-reauthorized update in an error state does NOT reconnect', async () => {
        // Guards against an `options.reauthorized !== undefined` style implementation.
        let { ctx, calls } = createCtx({
            account: 'acc4',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc4', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, { reauthorized: false });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('routine token renewal while connected does NOT reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc5',
            state: 'connected',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc5', oauth2: { accessToken: 'NEW', refreshToken: 'R0' } });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'no reconnect for a connected account');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });

    await t.test('flagged update with unchanged credentials does NOT reconnect', async () => {
        // userFlag-only partial update keeps the existing tokens after merge, so even an
        // explicitly re-authorized update has nothing to act on.
        let { ctx, calls } = createCtx({
            account: 'acc6',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc6', oauth2: { accessToken: 'OLD', refreshToken: 'R0', userFlag: true } }, REAUTHORIZED);

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'no reconnect when credentials are unchanged');
    });

    await t.test('imap config change still uses cmd:update, not reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc7',
            state: 'connected',
            imap: { host: 'old.example.com' }
        });

        await Account.prototype.update.call(ctx, {
            account: 'acc7',
            imap: { host: 'new.example.com' }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1, 'imap change requests cmd:update');
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('re-auth in error state without a call dispatcher does not crash (EMAILENGINE-4)', async () => {
        // Regression: some Account instances are built without a `call` channel. Before the fix
        // the reconnect gate hit `this.call(...)` and threw "TypeError: this.call is not a function",
        // which the try/catch turned into a handled error shipped to Sentry. A missing dispatcher
        // must degrade to a warning, never an error, and must not reject.
        let { ctx, calls } = createCtx({
            account: 'acc8',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        delete ctx.call;
        let errorLogged = false;
        ctx.logger.error = () => {
            errorLogged = true;
        };

        await assert.doesNotReject(Account.prototype.update.call(ctx, { account: 'acc8', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED));

        assert.strictEqual(calls.length, 0, 'no RPC should be attempted without a dispatcher');
        assert.strictEqual(errorLogged, false, 'missing dispatcher must not be reported as an error');
    });

    await t.test('imap config change without a call dispatcher does not throw', async () => {
        // The config-change branch dispatches cmd:update and has no try/catch, so a missing
        // dispatcher there would throw uncaught. It must be guarded too.
        let { ctx } = createCtx({
            account: 'acc9',
            state: 'connected',
            imap: { host: 'old.example.com' }
        });
        delete ctx.call;

        await assert.doesNotReject(
            Account.prototype.update.call(ctx, {
                account: 'acc9',
                imap: { host: 'new.example.com' }
            })
        );
    });

    await t.test('reconnect dispatch failure does not reject the update', async () => {
        // Credentials are already persisted by the time the reconnect is dispatched, so a failed
        // dispatch must be swallowed (logged) rather than surfaced as a 500 to the user.
        let { ctx, calls } = createCtx({
            account: 'acc10',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        ctx.call = async message => {
            calls.push(message);
            if (message.cmd === 'reconnect') {
                throw new Error('worker unavailable');
            }
            return true;
        };

        await assert.doesNotReject(Account.prototype.update.call(ctx, { account: 'acc10', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED));

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'reconnect was attempted');
    });
});

// Per-account serialization of the read-modify-write half of update(). Two writers interleaving
// between loadAccountData() and the hmset lose one of the merges; the case that matters is an
// unattended token refresh landing inside an admin update and restoring a stale refreshToken.
test('Account.update serialization', async t => {
    await t.test('takes and releases a per-account update lock', async () => {
        let { ctx, lockEvents } = createCtx({
            account: 'acc11',
            state: 'connected',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc11', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } });

        assert.deepStrictEqual(
            lockEvents.map(e => e.event),
            ['acquire', 'release']
        );
        // Keyed per account, so an update to one account never blocks another
        assert.strictEqual(lockEvents[0].key, 'account:update:acc11');
    });

    await t.test('releases the lock before dispatching to the IMAP worker', async () => {
        // The dispatch is an RPC whose connection setup can itself persist an account change (a
        // token renewal during connect). Holding the lock across it would make a writer wait on
        // its own dispatch until the 5s acquisition timeout expires.
        let { ctx, lockEvents } = createCtx({
            account: 'acc12',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'acc12', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        const releaseAt = lockEvents.findIndex(e => e.event === 'release');
        const dispatchAt = lockEvents.findIndex(e => e.event === 'call');

        assert.ok(releaseAt >= 0, 'lock was released');
        assert.ok(dispatchAt >= 0, 'a command was dispatched');
        assert.ok(releaseAt < dispatchAt, 'the lock must be released before the RPC dispatch');
    });

    await t.test('releases the lock when the write throws', async () => {
        let { ctx, lockEvents } = createCtx({
            account: 'acc13',
            state: 'connected',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        ctx.loadAccountData = async () => {
            throw new Error('redis is gone');
        };

        await assert.rejects(Account.prototype.update.call(ctx, { account: 'acc13', name: 'x' }), /redis is gone/);

        assert.deepStrictEqual(
            lockEvents.map(e => e.event),
            ['acquire', 'release'],
            'a failed write must not leak the lock'
        );
    });

    await t.test('proceeds when the lock cannot be acquired', async () => {
        // Fail-open: the critical section is a few Redis round trips, so a timeout here means
        // Redis is already unhealthy. Refusing the write would break token refreshes for every
        // account rather than losing a rare merge.
        let { ctx, calls, lockEvents } = createCtx(
            {
                account: 'acc14',
                state: 'authenticationError',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                lockOverrides: { waitAcquireLock: async () => ({ success: false }) }
            }
        );

        await Account.prototype.update.call(ctx, { account: 'acc14', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1, 'the update still went through');
        // Nothing was acquired, so nothing may be released
        assert.strictEqual(lockEvents.filter(e => e.event === 'release').length, 0, 'a lock that was never acquired must not be released');
    });

    await t.test('proceeds when the lock backend throws', async () => {
        let { ctx, calls } = createCtx(
            {
                account: 'acc15',
                state: 'connected',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                lockOverrides: {
                    waitAcquireLock: async () => {
                        throw new Error('lock backend unavailable');
                    }
                }
            }
        );

        await assert.doesNotReject(Account.prototype.update.call(ctx, { account: 'acc15', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }));
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });

    await t.test('a failed release does not mask the result', async () => {
        let { ctx } = createCtx(
            {
                account: 'acc16',
                state: 'connected',
                oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
            },
            {
                lockOverrides: {
                    releaseLock: async () => {
                        throw new Error('release failed');
                    }
                }
            }
        );

        const result = await Account.prototype.update.call(ctx, { account: 'acc16', name: 'x' });
        assert.deepStrictEqual(result, { account: 'acc16' });
    });
});

// Persisting a partial update. An empty payload - and, before serializeAccountData learned to write a
// cleared marker, a payload that only removed a field - serializes to no field/value pairs at all. Redis
// rejects an hmset with none ("wrong number of arguments"), which surfaced as a 500 on a valid request,
// so the write has to be skipped rather than issued empty.
test('Account.update field persistence', async t => {
    // Records the commands queued on the pipeline. The shared mock above accepts anything and always
    // reports OK, which is precisely why the empty-hmset bug went unnoticed there.
    function createRecordingCtx(serialized) {
        const commands = [];
        const pipeline = {
            exec: async () => commands.map(command => [null, command.name === 'hmset' ? 'OK' : 1]),
            hmset(key, fields) {
                commands.push({ name: 'hmset', key, fields });
                return this;
            },
            hdel(key, field) {
                commands.push({ name: 'hdel', key, field });
                return this;
            },
            hset() {
                return this;
            },
            sadd() {
                return this;
            },
            srem() {
                return this;
            }
        };

        // Same collaborators as createCtx above; only the pipeline and the serializer differ.
        const { ctx } = createCtx({ account: 'acc-fields', state: 'connected' });
        Object.assign(ctx, {
            redis: Object.assign({}, mockRedis, { multi: () => pipeline }),
            getAccountKey: () => 'iad:acc-fields',
            serializeAccountData: () => serialized
        });

        return { ctx, commands };
    }

    await t.test('writes the serialized fields when there are any', async () => {
        const { ctx, commands } = createRecordingCtx({ name: 'Nyan Cat' });

        await Account.prototype.update.call(ctx, { account: 'acc-fields', name: 'Nyan Cat' });

        assert.deepStrictEqual(
            commands.map(command => command.name),
            ['hmset']
        );
        assert.deepStrictEqual(commands[0].fields, { name: 'Nyan Cat' });
    });

    await t.test('skips the write when the payload serializes to nothing', async () => {
        const { ctx, commands } = createRecordingCtx({});

        await assert.doesNotReject(Account.prototype.update.call(ctx, { account: 'acc-fields' }));

        assert.deepStrictEqual(commands, [], 'an empty hmset must never be queued');
    });
});

// The identity pin has to be removable, so it cannot ride serializeAccountData's default branch: that
// drops nulls, and hmset only ever adds keys, which would leave the pin settable but never clearable.
test('Account expectedEmail round-trip', async t => {
    const serialize = accountData => Account.prototype.serializeAccountData.call({ logger: createMockLogger() }, accountData);
    const unserialize = accountData => Account.prototype.unserializeAccountData.call({ logger: createMockLogger() }, accountData);

    await t.test('stores an address and reads it back', () => {
        assert.strictEqual(serialize({ expectedEmail: 'owner@example.com' }).expectedEmail, 'owner@example.com');
        assert.strictEqual(unserialize({ expectedEmail: 'owner@example.com' }).expectedEmail, 'owner@example.com');
    });

    await t.test('clearing writes a marker that reads back as unset', () => {
        // null must survive into the write, otherwise the stored value would simply persist.
        assert.strictEqual(serialize({ expectedEmail: null }).expectedEmail, '');
        assert.ok(!('expectedEmail' in unserialize({ expectedEmail: '' })), 'a cleared pin must not be reported as set');
    });
});

test('a park is reported as a fault, not as a send-only configuration', async t => {
    const ctx = Object.assign(Object.create(Account.prototype), { logger: createMockLogger() });

    await t.test('isSendOnlyAccount ignores the flag the safety net set', () => {
        // Send-only is a configuration, a park is a fault. Reporting a parked gmailService or
        // password account as send-only rendered it "API Send-only" and hid its IMAP card, and the
        // stored error with it.
        assert.strictEqual(
            ctx.isSendOnlyAccount({ imap: { disabled: true }, oauth2: { provider: 'gmailService' }, _authFailureDisabledAt: DISABLED_AT }),
            false
        );
        assert.strictEqual(ctx.isSendOnlyAccount({ imap: { host: 'imap.test', disabled: true }, _authFailureDisabledAt: DISABLED_AT }), false);
    });

    await t.test('isSendOnlyAccount still honors the operator switch', () => {
        assert.strictEqual(ctx.isSendOnlyAccount({ imap: { disabled: true }, oauth2: { provider: 'gmailService' } }), true);
        assert.strictEqual(ctx.isSendOnlyAccount({ imap: { host: 'imap.test', disabled: true } }), true);
        assert.strictEqual(ctx.isSendOnlyAccount({ imap: { host: 'imap.test', disabled: false } }), false);
    });

    await t.test('isAuthFailureDisabled recognises both generations of the park', () => {
        // The marker, since 2.79.4
        assert.strictEqual(isAuthFailureDisabled({ imap: { disabled: true }, _authFailureDisabledAt: DISABLED_AT }), true);
        // The flag plus the threshold text, which is all a park before the marker left behind on a
        // password account. Nothing but the park writes that text.
        assert.strictEqual(
            isAuthFailureDisabled({ imap: { host: 'imap.test', disabled: true }, lastErrorState: { description: AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION } }),
            true
        );
        // The operator's switch, with or without an unrelated error beside it
        assert.strictEqual(isAuthFailureDisabled({ imap: { host: 'imap.test', disabled: true } }), false);
        assert.strictEqual(isAuthFailureDisabled({ imap: { host: 'imap.test', disabled: true }, lastErrorState: { response: 'timeout' } }), false);
        // A stale marker on an account the operator re-enabled by hand
        assert.strictEqual(isAuthFailureDisabled({ imap: { host: 'imap.test', disabled: false }, _authFailureDisabledAt: DISABLED_AT }), false);
    });
});
