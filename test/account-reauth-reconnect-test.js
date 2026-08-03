'use strict';

// Unit coverage for the OAuth re-authorization reconnect gate in Account.update().
// When an API client saves new OAuth credentials for an account that is currently in an error
// state, a full reconnect must be requested so syncing resumes without a manual "Reconnect".
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

const { Account } = require('../lib/account');

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
function createCtx(oldAccountData, lockOverrides) {
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

    // Inherit from the real prototype so update() reaches the real persistUpdate() and
    // dispatchPostUpdateCommands(); only the collaborators below are stubbed.
    let ctx = Object.assign(Object.create(Account.prototype), {
        account: oldAccountData.account,
        timeout: 1000,
        logger: createMockLogger(),
        redis: mockRedis,
        getLock: () => lock,
        getAccountKey: () => `iad:${oldAccountData.account}`,
        serializeAccountData: () => ({}),
        loadAccountData: async () => oldAccountData,
        call: async message => {
            calls.push(message);
            lockEvents.push({ event: 'call', cmd: message.cmd });
            return true;
        }
    });
    return { ctx, calls, lockEvents };
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
                waitAcquireLock: async () => ({ success: false })
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
                waitAcquireLock: async () => {
                    throw new Error('lock backend unavailable');
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
                releaseLock: async () => {
                    throw new Error('release failed');
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
