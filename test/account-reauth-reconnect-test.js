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
function createCtx(oldAccountData) {
    let calls = [];
    let ctx = {
        account: oldAccountData.account,
        timeout: 1000,
        logger: createMockLogger(),
        redis: mockRedis,
        getAccountKey: () => `iad:${oldAccountData.account}`,
        serializeAccountData: () => ({}),
        loadAccountData: async () => oldAccountData,
        call: async message => {
            calls.push(message);
            return true;
        }
    };
    return { ctx, calls };
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

// The auth-failure park (ACCOUNT_AUTH_FAILURE_DISABLED_KEY) is the only terminal backstop on the
// reconnect loop, so what lifts it matters as much as what sets it.
const { ACCOUNT_AUTH_FAILURE_DISABLED_KEY } = require('../lib/consts');

function createParkCtx(oldAccountData) {
    const hdelFields = [];
    const redis = Object.assign(createMockRedis(), {
        hdel: async (key, ...fields) => {
            hdelFields.push(...fields);
        }
    });

    const ctx = {
        account: oldAccountData.account,
        timeout: 1000,
        logger: createMockLogger(),
        redis,
        getAccountKey: () => `iad:${oldAccountData.account}`,
        serializeAccountData: () => ({}),
        loadAccountData: async () => oldAccountData,
        call: async () => true
    };

    return { ctx, parkCleared: () => hdelFields.includes(ACCOUNT_AUTH_FAILURE_DISABLED_KEY) };
}

test('Account.update auth-failure park clearing', async t => {
    await t.test('an unrelated update does not lift the park', async () => {
        // The regression: PUT /v1/account/{account} passes reauthorized:true on every call
        // regardless of payload. Because the park write also clears the error counters, re-parking
        // needs a fresh three-day window - so if a bare `{name}` PUT lifted the park, anything
        // PUTing an account periodically would keep a broken account retrying forever.
        const { ctx, parkCleared } = createParkCtx({
            account: 'park1',
            state: 'unset',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'park1', name: 'Renamed' }, REAUTHORIZED);

        assert.strictEqual(parkCleared(), false, 'a payload with no credential change must leave the park in place');
    });

    await t.test('re-authorized OAuth2 credentials lift the park', async () => {
        const { ctx, parkCleared } = createParkCtx({
            account: 'park2',
            state: 'unset',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'park2', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } }, REAUTHORIZED);

        assert.strictEqual(parkCleared(), true, 'fresh OAuth2 tokens must revive a parked account');
    });

    await t.test('a changed IMAP password lifts the park', async () => {
        // The park is transport-neutral, so a password account must be recoverable the same way -
        // this is the admin UI "save credentials" path.
        const { ctx, parkCleared } = createParkCtx({
            account: 'park3',
            state: 'unset',
            imap: { auth: { user: 'u', pass: 'OLDPASS' } }
        });

        await Account.prototype.update.call(ctx, { account: 'park3', imap: { auth: { user: 'u', pass: 'NEWPASS' } } }, REAUTHORIZED);

        assert.strictEqual(parkCleared(), true, 'a corrected IMAP password must revive a parked account');
    });

    await t.test('an unflagged update never lifts the park', async () => {
        // Unattended writers (renewAccessToken, invalidateAccessToken, the Gmail/Outlook init()
        // rewrites) all reach update() without the flag and must stay inert here.
        const { ctx, parkCleared } = createParkCtx({
            account: 'park4',
            state: 'unset',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, { account: 'park4', oauth2: { accessToken: 'NEW', refreshToken: 'R1' } });

        assert.strictEqual(parkCleared(), false, 'an unattended credential write must not lift the park');
    });
});
