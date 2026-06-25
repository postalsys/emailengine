'use strict';

// Unit coverage for the re-authorization reconnect gate added to Account.create().
//
// When an EXISTING account that is currently in a non-operational error state
// (authenticationError/connectError) is re-registered - which is what the interactive OAuth re-auth
// redirect and the IMAP re-credentials form both do - create() must request a FULL reconnect
// (cmd:'reconnect'), not an in-place cmd:'update'. cmd:'update' only calls reconnect() on the
// existing client instance, which cannot switch client type (IMAP <-> API) and is a no-op against a
// torn-down connection, so syncing would not resume without a manual "Reconnect". Healthy accounts
// keep cmd:'update' and brand-new accounts keep cmd:'new'.
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

function createMockLogger() {
    let logger = {};
    for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = () => {};
    }
    return logger;
}

// Builds a mock `this` for Account.prototype.create and records every RPC call() it issues.
// `execResult` is what the create() Redis pipeline's exec() resolves to (it drives the new vs
// existing branch and the old state). `throwOnReconnect` makes the reconnect RPC reject, to exercise
// the try/catch guard around the reconnect dispatch.
function createCtx(execResult, { throwOnReconnect = false } = {}) {
    let calls = [];

    // Chainable pipeline builder - every command returns the builder, exec() resolves execResult.
    let builder = {
        hgetall() {
            return this;
        },
        hmset() {
            return this;
        },
        hsetnx() {
            return this;
        },
        sadd() {
            return this;
        },
        hset() {
            return this;
        },
        srem() {
            return this;
        },
        exec: async () => execResult
    };

    let redis = Object.assign(createMockRedis(), {
        multi: () => builder
    });

    let ctx = {
        account: null,
        timeout: 1000,
        logger: createMockLogger(),
        redis,
        getAccountKey: () => 'iad:test',
        serializeAccountData: () => ({}),
        unserializeAccountData: data => data,
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
    };

    return { ctx, calls };
}

// Pipeline result tail shared by every case: hmset OK, then the hsetnx/sadd ops (values irrelevant).
const OK_TAIL = [
    [null, 'OK'], // [1] hmset
    [null, 0], // [2] hsetnx state
    [null, 0], // [3] hsetnx runIndex
    [null, 0], // [4] hsetnx state:count
    [null, 1] // [5] sadd accounts
];

// hgetall ([0]) carries the pre-overwrite account hash. A truthy `account` field => existing account.
function existing(state) {
    return [[null, { account: 'acc', state }], ...OK_TAIL];
}
function freshAccount() {
    return [[null, {}], ...OK_TAIL];
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
        let { ctx, calls } = createCtx(freshAccount());

        let res = await Account.prototype.create.call(ctx, { account: 'acc4', imapIndexer: 'full' });

        assert.strictEqual(calls.filter(c => c.cmd === 'new').length, 1);
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
        assert.strictEqual(res.state, 'new');
    });

    await t.test('existing account in unset (sync disabled) keeps cmd:update', async () => {
        // Regression guard: "unset" means the user disabled syncing - do not force-connect it.
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
