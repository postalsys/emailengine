'use strict';

// Unit coverage for the OAuth re-authorization reconnect gate added to Account.update().
// When new OAuth credentials are saved for an account that is currently in an error state,
// a full reconnect must be requested so syncing resumes without a manual "Reconnect".
// Routine token renewal (account is connected) must NOT trigger a reconnect.

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

test('Account.update OAuth re-auth reconnect gate', async t => {
    await t.test('re-auth while in authenticationError requests a full reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc1',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        await Account.prototype.update.call(ctx, {
            account: 'acc1',
            oauth2: { accessToken: 'NEW', refreshToken: 'R1' }
        });

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

        await Account.prototype.update.call(ctx, {
            account: 'acc2',
            oauth2: { accessToken: 'NEW', refreshToken: 'R0' }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 1);
    });

    await t.test('routine token renewal while connected does NOT reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc3',
            state: 'connected',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        // Mirrors renewAccessToken(): a fresh access token saved on a healthy account.
        await Account.prototype.update.call(ctx, {
            account: 'acc3',
            oauth2: { accessToken: 'NEW', refreshToken: 'R0' }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'no reconnect for a connected account');
        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 0);
    });

    await t.test('partial oauth2 update (no credential change) in error state does NOT reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc4',
            state: 'authenticationError',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0' }
        });

        // userFlag-only partial update keeps the existing tokens after merge.
        await Account.prototype.update.call(ctx, {
            account: 'acc4',
            oauth2: { accessToken: 'OLD', refreshToken: 'R0', userFlag: true }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0, 'no reconnect when credentials are unchanged');
    });

    await t.test('imap config change still uses cmd:update, not reconnect', async () => {
        let { ctx, calls } = createCtx({
            account: 'acc5',
            state: 'connected',
            imap: { host: 'old.example.com' }
        });

        await Account.prototype.update.call(ctx, {
            account: 'acc5',
            imap: { host: 'new.example.com' }
        });

        assert.strictEqual(calls.filter(c => c.cmd === 'update').length, 1, 'imap change requests cmd:update');
        assert.strictEqual(calls.filter(c => c.cmd === 'reconnect').length, 0);
    });
});
