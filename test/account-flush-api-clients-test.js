'use strict';

// PUT /v1/account/{account}/flush on Gmail API and MS Graph accounts. It used to fail with a 500
// (`pause is not a function`: only IMAPClient had one), and had it run it would not have flushed
// anything: those clients keep their sync position in the account hash, which the flush left alone,
// and for Graph it removed the announced set while keeping the point that set started from, so the
// next recovery pass would have announced every message since then again.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account, FLUSHED_SYNC_FIELDS } = require('../lib/account');
const { REDIS_PREFIX, OUTLOOK_SYNC_MAX_LOOKBACK } = require('../lib/consts');
const { BaseClient } = require('../lib/email-client/base-client');
const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient, flushRecoveryStart } = require('../lib/email-client/outlook-client');
const { createMockLogger } = require('./helpers/mock-logger');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(test);

const created = [];

test.after(async () => {
    for (const account of created) {
        await redis.del(`${REDIS_PREFIX}iad:${account}`);
    }
});

async function storeApiAccount(extra) {
    const account = `flush-test-${crypto.randomBytes(6).toString('hex')}`;
    created.push(account);
    await redis.hmset(
        `${REDIS_PREFIX}iad:${account}`,
        Object.assign(
            {
                account,
                name: 'Flush test',
                email: 'user@example.com',
                oauth2: JSON.stringify({ provider: 'gmail', auth: { user: 'user@example.com' } })
            },
            extra
        )
    );
    return account;
}

test('account flush on API-backed accounts', async t => {
    await t.test('clears the sync positions the API clients keep in the account hash', async () => {
        const account = await storeApiAccount({
            googleHistoryId: '123456',
            googleHistoryProcessing: '123400',
            outlookAnnouncedInSince: '1700000000000',
            outlookRecoveredUntil: '1700000500000',
            outlookSubscription: JSON.stringify({ id: 'sub-1' })
        });

        const calls = [];
        const accountObject = new Account({
            account,
            redis,
            call: async message => {
                calls.push(message.cmd);
                return true;
            },
            logger: createMockLogger(),
            timeout: 1000
        });

        assert.strictEqual(await accountObject.flush({ flush: true, notifyFrom: 'now' }), true);

        const stored = await redis.hgetall(`${REDIS_PREFIX}iad:${account}`);
        for (const field of FLUSHED_SYNC_FIELDS) {
            assert.ok(!(field in stored), `${field} is cleared`);
        }
        // only the sync position goes, not the rest of the account
        assert.strictEqual(stored.outlookSubscription, JSON.stringify({ id: 'sub-1' }));
        assert.ok(stored.notifyFrom);
        assert.deepStrictEqual(calls, ['pause']);
    });

    await t.test('every client type can be paused and resumed (regression: pause is not a function)', () => {
        for (const Client of [GmailClient, OutlookClient]) {
            assert.strictEqual(typeof Client.prototype.pause, 'function', `${Client.name}.pause`);
            assert.strictEqual(typeof Client.prototype.resume, 'function', `${Client.name}.resume`);
        }
    });

    await t.test('BaseClient.pause() closes and resume() reconnects without waiting for it', async () => {
        const events = [];
        let finishReconnect;
        const client = Object.assign(Object.create(BaseClient.prototype), {
            logger: createMockLogger(),
            account: 'a',
            async close() {
                events.push('close');
            },
            reconnect() {
                events.push('reconnect');
                return new Promise(resolve => (finishReconnect = resolve));
            }
        });

        assert.strictEqual(await client.pause(), true);
        // resolves while the reconnect is still running, the RPC caller has a timeout
        assert.strictEqual(await client.resume(), true);
        assert.deepStrictEqual(events, ['close', 'reconnect']);
        finishReconnect();
    });

    await t.test('a failed reconnect on resume is logged, not thrown', async () => {
        const logger = createMockLogger();
        const client = Object.assign(Object.create(BaseClient.prototype), {
            logger,
            account: 'a',
            reconnect: async () => {
                throw new Error('token refresh failed');
            }
        });
        await client.resume();
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(logger.entries[0].msg, 'Resuming failed');
    });
});

test('Graph recovery pass after a flush', async t => {
    const now = Date.parse('2026-10-21T12:00:00.000Z');

    await t.test('no pass for the default flush from now', () => {
        assert.strictEqual(flushRecoveryStart(new Date(now - 5 * 1000).toISOString(), now), null);
        assert.strictEqual(flushRecoveryStart(undefined, now), null);
        assert.strictEqual(flushRecoveryStart('not a date', now), null);
    });

    await t.test('starts at an earlier notifyFrom, bounded like "Run sync"', () => {
        const hourAgo = now - 3600 * 1000;
        assert.strictEqual(flushRecoveryStart(new Date(hourAgo).toISOString(), now), hourAgo);
        assert.strictEqual(flushRecoveryStart(new Date(now - 90 * 24 * 3600 * 1000), now), now - OUTLOOK_SYNC_MAX_LOOKBACK);
    });

    await t.test('resume reconnects, then runs the pass from notifyFrom', async () => {
        const since = Date.now() - 2 * 3600 * 1000;
        const events = [];
        const client = Object.assign(Object.create(OutlookClient.prototype), {
            logger: createMockLogger(),
            account: 'a',
            closed: false,
            state: 'connected',
            accountObject: { loadAccountData: async () => ({ notifyFrom: new Date(since).toISOString() }) },
            async reconnect() {
                events.push('reconnect');
            },
            async syncMailboxes(opts) {
                events.push(['sync', opts.since]);
            }
        });

        await client.resumeAfterFlush();
        assert.deepStrictEqual(events, ['reconnect', ['sync', since]]);
    });

    await t.test('no pass when the account did not come back connected', async () => {
        const events = [];
        const client = Object.assign(Object.create(OutlookClient.prototype), {
            logger: createMockLogger(),
            account: 'a',
            closed: false,
            state: 'authenticationError',
            accountObject: { loadAccountData: async () => ({ notifyFrom: new Date(Date.now() - 3600 * 1000).toISOString() }) },
            async reconnect() {
                events.push('reconnect');
            },
            async syncMailboxes() {
                events.push('sync');
            }
        });

        await client.resumeAfterFlush();
        assert.deepStrictEqual(events, ['reconnect']);
    });
});
