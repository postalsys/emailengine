'use strict';

// Account deletion removes what the provider keeps for the account before the account record goes.
// Regression: the record was unlinked first and the worker told afterwards, so OutlookClient.delete()
// found no stored subscription and had no token to delete one with, and a Gmail Pub/Sub watch was
// never stopped at all. Graph went on posting notifications for up to three days, Gmail for seven.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const { REDIS_PREFIX } = require('../lib/consts');
const { BaseClient } = require('../lib/email-client/base-client');
const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { createMockLogger } = require('./helpers/mock-logger');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(test);

async function storeAccount() {
    const account = `delete-teardown-${crypto.randomBytes(6).toString('hex')}`;
    await redis.hmset(`${REDIS_PREFIX}iad:${account}`, {
        account,
        name: 'Delete test',
        email: 'user@example.com',
        imap: JSON.stringify({ host: 'imap.example.com', port: 993, secure: true, auth: { user: 'user@example.com', pass: 'x' } })
    });
    await redis.sadd(`${REDIS_PREFIX}ia:accounts`, account);
    return account;
}

test('account delete', async t => {
    await t.test('tears the provider side down while the record still exists, then deletes', async () => {
        const account = await storeAccount();
        const seen = [];
        const accountObject = new Account({
            account,
            redis,
            logger: createMockLogger(),
            timeout: 1000,
            call: async message => {
                seen.push({ cmd: message.cmd, recordExists: await redis.exists(`${REDIS_PREFIX}iad:${account}`) });
                return true;
            }
        });

        const result = await accountObject.delete();
        assert.deepStrictEqual(result, { account, deleted: true });
        assert.deepStrictEqual(seen, [
            { cmd: 'teardown', recordExists: 1 },
            { cmd: 'delete', recordExists: 0 }
        ]);
    });

    await t.test('a failed teardown does not stop the deletion', async () => {
        const account = await storeAccount();
        const logger = createMockLogger();
        const accountObject = new Account({
            account,
            redis,
            logger,
            timeout: 1000,
            call: async message => {
                if (message.cmd === 'teardown') {
                    const err = new Error('Request timed out');
                    err.code = 'Timeout';
                    throw err;
                }
                return true;
            }
        });

        assert.deepStrictEqual(await accountObject.delete(), { account, deleted: true });
        assert.strictEqual(await redis.exists(`${REDIS_PREFIX}iad:${account}`), 0);
        assert.ok(logger.entries.some(entry => entry.msg === 'Failed to release provider resources before account delete'));
    });

    await t.test('an account no worker holds is deleted without a warning', async () => {
        // what the main thread answers for an account no worker holds, see the teardown command in server.js
        const account = await storeAccount();
        const logger = createMockLogger();
        const accountObject = new Account({
            account,
            redis,
            logger,
            timeout: 1000,
            call: async message => message.cmd !== 'teardown'
        });

        assert.deepStrictEqual(await accountObject.delete(), { account, deleted: true });
        assert.ok(!logger.entries.some(entry => entry.level === 'warn'), JSON.stringify(logger.entries));
    });
});

test('releaseRemoteResources()', async t => {
    await t.test('nothing to release for IMAP accounts', async () => {
        assert.strictEqual(await Object.create(BaseClient.prototype).releaseRemoteResources(), false);
    });

    await t.test('Graph: deletes the stored subscription and forgets it', async () => {
        const requests = [];
        const hdels = [];
        const client = Object.assign(Object.create(OutlookClient.prototype), {
            account: 'a',
            logger: createMockLogger(),
            getAccountKey: () => 'iad:a',
            getStoredSubscription: async () => ({ id: 'sub-1' }),
            request: async (url, method) => requests.push([url, method]),
            redis: { hdel: async (...args) => hdels.push(args) }
        });

        assert.strictEqual(await client.releaseRemoteResources(), true);
        assert.deepStrictEqual(requests, [['/subscriptions/sub-1', 'DELETE']]);
        assert.deepStrictEqual(hdels, [['iad:a', 'outlookSubscription']]);
    });

    await t.test('Graph: no subscription, no request; a failed request is logged', async () => {
        const requests = [];
        const logger = createMockLogger();
        const client = Object.assign(Object.create(OutlookClient.prototype), {
            account: 'a',
            logger,
            getStoredSubscription: async () => ({}),
            request: async () => requests.push(1)
        });
        assert.strictEqual(await client.releaseRemoteResources(), false);
        assert.strictEqual(requests.length, 0);

        client.getStoredSubscription = async () => ({ id: 'sub-2' });
        client.request = async () => {
            throw new Error('401');
        };
        assert.strictEqual(await client.releaseRemoteResources(), false);
        assert.strictEqual(logger.entries[0].msg, 'Failed to delete MS Graph subscription');
    });

    function gmailClient(accountData, storedWatch = accountData.watchResponse ? JSON.stringify(accountData.watchResponse) : null) {
        const requests = [];
        const loads = [];
        const client = Object.assign(Object.create(GmailClient.prototype), {
            account: 'a',
            logger: createMockLogger(),
            redis: { hget: async (key, field) => (field === 'watchResponse' ? storedWatch : null) },
            getAccountKey: () => 'iad:a',
            accountObject: {
                loadAccountData: async () => {
                    loads.push(1);
                    return accountData;
                }
            },
            prepare: async () => {},
            request: async (url, method) => requests.push([url, method])
        });
        return { client, requests, loads };
    }

    await t.test('Gmail: stops an armed Pub/Sub watch', async () => {
        const { client, requests } = gmailClient({ _app: { pubSubApp: 'pubsub' }, watchResponse: { historyId: '1' } });
        assert.strictEqual(await client.releaseRemoteResources(), true);
        assert.strictEqual(requests.length, 1);
        assert.match(requests[0][0], /\/gmail\/v1\/users\/me\/stop$/);
        assert.strictEqual(requests[0][1], 'post');
    });

    await t.test('Gmail: no watch, nothing to stop', async () => {
        for (const accountData of [{}, { _app: { pubSubApp: 'pubsub' } }, { watchResponse: { historyId: '1' } }]) {
            const { client, requests } = gmailClient(accountData);
            assert.strictEqual(await client.releaseRemoteResources(), false);
            assert.strictEqual(requests.length, 0);
        }
    });

    await t.test('Gmail: an account without a stored watch is not loaded at all', async () => {
        for (const storedWatch of [null, 'null']) {
            const { client, requests, loads } = gmailClient({ _app: { pubSubApp: 'pubsub' } }, storedWatch);
            assert.strictEqual(await client.releaseRemoteResources(), false);
            assert.strictEqual(loads.length, 0, String(storedWatch));
            assert.strictEqual(requests.length, 0);
        }
    });
});
