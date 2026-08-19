'use strict';

// Unit coverage for accountExists()/accountsExist() (lib/account.js).
//
// The admin listings ask "does this account still exist" once per distinct account on the page,
// because rows outlive the account they name - deleting an account leaves its suppression-list
// entries and its access tokens behind, and a row naming a dead account must not be rendered as a
// link to a page that 404s. The batched form answers the same question in one round trip, and it
// reads raw pipeline results, so what it makes of an error reply is worth pinning.

const test = require('node:test');
const assert = require('node:assert').strict;

const { accountExists, accountsExist } = require('../lib/account');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const PRESENT = ['exists-test-a', 'exists-test-b'];
const ABSENT = 'exists-test-gone';

const accountKey = account => `${REDIS_PREFIX}iad:${account}`;

test.before(async () => {
    for (const account of PRESENT) {
        await redis.hset(accountKey(account), 'account', account);
    }
    await redis.del(accountKey(ABSENT));
});

registerRedisTeardown(redis, async () => {
    for (const account of PRESENT) {
        await redis.del(accountKey(account));
    }
});

test('accountsExist()', async t => {
    await t.test('gives the same answer as accountExists(), one account at a time', async () => {
        const accounts = [...PRESENT, ABSENT];
        const batched = await accountsExist(redis, accounts);

        for (const account of accounts) {
            assert.strictEqual(batched.get(account), await accountExists(redis, account), `${account} must read the same either way`);
        }
    });

    await t.test('keys the answers by account rather than by position', async () => {
        // A pipeline replies in order, so an off-by-one here would silently mark a live account dead
        // and a deleted one live - which is exactly the pair of mistakes the listing renders
        const batched = await accountsExist(redis, [ABSENT, PRESENT[0]]);

        assert.deepEqual(
            [...batched],
            [
                [ABSENT, false],
                [PRESENT[0], true]
            ]
        );
    });

    await t.test('answers an empty list without asking Redis', async () => {
        // Every listing page with no bound rows takes this path, and a pipeline with no commands is
        // not a shape worth sending
        assert.deepEqual([...(await accountsExist(redis, []))], []);
        assert.deepEqual([...(await accountsExist(redis, null))], []);
    });

    await t.test('treats an account it could not probe as one that does not exist', async () => {
        // A pipeline reports per-command failures in the result rather than rejecting, so a reply
        // that carries an error must not be read as a 0/1 answer
        const failing = {
            pipeline: () => ({
                hexists() {
                    return this;
                },
                exec: async () => [[new Error('READONLY'), null]]
            })
        };

        assert.deepEqual([...(await accountsExist(failing, ['unprobed']))], [['unprobed', false]]);
    });
});
