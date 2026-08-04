'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis, submitQueue } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const outbox = require('../lib/outbox');
const { Account } = require('../lib/account');
const registerRedisTeardown = require('./helpers/redis-teardown');

const logger = {
    error: () => {},
    info: () => {},
    debug: () => {},
    trace: () => {}
};

// Queues an outgoing message the way base-client does: the content goes into the account's outbox
// hash, and a submit queue job whose ID is the queue ID points at it.
async function queueMessage(account, queueId) {
    await redis.hsetBuffer(`${REDIS_PREFIX}iaq:${account}`, queueId, Buffer.from('encoded-message'));
    await submitQueue.add(
        'queued',
        {
            account,
            queueId,
            envelope: { from: 'sender@example.com', to: ['rcpt@example.com'] },
            subject: 'Scheduled message'
        },
        {
            jobId: queueId,
            // Far enough ahead that the job would otherwise outlive the account by a year
            delay: 365 * 24 * 3600 * 1000,
            removeOnComplete: true,
            removeOnFail: true
        }
    );
}

test('Outbox', async t => {
    registerRedisTeardown(redis, () => submitQueue.obliterate({ force: true }).catch(() => false));

    await t.test('removeJobs() removes a scheduled message and leaves other accounts alone', async () => {
        const account = 'outbox-delete-account';
        const otherAccount = 'outbox-other-account';

        await queueMessage(account, 'outbox-delete-id');
        await queueMessage(otherAccount, 'outbox-keep-id');

        const queueIds = await redis.hkeys(`${REDIS_PREFIX}iaq:${account}`);
        assert.deepEqual(queueIds, ['outbox-delete-id']);

        assert.equal(await outbox.removeJobs(queueIds, { account, logger }), 1);

        assert.equal(await submitQueue.getJob('outbox-delete-id'), undefined);

        const survivor = await submitQueue.getJob('outbox-keep-id');
        assert.ok(survivor, 'a job belonging to another account must not be removed');
        assert.equal(survivor.data.account, otherAccount);

        await survivor.remove();
        await redis.unlink(`${REDIS_PREFIX}iaq:${account}`, `${REDIS_PREFIX}iaq:${otherAccount}`);
    });

    await t.test('removeJobs() tolerates a queue ID that has no job', async () => {
        // A job that is already gone is indistinguishable from one this call removed, and either
        // way there is nothing left behind
        assert.equal(await outbox.removeJobs(['outbox-missing-id'], { account: 'outbox-missing-account', logger }), 1);
    });

    await t.test('deleting an account removes the messages it had queued', async () => {
        const accountId = 'outbox-account-delete';

        const account = new Account({
            redis,
            account: accountId,
            documentsQueue: { add: async () => {} },
            call: async () => 0,
            logger
        });

        await redis.hmset(account.getAccountKey(), account.serializeAccountData({ account: accountId, name: 'Outbox test' }));
        await redis.sadd(`${REDIS_PREFIX}ia:accounts`, accountId);
        await queueMessage(accountId, 'outbox-account-delete-id');

        try {
            const result = await account.delete();

            assert.equal(result.deleted, true);
            // The queue IDs are read positionally out of the deletion transaction, so this also
            // covers the transaction still reporting whether the account existed
            assert.equal(await submitQueue.getJob('outbox-account-delete-id'), undefined);
            assert.equal(await redis.exists(`${REDIS_PREFIX}iaq:${accountId}`), 0);
        } finally {
            await redis.srem(`${REDIS_PREFIX}ia:accounts`, accountId);
        }
    });

    await t.test('removeJobs() reports a removal failure instead of throwing', async () => {
        const originalRemove = submitQueue.remove;
        submitQueue.remove = async () => {
            throw new Error('Redis is unavailable');
        };

        try {
            assert.equal(await outbox.removeJobs(['outbox-failing-id'], { account: 'outbox-failing-account', logger }), 0);
        } finally {
            submitQueue.remove = originalRemove;
        }
    });
});
