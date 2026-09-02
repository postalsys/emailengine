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
// Far enough ahead that the job would otherwise outlive the account by a year
const DEFAULT_DELAY = 365 * 24 * 3600 * 1000;

async function queueMessage(account, queueId, { delay = DEFAULT_DELAY } = {}) {
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
            delay,
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

    await t.test('list() counts waiting messages in the total, not just delayed ones', async () => {
        // Regression: jobStates carried 'wait', which getRanges() understands but getJobCounts()
        // never keys its result by - it only ever reports 'waiting'. So the count read back
        // undefined and an immediate (undelayed) message was listed with total/pages both 0.
        const account = 'outbox-waiting-account';
        // delay 0 so the job lands in the wait list rather than the delayed set
        await queueMessage(account, 'outbox-waiting-id', { delay: 0 });

        try {
            const result = await outbox.list({ logger });

            assert.equal(result.messages.length, 1, 'the queued message should be listed');
            assert.equal(result.total, 1, 'total must count the waiting message');
            assert.equal(result.pages, 1, 'pages is derived from total, so it must not be 0 either');
        } finally {
            // list() counts the whole queue, so leftovers would show up in the next test's totals
            await submitQueue.remove('outbox-waiting-id').catch(() => false);
            await redis.unlink(`${REDIS_PREFIX}iaq:${account}`);
        }
    });

    await t.test('list() returns at most pageSize entries and pages across states without skipping', async () => {
        // Two states at once: getRanges() applies a range to each state separately, so asking all
        // of them for [start, end] returned up to pageSize entries PER state and skipped entries
        // once page > 0. Three delayed + three waiting is enough to catch both.
        const account = 'outbox-paging-account';
        const queueIds = [];
        for (let i = 0; i < 3; i++) {
            queueIds.push(`outbox-paging-delayed-${i}`, `outbox-paging-waiting-${i}`);
        }

        try {
            for (let i = 0; i < 3; i++) {
                await queueMessage(account, `outbox-paging-delayed-${i}`);
                await queueMessage(account, `outbox-paging-waiting-${i}`, { delay: 0 });
            }

            const seen = [];
            for (let page = 0; page < 3; page++) {
                const result = await outbox.list({ page, pageSize: 2, logger });

                assert.equal(result.total, 6, 'every queued message counts toward the total');
                assert.equal(result.pages, 3, '6 entries at 2 per page is 3 pages');
                assert.ok(result.messages.length <= 2, `page ${page} must not exceed pageSize, got ${result.messages.length}`);

                seen.push(...result.messages.map(message => message.queueId));
            }

            // Walking the pages must yield each entry exactly once
            assert.equal(seen.length, 6, 'paging through must return every entry');
            assert.equal(new Set(seen).size, 6, 'no entry may appear on two pages');
        } finally {
            await Promise.all(queueIds.map(queueId => submitQueue.remove(queueId).catch(() => false)));
            await redis.unlink(`${REDIS_PREFIX}iaq:${account}`);
        }
    });

    await t.test('selectPageRanges() maps a page onto the states it actually spans', () => {
        // The real state order, so a change to it is exercised here rather than shadowed by a copy
        const states = outbox.JOB_STATES;
        const counts = { delayed: 3, waiting: 3, active: 0, failed: 2 };

        // Wholly inside the first state
        assert.deepEqual(outbox.selectPageRanges(states, counts, 0, 2), [{ state: 'delayed', start: 0, end: 1 }]);

        // Straddling two states: one left in delayed, the rest from the start of waiting
        assert.deepEqual(outbox.selectPageRanges(states, counts, 2, 2), [
            { state: 'delayed', start: 2, end: 2 },
            { state: 'waiting', start: 0, end: 0 }
        ]);

        // An empty state is skipped rather than consuming part of the page
        assert.deepEqual(outbox.selectPageRanges(states, counts, 5, 3), [
            { state: 'waiting', start: 2, end: 2 },
            { state: 'failed', start: 0, end: 1 }
        ]);

        // A page past the end of every state selects nothing, and issues no range reads
        assert.deepEqual(outbox.selectPageRanges(states, counts, 8, 2), []);

        // The deepest page the route's joi schema allows (page 1024*1024 at pageSize 1000) must
        // also select nothing rather than a huge range
        assert.deepEqual(outbox.selectPageRanges(states, counts, 1024 * 1024 * 1000, 1000), []);

        // Never more than pageSize in total, and it stops mid-state rather than overshooting
        assert.deepEqual(outbox.selectPageRanges(states, counts, 0, 4), [
            { state: 'delayed', start: 0, end: 2 },
            { state: 'waiting', start: 0, end: 0 }
        ]);
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

    await t.test('del() removes a scheduled message and its content', async () => {
        const account = 'outbox-del-account';
        await queueMessage(account, 'outbox-del-id');

        try {
            assert.deepEqual(await outbox.del({ queueId: 'outbox-del-id', logger }), { deleted: true });

            assert.equal(await submitQueue.getJob('outbox-del-id'), undefined);
            assert.equal(await redis.hexists(`${REDIS_PREFIX}iaq:${account}`, 'outbox-del-id'), 0);
        } finally {
            await submitQueue.remove('outbox-del-id').catch(() => false);
            await redis.unlink(`${REDIS_PREFIX}iaq:${account}`);
        }
    });

    await t.test('del() reports an unknown queue ID as not deleted', async () => {
        assert.deepEqual(await outbox.del({ queueId: 'outbox-del-missing-id', logger }), { deleted: false });
    });

    // Stands in for the job a submit worker is delivering: BullMQ reports it as active and refuses
    // to remove it while the worker holds the lock
    function stubGetJob(patchJob) {
        const originalGetJob = submitQueue.getJob;
        submitQueue.getJob = async queueId => {
            const job = await originalGetJob.call(submitQueue, queueId);
            if (job) {
                patchJob(job);
            }
            return job;
        };
        return () => {
            submitQueue.getJob = originalGetJob;
        };
    }

    await t.test('del() reports a message that is being delivered as locked and leaves it alone', async () => {
        const account = 'outbox-del-locked-account';
        await queueMessage(account, 'outbox-del-locked-id');

        const restore = stubGetJob(job => {
            job.isActive = async () => true;
            job.remove = async () => {
                throw new Error('remove() must not be called for a job in flight');
            };
        });

        try {
            assert.deepEqual(await outbox.del({ queueId: 'outbox-del-locked-id', logger }), { deleted: false, locked: true });

            assert.equal(await redis.hexists(`${REDIS_PREFIX}iaq:${account}`, 'outbox-del-locked-id'), 1, 'the content of a message in flight must stay');
        } finally {
            restore();
            await submitQueue.remove('outbox-del-locked-id').catch(() => false);
            await redis.unlink(`${REDIS_PREFIX}iaq:${account}`);
        }
    });

    await t.test('del() throws when the queue entry cannot be removed for any other reason', async () => {
        // Anything but the lock is a real failure, and a 200 with deleted:false would hide it
        const account = 'outbox-del-failing-account';
        await queueMessage(account, 'outbox-del-failing-id');

        const restore = stubGetJob(job => {
            job.remove = async () => {
                throw new Error('Redis is unavailable');
            };
        });

        try {
            await assert.rejects(outbox.del({ queueId: 'outbox-del-failing-id', logger }), /Redis is unavailable/);
        } finally {
            restore();
            await submitQueue.remove('outbox-del-failing-id').catch(() => false);
            await redis.unlink(`${REDIS_PREFIX}iaq:${account}`);
        }
    });
});
