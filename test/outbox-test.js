'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis, submitQueue } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const outbox = require('../lib/outbox');
const { outboxEntrySchema } = require('../lib/schemas');
const msgpack = require('../lib/msgpack');
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

// Module level, never inside a test: a root hook registered while a test runs fires once that
// test is over, which closed Redis under the second test block of this file
registerRedisTeardown(redis, () => submitQueue.obliterate({ force: true }).catch(() => false));

test('Outbox', async t => {
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

    await t.test('decodeQueueEntry() rejects a stored value that is not a message', () => {
        // A real entry survives the guard
        const entry = { account: 'outbox-decode-account', envelope: { from: 'sender@example.com' } };
        assert.deepEqual(outbox.decodeQueueEntry(msgpack.encode(entry)), entry);

        // The reported crash: msgpack.decode() reads the first value of a buffer and ignores the
        // rest, so a foreign value whose first byte is a valid scalar decodes without throwing.
        // 'encoded-message' starts with 0x65, a positive fixint, and came back as the number 101 -
        // which reached the submit worker and threw "Cannot create property 'job' on number '101'"
        assert.throws(() => outbox.decodeQueueEntry(Buffer.from('encoded-message')), /Unexpected outbox entry format/);

        // Every other non-map type is equally unusable
        for (let value of [null, 101, 'a string', ['an', 'array'], Buffer.from('bin'), new Date()]) {
            assert.throws(() => outbox.decodeQueueEntry(msgpack.encode(value)), /Unexpected outbox entry format/, `${typeof value} must be rejected`);
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

// The submit worker records the route a failed attempt took with
//   job.updateProgress({ status: 'error', error: { message, code, statusCode }, networkRouting })
// (workers/submit.js), and formatQueueEntry() passes job.progress through verbatim. The schema used
// to declare networkRouting one level deeper, inside `error`, so a client reading the documented
// location found nothing and response validation logged the real field as unknown.
test('outboxEntrySchema matches the progress object the submit worker writes', async t => {
    const failedProgress = {
        status: 'error',
        error: { message: 'Authentication failed', code: 'EAUTH', statusCode: 535 },
        networkRouting: { localAddress: '198.51.100.24', name: 'relay.example.com' }
    };

    await t.test('networkRouting is declared beside error, not inside it', () => {
        const { error, value } = outboxEntrySchema.validate(
            { account: 'acc-1', queueId: 'q-1', progress: failedProgress },
            { stripUnknown: false, abortEarly: false, convert: true }
        );
        assert.ifError(error);
        assert.deepEqual(value.progress.networkRouting, failedProgress.networkRouting);
    });

    await t.test('the same object nested inside error is not what the schema describes', () => {
        const { error } = outboxEntrySchema.validate(
            { account: 'acc-1', queueId: 'q-1', progress: { status: 'error', error: Object.assign({}, failedProgress.error, { networkRouting: {} }) } },
            { stripUnknown: false, abortEarly: false, convert: true }
        );
        assert.ok(error, 'progress.error has no networkRouting field');
    });
});

// The content retained for failed messages, and the retry and promote actions over it. In this
// file rather than one of its own because every test here shares the one `submit` queue, and the
// teardown above obliterates it: a sibling file running in parallel would lose its jobs to that.
//
// A job is failed the way a worker fails it: fetched into the active list through a worker with
// no processor and moved to failed with a single attempt configured. Nothing else in the unit tier
// adds a waiting submit job (the ones above are delayed by a year), so the fetch returns the job
// this test just added.
test('Outbox failed content', async t => {
    const { Worker } = require('bullmq');
    const { queueConf } = require('../lib/db');

    const worker = new Worker('submit', null, Object.assign({ autorun: false }, queueConf));
    await worker.waitUntilReady();

    const account = 'outbox-failed-account';
    const limits = outbox.FAILED_CONTENT_LIMITS;
    const hasContent = async queueId => !!(await redis.hexists(`${REDIS_PREFIX}iaq:${account}`, queueId));
    const originalLimits = Object.assign({}, limits);

    let token = 0;

    async function failJob(queueId, content = 'failed-message') {
        await redis.hsetBuffer(`${REDIS_PREFIX}iaq:${account}`, queueId, Buffer.from(content));
        await submitQueue.add(
            'queued',
            { account, queueId, messageId: `<${queueId}@example.com>`, envelope: { from: 'a@example.com', to: ['b@example.com'] }, subject: 'Failing' },
            { jobId: queueId, attempts: 1, removeOnComplete: true, removeOnFail: false }
        );

        const lock = `lock-${++token}`;
        const job = await worker.getNextJob(lock, { block: false });
        assert.ok(job, 'the fetch must return a job');
        assert.equal(job.id, queueId, 'the fetched job must be the one just added');
        await job.moveToFailed(new Error('550 No such user'), lock, false);

        assert.equal(await submitQueue.getJobState(queueId), 'failed');
        return job;
    }

    async function cleanup(...queueIds) {
        for (const queueId of queueIds) {
            await submitQueue.remove(queueId).catch(() => false);
        }
        await redis.unlink(`${REDIS_PREFIX}iaq:${account}`, outbox.FAILED_CONTENT_KEY);
    }

    t.after(async () => {
        Object.assign(limits, originalLimits);
        await worker.close();
    });

    await t.test('the worker keeps the content of a failed message and the retry sends it again', async () => {
        try {
            const job = await failJob('outbox-failed-retry');

            // what the submit worker's failed handler does once finishedOn is set
            assert.equal(await outbox.retainFailedContent({ account, queueId: job.id, finishedOn: job.finishedOn, logger }), true);
            assert.equal(await hasContent(job.id), true);

            const retained = await outbox.listRetainedFailedContent();
            const entry = retained.find(item => item.queueId === job.id);
            assert.ok(entry, 'the content is listed as retained');
            assert.equal(entry.account, account);
            assert.equal(entry.size, Buffer.byteLength('failed-message'));

            // the API surfaces the state and the entry while the content is there
            const got = await outbox.get({ queueId: job.id, logger });
            assert.equal(got.state, 'failed');
            assert.equal(got.nextAttempt, false);

            const result = await outbox.retry({ queueId: job.id, logger });
            assert.deepEqual(result, { retried: true, queueId: job.id, messageId: `<${job.id}@example.com>` });

            assert.equal(await submitQueue.getJobState(job.id), 'waiting');
            const retried = await submitQueue.getJob(job.id);
            assert.equal(retried.attemptsMade, 0, 'a retry starts over with a full set of attempts');
            assert.equal(retried.finishedOn, undefined);
            assert.deepEqual(retried.progress, { status: 'queued' });
            assert.equal(await hasContent(job.id), true, 'the content stays for the worker');
            assert.ok(!(await outbox.listRetainedFailedContent()).some(item => item.queueId === job.id), 'a live message is no longer retained');

            await assert.rejects(outbox.retry({ queueId: job.id, logger }), err => err.code === 'NotFailed' && err.statusCode === 409);
        } finally {
            await cleanup('outbox-failed-retry');
        }
    });

    await t.test('a failed message whose content was dropped cannot be retried', async () => {
        try {
            const job = await failJob('outbox-failed-gone');
            await outbox.retainFailedContent({ account, queueId: job.id, finishedOn: job.finishedOn, logger });

            // the worker's own path for a message with nothing to send: the content is gone
            await redis.hdel(`${REDIS_PREFIX}iaq:${account}`, job.id);

            await assert.rejects(outbox.retry({ queueId: job.id, logger }), err => err.code === 'ContentGone' && err.statusCode === 409);
            assert.equal(await submitQueue.getJobState(job.id), 'failed', 'the job is left where it was');
            assert.equal(await outbox.get({ queueId: job.id, logger }), false, 'and the API no longer returns it');
        } finally {
            await cleanup('outbox-failed-gone');
        }
    });

    await t.test('retry() and promote() answer false for an unknown message', async () => {
        assert.equal(await outbox.retry({ queueId: 'outbox-no-such-job', logger }), false);
        assert.equal(await outbox.promote({ queueId: 'outbox-no-such-job', logger }), false);
    });

    await t.test('promote() sends a scheduled message now and refuses one that is not waiting for a time', async () => {
        try {
            await queueMessage(account, 'outbox-promote-id');
            assert.equal(await submitQueue.getJobState('outbox-promote-id'), 'delayed');

            const result = await outbox.promote({ queueId: 'outbox-promote-id', logger });
            assert.deepEqual(result, { promoted: true, queueId: 'outbox-promote-id', messageId: undefined });
            assert.equal(await submitQueue.getJobState('outbox-promote-id'), 'waiting');

            await assert.rejects(outbox.promote({ queueId: 'outbox-promote-id', logger }), err => err.code === 'NotDelayed' && err.statusCode === 409);
        } finally {
            await cleanup('outbox-promote-id');
        }
    });

    await t.test('retainFailedContent() applies the count and size bounds, oldest first', async () => {
        try {
            limits.maxCount = 2;
            limits.maxBytes = 1024;

            // recent failures, a second apart: the age bound must not be what drops them
            const base = Date.now() - 10000;
            const first = await failJob('outbox-bound-1', 'one');
            assert.equal(await outbox.retainFailedContent({ account, queueId: first.id, finishedOn: base + 1000, logger }), true);
            const second = await failJob('outbox-bound-2', 'two');
            assert.equal(await outbox.retainFailedContent({ account, queueId: second.id, finishedOn: base + 2000, logger }), true);
            const third = await failJob('outbox-bound-3', 'three');
            assert.equal(await outbox.retainFailedContent({ account, queueId: third.id, finishedOn: base + 3000, logger }), true);

            // the oldest went to make room
            assert.equal(await hasContent(first.id), false);
            assert.equal(await hasContent(second.id), true);
            assert.equal(await hasContent(third.id), true);
            assert.deepEqual((await outbox.listRetainedFailedContent()).map(entry => entry.queueId).sort(), ['outbox-bound-2', 'outbox-bound-3']);

            // a message larger than the whole size bound is never kept, and takes nothing with it
            const huge = await failJob('outbox-bound-huge', 'x'.repeat(2048));
            assert.equal(await outbox.retainFailedContent({ account, queueId: huge.id, finishedOn: base + 4000, logger }), false);
            assert.equal(await hasContent(huge.id), false);
            assert.equal(await hasContent(third.id), true);

            // nothing to retain for a message whose content is already gone
            assert.equal(await outbox.retainFailedContent({ account, queueId: 'outbox-bound-missing', finishedOn: base + 5000, logger }), false);
        } finally {
            Object.assign(limits, originalLimits);
            await cleanup('outbox-bound-1', 'outbox-bound-2', 'outbox-bound-3', 'outbox-bound-huge');
        }
    });

    await t.test('pruneFailedContent() follows the job: dropped when it is gone, released when it is live again', async () => {
        try {
            const gone = await failJob('outbox-prune-gone');
            await outbox.retainFailedContent({ account, queueId: gone.id, finishedOn: gone.finishedOn, logger });
            const live = await failJob('outbox-prune-live');
            await outbox.retainFailedContent({ account, queueId: live.id, finishedOn: live.finishedOn, logger });
            const kept = await failJob('outbox-prune-kept');
            await outbox.retainFailedContent({ account, queueId: kept.id, finishedOn: kept.finishedOn, logger });

            // a clean of the failed set removes the job record without this module hearing of it
            await submitQueue.remove(gone.id);
            // a retry through BullMQ itself, as the queue browser does for webhooks
            await live.retry('failed', { resetAttemptsMade: true });

            const pruned = await outbox.pruneFailedContent({ logger });
            assert.equal(pruned.dropped, 1);
            assert.equal(pruned.released, 1);

            assert.equal(await hasContent(gone.id), false, 'content without a job is memory');
            assert.equal(await hasContent(live.id), true, 'the worker owns a live message again');
            assert.deepEqual(
                (await outbox.listRetainedFailedContent()).map(entry => entry.queueId),
                [kept.id]
            );
        } finally {
            await cleanup('outbox-prune-gone', 'outbox-prune-live', 'outbox-prune-kept');
        }
    });

    await t.test('removeJobs() forgets the retained failed messages of the account', async () => {
        try {
            const job = await failJob('outbox-remove-retained');
            await outbox.retainFailedContent({ account, queueId: job.id, finishedOn: job.finishedOn, logger });

            // the account deletion path: the outbox hash keys, then the hash itself
            assert.equal(await outbox.removeJobs([job.id], { account, logger }), 1);
            assert.ok(!(await outbox.listRetainedFailedContent()).some(entry => entry.queueId === job.id));
        } finally {
            await cleanup('outbox-remove-retained');
        }
    });

    await t.test('del() of a failed message takes its retained content with it', async () => {
        try {
            const job = await failJob('outbox-failed-del');
            await outbox.retainFailedContent({ account, queueId: job.id, finishedOn: job.finishedOn, logger });

            assert.deepEqual(await outbox.del({ queueId: job.id, logger }), { deleted: true });
            assert.equal(await hasContent(job.id), false);
            assert.equal(await submitQueue.getJob(job.id), undefined);
            assert.ok(!(await outbox.listRetainedFailedContent()).some(item => item.queueId === job.id));
        } finally {
            await cleanup('outbox-failed-del');
        }
    });

    await t.test('list() reports the state each entry was read from', async () => {
        try {
            await queueMessage(account, 'outbox-state-delayed');
            const failed = await failJob('outbox-state-failed');
            await outbox.retainFailedContent({ account, queueId: failed.id, finishedOn: failed.finishedOn, logger });

            const listing = await outbox.list({ logger, pageSize: 100 });
            const byId = new Map(listing.messages.map(message => [message.queueId, message]));
            assert.equal(byId.get('outbox-state-delayed').state, 'delayed');
            assert.equal(byId.get('outbox-state-failed').state, 'failed');
        } finally {
            await cleanup('outbox-state-delayed', 'outbox-state-failed');
        }
    });

    await t.test('list() with an account lists only that account, from its outbox hash', async () => {
        const other = 'outbox-other-account';
        try {
            // failed first: failJob() takes the next waiting job off the queue
            const failed = await failJob('outbox-acct-failed');
            await outbox.retainFailedContent({ account, queueId: failed.id, finishedOn: failed.finishedOn, logger });
            await queueMessage(account, 'outbox-acct-delayed');
            await queueMessage(account, 'outbox-acct-waiting', { delay: 0 });
            await queueMessage(other, 'outbox-other-delayed');

            const listing = await outbox.list({ account, logger });
            assert.deepEqual(
                listing.messages.map(message => [message.queueId, message.state]),
                [
                    ['outbox-acct-delayed', 'delayed'],
                    ['outbox-acct-waiting', 'waiting'],
                    ['outbox-acct-failed', 'failed']
                ],
                'by state in listing order, and nothing of the other account'
            );
            assert.equal(listing.total, 3);
            assert.equal(listing.pages, 1);

            const paged = await outbox.list({ account, logger, page: 1, pageSize: 2 });
            assert.deepEqual(
                paged.messages.map(message => message.queueId),
                ['outbox-acct-failed']
            );
            assert.equal(paged.pages, 2);

            const failedOnly = await outbox.list({ account, state: 'failed', logger });
            assert.deepEqual(
                failedOnly.messages.map(message => message.queueId),
                ['outbox-acct-failed']
            );
            assert.equal(failedOnly.total, 1);
        } finally {
            await cleanup('outbox-acct-delayed', 'outbox-acct-waiting', 'outbox-acct-failed');
            await submitQueue.remove('outbox-other-delayed').catch(() => false);
            await redis.unlink(`${REDIS_PREFIX}iaq:${other}`);
        }
    });

    await t.test('list() with a state counts and pages only that state', async () => {
        try {
            await queueMessage(account, 'outbox-statefilter-delayed');
            const failed = await failJob('outbox-statefilter-failed');

            const listing = await outbox.list({ state: 'failed', logger, pageSize: 100 });
            const ids = listing.messages.map(message => message.queueId);
            assert.ok(ids.includes(failed.id));
            assert.ok(!ids.includes('outbox-statefilter-delayed'), 'a delayed message is not in the failed listing');
            assert.ok(listing.messages.every(message => message.state === 'failed'));
            assert.equal(listing.total, Number((await submitQueue.getJobCounts('failed')).failed));
        } finally {
            await cleanup('outbox-statefilter-delayed', 'outbox-statefilter-failed');
        }
    });

    await t.test('an account given to get, del, retry and promote has to own the message', async () => {
        const other = 'outbox-owner-other';
        try {
            await queueMessage(account, 'outbox-owner-delayed');
            const failed = await failJob('outbox-owner-failed');
            await outbox.retainFailedContent({ account, queueId: failed.id, finishedOn: failed.finishedOn, logger });

            // Another account naming these queue IDs reaches nothing, and changes nothing
            assert.equal(await outbox.get({ queueId: 'outbox-owner-delayed', account: other, logger }), false);
            assert.deepEqual(await outbox.del({ queueId: 'outbox-owner-delayed', account: other, logger }), { deleted: false });
            assert.equal(await outbox.promote({ queueId: 'outbox-owner-delayed', account: other, logger }), false);
            assert.equal(await outbox.retry({ queueId: failed.id, account: other, logger }), false);
            assert.equal(await submitQueue.getJobState('outbox-owner-delayed'), 'delayed');
            assert.equal(await submitQueue.getJobState(failed.id), 'failed');
            assert.ok(await hasContent('outbox-owner-delayed'));

            // The owner reaches them
            assert.equal((await outbox.get({ queueId: 'outbox-owner-delayed', account, logger })).queueId, 'outbox-owner-delayed');
            assert.equal((await outbox.retry({ queueId: failed.id, account, logger })).retried, true);
            assert.equal((await outbox.promote({ queueId: 'outbox-owner-delayed', account, logger })).promoted, true);
            assert.equal((await outbox.del({ queueId: 'outbox-owner-delayed', account, logger })).deleted, true);
        } finally {
            await cleanup('outbox-owner-delayed', 'outbox-owner-failed');
        }
    });
});
