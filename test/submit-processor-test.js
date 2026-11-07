'use strict';

// A queued message must be sent once even when the submit worker dies between the send and
// BullMQ recording the job as completed. The send lock's marker (lib/submit-lock.js) is what stops
// the job's next run from sending again, so it has to outlive that window: the processor used to
// clear it before returning, and a worker that died right after (with the 'submitted' progress
// write refused by a Redis at its memory limit, so the job carried no other sign of the send) left
// a job whose next run sent the message a second time.
//
// The real processor (lib/submit-processor.js) runs here against real BullMQ jobs on a queue of the
// test's own, taken and handed back the way a worker and BullMQ's stalled-job recovery do. Only the
// account is replaced, by one that sends through the real sendQueuedOnce() and counts the sends.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Queue, Worker } = require('bullmq');

const { redis, queueConf } = require('../lib/db');
const msgpack = require('../lib/msgpack');
const { outboxKey } = require('../lib/outbox');
const { getSharedLock } = require('../lib/lock-run');
const { sendQueuedOnce, sentKey } = require('../lib/submit-lock');
const { createSubmitProcessor, completeSubmission } = require('../lib/submit-processor');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createMockLogger } = require('./helpers/mock-logger');
const exitWhenStandalone = require('./helpers/exit-standalone');

const QUEUE_NAME = `submit-processor-test-${process.pid}`;
const ACCOUNT = `submit-processor-${process.pid}`;
const OUTBOX_KEY = outboxKey(ACCOUNT);

const silent = createMockLogger();

const queue = new Queue(QUEUE_NAME, queueConf);
const worker = new Worker(QUEUE_NAME, null, { ...queueConf, autorun: false, lockDuration: 60 * 1000 });
worker.on('error', () => {});

const queueIds = new Set();

registerRedisTeardown(redis, async () => {
    await worker.close(true);
    await queue.obliterate({ force: true });
    await queue.close();
    await redis.del(OUTBOX_KEY, ...[...queueIds].map(queueId => sentKey(ACCOUNT, queueId)));
});

let sends = 0;

function sendOnce(queueId) {
    return sendQueuedOnce({
        lock: getSharedLock(),
        redis,
        logger: silent,
        account: ACCOUNT,
        queueId,
        send: async () => {
            sends++;
            return { response: '250 2.0.0 Accepted' };
        }
    });
}

const processor = createSubmitProcessor({
    redis,
    logger: silent,
    submitQueue: queue,
    getAccount: async () => ({ submitMessage: queueEntry => sendOnce(queueEntry.queueId) })
});

async function queueMessage(queueId) {
    queueIds.add(queueId);
    await redis.hset(OUTBOX_KEY, queueId, msgpack.encode({ account: ACCOUNT, queueId, messageId: `<${queueId}@example.com>` }));
    await queue.add('submit', { account: ACCOUNT, queueId }, { jobId: queueId, attempts: 5 });
}

// Takes the next job the way a worker does. The progress write that says the message went out is
// refused, as Redis refuses writes at its memory limit; everything else about the job is real
async function takeJob(token) {
    const job = await worker.getNextJob(token, { block: false });
    const updateProgress = job.updateProgress.bind(job);
    job.updateProgress = async progress => {
        if (progress && progress.status === 'submitted') {
            throw new Error('OOM command not allowed when used memory > maxmemory');
        }
        return await updateProgress(progress);
    };
    return job;
}

// The worker dies after the processor returned and before BullMQ stored the completion. BullMQ's
// stalled-job check then puts the job back in the queue for another run
async function crashBeforeCompletion(job, token) {
    assert.equal(await job.getState(), 'active', 'the job is not completed');
    await job.moveToWait(token);
}

async function markerExists(queueId) {
    return (await redis.exists(sentKey(ACCOUNT, queueId))) === 1;
}

test('the sent marker outlives a crash before the job completes', async t => {
    await t.test('a message sent by this run', async () => {
        const queueId = `sent-${process.pid}`;
        sends = 0;
        await queueMessage(queueId);

        const job = await takeJob('first-run');
        await processor(job);
        assert.equal(sends, 1);
        assert.ok(await markerExists(queueId), 'the processor leaves the marker for the completion to clear');

        await crashBeforeCompletion(job, 'first-run');

        const rerun = await takeJob('second-run');
        assert.equal(rerun.id, queueId);
        await processor(rerun);
        assert.equal(sends, 1, 'the run after the crash does not send again');
        assert.ok(await markerExists(queueId), 'and keeps the marker until its own completion');

        await rerun.moveToCompleted(undefined, 'second-run', false);
        await completeSubmission(rerun, { redis, logger: silent });
        assert.ok(!(await markerExists(queueId)), 'the completion clears the marker');
        assert.equal(await redis.hexists(OUTBOX_KEY, queueId), 0, 'and the stored message');
    });

    await t.test('a message an earlier attempt sent (AlreadySent)', async () => {
        const queueId = `already-${process.pid}`;
        sends = 0;
        await queueMessage(queueId);

        // An earlier attempt sent the message and its call failed after the fact (the reply was
        // lost), so its job was retried. The marker is that attempt's own record
        await sendOnce(queueId);
        assert.equal(sends, 1);

        const job = await takeJob('retry');
        await processor(job);
        assert.equal(sends, 1, 'the retry is answered AlreadySent');
        assert.ok(await markerExists(queueId), 'the AlreadySent branch leaves the marker too');

        await crashBeforeCompletion(job, 'retry');

        const rerun = await takeJob('retry-after-crash');
        await processor(rerun);
        assert.equal(sends, 1, 'the run after the crash does not send again');

        await rerun.moveToCompleted(undefined, 'retry-after-crash', false);
        await completeSubmission(rerun, { redis, logger: silent });
        assert.ok(!(await markerExists(queueId)));
    });
});

test('completeSubmission()', async t => {
    await t.test('reads the legacy qId and skips a job without a queue entry', async () => {
        const queueId = `legacy-${process.pid}`;
        queueIds.add(queueId);
        await redis.set(sentKey(ACCOUNT, queueId), '1', 'EX', 60);
        await completeSubmission({ id: 'legacy', data: { account: ACCOUNT, qId: queueId } }, { redis, logger: silent });
        assert.ok(!(await markerExists(queueId)));

        // A direct send carries no queue entry, and there is nothing to clear for it
        await completeSubmission({ id: 'direct', data: { account: ACCOUNT } }, { redis, logger: silent });
    });

    await t.test('a failure to clear is logged, not thrown', async () => {
        const logger = createMockLogger();
        const failing = {
            hdel: async () => 1,
            del: async () => {
                throw new Error('LOADING Redis is loading the dataset in memory');
            }
        };
        await completeSubmission({ id: 'job', data: { account: ACCOUNT, queueId: 'q' } }, { redis: failing, logger });
        assert.deepEqual(
            logger.entries.map(entry => `${entry.level}: ${entry.msg}`),
            ['warn: Failed to clear the sent marker of a completed message']
        );
    });
});

exitWhenStandalone();

// An account whose SMTP server trickled each delivery until the deadline held the queue every other
// account shares; its next messages now wait in the delayed set instead
test('a message of a penalised account is delayed without being sent', async () => {
    const { submitPenaltyKey } = require('../lib/submit-penalty');
    const { DelayedError } = require('bullmq');
    const queueId = `penalised-${process.pid}`;
    sends = 0;
    await queueMessage(queueId);
    await redis.set(submitPenaltyKey(ACCOUNT), '1', 'PX', 60 * 1000);
    try {
        const job = await worker.getNextJob('penalised-run', { block: false });
        await assert.rejects(processor(job, 'penalised-run'), err => err instanceof DelayedError);
        assert.equal(sends, 0, 'nothing is sent while the account is penalised');
        assert.equal(await job.getState(), 'delayed');
        assert.equal((await queue.getJob(queueId)).attemptsMade, 0, 'the wait spends no attempt');
    } finally {
        await redis.del(submitPenaltyKey(ACCOUNT));
        await queue.remove(queueId).catch(() => false);
    }
});
