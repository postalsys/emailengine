'use strict';

// A queued message is sent under a lock (lib/submit-lock.js): the submit worker retries when its
// call fails, and a call can fail while the send itself goes on (a timeout, or a forwarded call
// whose connection was cut). The retry must not start a second send next to the first, and once
// the first has sent the message a retry must not send it again.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { getSharedLock } = require('../lib/lock-run');
const { sendQueuedOnce, clearSent, sentKey } = require('../lib/submit-lock');
const registerRedisTeardown = require('./helpers/redis-teardown');

const account = `submit-lock-${process.pid}`;

registerRedisTeardown(redis, () => redis.del(...['q1', 'q2', 'q3'].map(queueId => sentKey(account, queueId))));

test('sendQueuedOnce()', async t => {
    await t.test('a retry while the first send is running is refused as in progress', async () => {
        let release;
        const first = sendQueuedOnce({
            lock: getSharedLock(),
            account,
            redis,
            queueId: 'q1',
            send: () => new Promise(resolve => (release = resolve))
        });
        // Let the first attempt take the lock
        await new Promise(resolve => setTimeout(resolve, 100));

        let sent = false;
        await assert.rejects(
            sendQueuedOnce({
                lock: getSharedLock(),
                account,
                redis,
                queueId: 'q1',
                send: async () => {
                    sent = true;
                }
            }),
            err => err.code === 'SubmitInProgress'
        );
        assert.equal(sent, false, 'the retry did not send');

        release({ response: '250 ok' });
        assert.deepEqual(await first, { response: '250 ok' });
    });

    await t.test('a retry after the message was sent does not send it again', async () => {
        // Whatever the job progress says: a retry writes 'processing' over it
        assert.equal(await redis.exists(sentKey(account, 'q1')), 1, 'the first send was recorded');
        let sent = false;
        await assert.rejects(
            sendQueuedOnce({
                lock: getSharedLock(),
                redis,
                account,
                queueId: 'q1',
                send: async () => {
                    sent = true;
                }
            }),
            err => err.code === 'AlreadySent'
        );
        assert.equal(sent, false);
    });

    await t.test('a failed send is not recorded as sent and releases the lock', async () => {
        const queueId = 'q3';
        await assert.rejects(sendQueuedOnce({ lock: getSharedLock(), redis, account, queueId, send: () => Promise.reject(new Error('421 try later')) }), /421/);
        assert.equal(await redis.exists(sentKey(account, 'q3')), 0);
        assert.equal(await sendQueuedOnce({ lock: getSharedLock(), redis, account, queueId, send: async () => 'sent' }), 'sent');
    });

    await t.test('a completed job forgets the marker, a failed marker write does not fail the send', async () => {
        await clearSent(redis, account, 'q1');
        assert.equal(await redis.exists(sentKey(account, 'q1')), 0);

        const failingRedis = { exists: redis.exists.bind(redis), set: () => Promise.reject(new Error('READONLY')) };
        const logged = [];
        const result = await sendQueuedOnce({
            lock: getSharedLock(),
            redis: failingRedis,
            logger: { error: entry => logged.push(entry.msg) },
            account,
            queueId: 'q2',
            send: async () => 'sent'
        });
        assert.equal(result, 'sent');
        assert.deepEqual(logged, ['Failed to record a sent message']);
    });

    await t.test('a submission without a queue entry is sent as before', async () => {
        assert.equal(await sendQueuedOnce({ lock: getSharedLock(), redis, account, send: async () => 'direct' }), 'direct');
    });
});
