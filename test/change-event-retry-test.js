'use strict';

// A Graph change notification whose follow-up request failed on a transient error (a 504 after
// 30 seconds, in the report that prompted this) used to be dropped: the event was already off the
// queue, so no messageNew webhook was ever sent for the message. A 5xx on the existence probe of a
// "deleted" event was worse and reported a deletion. These tests pin the retry: transient
// failures are deferred in Redis on a fixed schedule with a cap, anything else is given up on,
// and a deferred event comes back through the normal queue once it is due.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { Account } = require('../lib/account');
const { MESSAGE_DELETED_NOTIFY, OUTLOOK_QUEUE_RETRY_DELAYS } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

// The shape the Graph transport throws for a failed request
function graphError(status) {
    return Object.assign(new Error('OAuth2 request failed'), { oauthRequest: { status, response: { error: { code: 'UnknownError' } } } });
}

function makeClient(accountObject) {
    const outlook = new OutlookClient('test-account', { redis });
    outlook.logger = noopLogger;
    outlook.oauth2UserPath = 'me';
    outlook.accountObject = accountObject;
    outlook._updateLastNotificationTime = async () => {};
    return outlook;
}

function stubQueue(events) {
    const queue = {
        deferred: [],
        promoted: 0,
        promoteDueQueueEvents: async () => {
            queue.promoted++;
            return null;
        },
        pullQueueEvent: async () => (events.length ? events.shift() : null),
        deferQueueEvent: async (event, dueTime) => queue.deferred.push({ event, dueTime })
    };
    return queue;
}

test('OutlookClient.processHistory() retries transient failures', async t => {
    await t.test('a 504 on a created event defers it and the drain continues', async () => {
        const queue = stubQueue([
            { type: 'created', message: 'm1' },
            { type: 'updated', message: 'm2' }
        ]);
        const outlook = makeClient(queue);
        outlook.getMessageFetchOptions = async () => ({});
        outlook.prepareNewMessage = async () => {
            throw graphError(504);
        };
        const updated = [];
        outlook.processUpdatedMessage = async emailId => updated.push(emailId);

        const before = Date.now();
        await outlook.processHistory();
        outlook.cancelQueueRetryTimer();

        assert.deepEqual(updated, ['m2']);
        assert.equal(queue.deferred.length, 1);
        assert.deepEqual(queue.deferred[0].event, { type: 'created', message: 'm1', attempt: 1 });
        assert.ok(queue.deferred[0].dueTime >= before + OUTLOOK_QUEUE_RETRY_DELAYS[0]);
    });

    await t.test('each attempt takes the next delay on the schedule', async () => {
        const queue = stubQueue([{ type: 'updated', message: 'm1', attempt: 2 }]);
        const outlook = makeClient(queue);
        outlook.processUpdatedMessage = async () => {
            throw graphError(503);
        };

        const before = Date.now();
        await outlook.processHistory();
        outlook.cancelQueueRetryTimer();

        assert.equal(queue.deferred[0].event.attempt, 3);
        const delay = queue.deferred[0].dueTime - before;
        assert.ok(delay >= OUTLOOK_QUEUE_RETRY_DELAYS[2] && delay < OUTLOOK_QUEUE_RETRY_DELAYS[2] + 1000);
    });

    for (const [label, event, err] of [
        ['the last attempt', { type: 'created', message: 'm1', attempt: OUTLOOK_QUEUE_RETRY_DELAYS.length }, graphError(502)],
        ['a failure that is not the service failing', { type: 'created', message: 'm1' }, graphError(400)]
    ]) {
        await t.test(`${label} is given up on`, async () => {
            const queue = stubQueue([event]);
            const outlook = makeClient(queue);
            outlook.getMessageFetchOptions = async () => ({});
            outlook.prepareNewMessage = async () => {
                throw err;
            };

            await outlook.processHistory();

            assert.equal(queue.deferred.length, 0);
            assert.equal(outlook.queueRetryTimer, null);
        });
    }

    await t.test('a network failure is retried', async () => {
        const queue = stubQueue([{ type: 'deleted', message: 'm1' }]);
        const outlook = makeClient(queue);
        outlook.processDeletedMessage = async () => {
            throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
        };

        await outlook.processHistory();
        outlook.cancelQueueRetryTimer();

        assert.equal(queue.deferred.length, 1);
    });

    await t.test('a drain with nothing deferred asks Redis only once', async () => {
        const queue = stubQueue([]);
        const outlook = makeClient(queue);

        await outlook.processHistory();
        await outlook.processHistory();

        assert.equal(queue.promoted, 1);
    });
});

test('OutlookClient change probes do not mistake a failed request for a missing message', async t => {
    await t.test('a 5xx on the deleted probe throws instead of reporting a deletion', async () => {
        const outlook = makeClient(null);
        const notifications = [];
        outlook.notify = async (mailbox, event) => notifications.push(event);
        outlook.request = async () => {
            throw graphError(504);
        };

        await assert.rejects(outlook.processDeletedMessage('m1'), /OAuth2 request failed/);
        await assert.rejects(outlook.processUpdatedMessage('m1'), /OAuth2 request failed/);
        assert.deepEqual(notifications, []);
    });

    await t.test('a 404 on the deleted probe still reports the deletion', async () => {
        const outlook = makeClient(null);
        const notifications = [];
        outlook.notify = async (mailbox, event, data) => notifications.push({ event, data });
        outlook.request = async () => {
            throw Object.assign(new Error('Not found'), { code: 'MessageNotFound', statusCode: 404 });
        };

        await outlook.processDeletedMessage('m1');
        await outlook.processUpdatedMessage('m1');
        assert.deepEqual(notifications, [{ event: MESSAGE_DELETED_NOTIFY, data: { id: 'm1' } }]);
    });
});

test('Account deferred change notification queue', async t => {
    const accountId = `test-change-retry-${process.pid}`;
    const account = new Account({ redis, account: accountId, logger: noopLogger, call: async () => {} });

    const cleanup = () => redis.del(account.getExternalQueueKey(), account.getDeferredQueueKey());
    t.beforeEach(cleanup);
    t.after(cleanup);

    await t.test('only due events are moved back to the queue', async () => {
        const now = Date.now();
        await account.deferQueueEvent({ type: 'created', message: 'due', attempt: 1 }, now - 1000);
        await account.deferQueueEvent({ type: 'created', message: 'later', attempt: 1 }, now + 60 * 1000);

        assert.equal(await account.promoteDueQueueEvents(), now + 60 * 1000);

        assert.deepEqual(await account.pullQueueEvent(), { type: 'created', message: 'due', attempt: 1 });
        assert.equal(await account.pullQueueEvent(), null);
    });

    await t.test('an empty deferred queue reports nothing due', async () => {
        assert.equal(await account.promoteDueQueueEvents(), null);
    });

    await t.test('a message whose fetch failed is announced on the retry', async () => {
        const outlook = makeClient(account);
        outlook.getMessageFetchOptions = async () => ({});
        let fail = true;
        outlook.prepareNewMessage = async emailId => {
            if (fail) {
                throw graphError(504);
            }
            return { id: emailId, path: 'INBOX' };
        };
        outlook.rollingBucketLock = async () => false;
        const announced = [];
        outlook.processNew = async messageData => announced.push(messageData.id);

        await account.pushQueueEvent({ type: 'created', message: 'm1' });

        await outlook.processHistory();
        assert.deepEqual(announced, []);
        assert.ok(outlook.queueRetryTimerDueAt > Date.now(), 'a retry timer is armed for the deferred event');

        // Make the deferred event due now instead of waiting a minute
        await account.deferQueueEvent({ type: 'created', message: 'm1', attempt: 1 }, Date.now() - 1);
        outlook.cancelQueueRetryTimer();
        fail = false;
        await outlook.processHistory();

        assert.deepEqual(announced, ['m1']);
        assert.equal(await account.promoteDueQueueEvents(), null);
    });
});
