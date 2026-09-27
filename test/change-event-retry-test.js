'use strict';

// A mailbox change the Gmail or MS Graph client failed to process on a transient provider error
// used to be dropped. Graph pops its notification off the queue before the follow-up request, and
// Gmail moved its history cursor past a failed entry, so a new message whose fetch got a 504 (the
// report that prompted this) never produced a messageNew webhook, and nothing recovered it later.
// A 5xx on the Graph existence probe of a "deleted" event was worse and reported a deletion.
// These tests pin the shared retry: transient failures are deferred in Redis on a fixed schedule
// with a cap, anything else is given up on, and a deferred change is processed again once due.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { GmailClient } = require('../lib/email-client/gmail-client');
const { Account } = require('../lib/account');
const { MESSAGE_DELETED_NOTIFY, CHANGE_EVENT_RETRY_DELAYS, OUTLOOK_MISSED_LOOKBACK, OUTLOOK_ANNOUNCED_RETENTION } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

// The shape the API transports throw for a failed request
function apiError(status) {
    return Object.assign(new Error('OAuth2 request failed'), { oauthRequest: { status, response: { error: { code: 'UnknownError' } } } });
}

// An in-memory stand-in for the Account methods the clients call
function stubStore(queue = [], due = []) {
    const store = {
        deferred: [],
        completed: [],
        asked: 0,
        listDueChangeEvents: async () => {
            store.asked++;
            return { due: due.splice(0).map((event, i) => ({ event, member: `member-${i}` })), next: null };
        },
        completeChangeEvent: async member => store.completed.push(member),
        deferChangeEvent: async (event, dueTime) => store.deferred.push({ event, dueTime }),
        pullQueueEvent: async () => (queue.length ? queue.shift() : null)
    };
    return store;
}

function makeOutlook(accountObject) {
    const outlook = new OutlookClient('test-account', { redis });
    outlook.logger = noopLogger;
    outlook.oauth2UserPath = 'me';
    outlook.accountObject = accountObject;
    outlook._updateLastNotificationTime = async () => {};
    outlook.getMessageFetchOptions = async () => ({});
    return outlook;
}

// Like the real processNew(), which clears messageData.path before it returns
function clearsPath(fn) {
    return async messageData => {
        const result = await fn(messageData);
        messageData.path = undefined;
        return result;
    };
}

function makeGmail(accountObject, account = 'test-account') {
    const gmail = new GmailClient(account, { redis });
    gmail.logger = noopLogger;
    gmail.accountObject = accountObject;
    gmail.getMessageFetchOptions = async () => ({});
    gmail.getLabels = async () => [];
    return gmail;
}

test('BaseClient.deferFailedChangeEvent()', async t => {
    await t.test('a transient failure is deferred with the next delay on the schedule', async () => {
        const store = stubStore();
        const client = makeOutlook(store);

        const before = Date.now();
        await client.deferFailedChangeEvent({ type: 'created', message: 'm1' }, apiError(504), ['m1']);
        await client.deferFailedChangeEvent({ type: 'created', message: 'm2', attempt: 2 }, apiError(503), ['m2']);

        assert.deepEqual(
            store.deferred.map(entry => entry.event),
            [
                { type: 'created', message: 'm1', attempt: 1 },
                { type: 'created', message: 'm2', attempt: 3 }
            ]
        );
        const delays = store.deferred.map(entry => entry.dueTime - before);
        assert.ok(delays[0] >= CHANGE_EVENT_RETRY_DELAYS[0] && delays[0] < CHANGE_EVENT_RETRY_DELAYS[0] + 1000);
        assert.ok(delays[1] >= CHANGE_EVENT_RETRY_DELAYS[2] && delays[1] < CHANGE_EVENT_RETRY_DELAYS[2] + 1000);
        assert.equal(client.deferredDueAt, store.deferred[0].dueTime, 'the earliest due time is remembered');
    });

    await t.test('network failures and throttling are retried', async () => {
        const store = stubStore();
        const client = makeOutlook(store);

        await client.deferFailedChangeEvent(
            { type: 'updated', message: 'm1' },
            Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } })
        );
        await client.deferFailedChangeEvent({ type: 'updated', message: 'm2' }, apiError(429));

        assert.equal(store.deferred.length, 2);
    });

    for (const [label, event, err] of [
        ['the last attempt', { type: 'created', message: 'm1', attempt: CHANGE_EVENT_RETRY_DELAYS.length }, apiError(502)],
        ['a failure that is not the service failing', { type: 'created', message: 'm1' }, apiError(400)]
    ]) {
        await t.test(`${label} is given up on`, async () => {
            const store = stubStore();
            const client = makeOutlook(store);
            const errors = [];
            client.logger = Object.assign({}, noopLogger, { error: entry => errors.push(entry) });

            await client.deferFailedChangeEvent(event, err, ['m1']);

            assert.equal(store.deferred.length, 0);
            assert.equal(errors[0].msg, 'Failed to process mailbox change, giving up');
            assert.deepEqual(errors[0].messageIds, ['m1']);
        });
    }

    await t.test('the retry timer runs the usual processing when due and is cancelled on close', async () => {
        const client = makeOutlook(stubStore());
        let retried = 0;
        client.triggerSync = () => retried++;

        client.deferredDueAt = Date.now() + 60 * 1000;
        client.scheduleDeferredRetryTimer();
        client.cancelDeferredRetryTimer();
        assert.equal(client.deferredDueAt, undefined, 'the next run asks Redis again');

        client.deferredDueAt = Date.now() - 1;
        client.scheduleDeferredRetryTimer();
        await new Promise(resolve => setTimeout(resolve, 20));
        assert.equal(retried, 1);
    });
});

test('OutlookClient.processHistory()', async t => {
    await t.test('a 504 on a created event defers it and the drain continues', async () => {
        const store = stubStore([
            { type: 'created', message: 'm1' },
            { type: 'updated', message: 'm2' }
        ]);
        const outlook = makeOutlook(store);
        outlook.prepareNewMessage = async () => {
            throw apiError(504);
        };
        const updated = [];
        outlook.processUpdatedMessage = async emailId => updated.push(emailId);

        await outlook.processHistory();

        assert.deepEqual(updated, ['m2']);
        assert.deepEqual(
            store.deferred.map(entry => entry.event),
            [{ type: 'created', message: 'm1', attempt: 1 }]
        );
    });

    await t.test('due retries are processed ahead of the queue and dropped from the store once handled', async () => {
        const store = stubStore(
            [{ type: 'updated', message: 'queued' }],
            [
                { type: 'updated', message: 'retried', attempt: 1 },
                { type: 'updated', message: 'fails-again', attempt: 1 }
            ]
        );
        const outlook = makeOutlook(store);
        const updated = [];
        outlook.processUpdatedMessage = async emailId => {
            if (emailId === 'fails-again') {
                throw apiError(503);
            }
            updated.push(emailId);
        };

        await outlook.processHistory();

        assert.deepEqual(updated, ['retried', 'queued']);
        assert.deepEqual(store.completed, ['member-0', 'member-1']);
        assert.deepEqual(
            store.deferred.map(entry => entry.event),
            [{ type: 'updated', message: 'fails-again', attempt: 2 }]
        );
    });

    await t.test('a message is marked seen only once it was announced, so a failed one is not skipped on its retry', async () => {
        const outlook = makeOutlook(stubStore());
        const emailId = `lock-test-${process.pid}`;
        const dedupeKey = `${emailId}:created`;
        outlook.prepareNewMessage = async () => ({ id: emailId, path: 'INBOX' });
        const announced = [];
        let fail = true;
        outlook.processNew = clearsPath(async messageData => {
            if (fail) {
                throw apiError(502);
            }
            announced.push(messageData.id);
        });

        await assert.rejects(outlook.processChangeEvent({ type: 'created', message: emailId }, {}), /OAuth2 request failed/);
        assert.equal(await outlook.isRecentlySeen(dedupeKey, 'INBOX'), false);

        fail = false;
        await outlook.processChangeEvent({ type: 'created', message: emailId }, {});
        await outlook.processChangeEvent({ type: 'created', message: emailId }, {});
        assert.deepEqual(announced, [emailId], 'announced once, the repeat is skipped as recently seen');

        await redis.hdel(outlook.dedupeBucketKeys()[1], dedupeKey);
        await redis.del(outlook.getAnnouncedKey());
    });

    await t.test('a drain with nothing deferred asks Redis only once', async () => {
        const store = stubStore();
        const outlook = makeOutlook(store);

        await outlook.processHistory();
        await outlook.processHistory();

        assert.equal(store.asked, 1);
    });

    await t.test('missed notification recovery defers a message it could not fetch', async () => {
        const store = stubStore();
        const outlook = makeOutlook(store);
        outlook.request = async () => ({ value: [{ id: 'm1', parentFolderId: 'f1' }] });
        outlook.getCachedMailboxListing = async () => null;
        outlook.prepareNewMessage = async () => {
            throw apiError(503);
        };

        await outlook.syncMissedMessages({ since: Date.now() - 60 * 1000 });

        assert.deepEqual(
            store.deferred.map(entry => entry.event),
            [{ type: 'created', message: 'm1', attempt: 1 }]
        );
    });

    await t.test('missed notification recovery does not mark a message it could not fetch as announced', async () => {
        const store = stubStore();
        const outlook = makeOutlook(store);
        outlook.account = `recovery-unmarked-${process.pid}`;
        const emailId = `recovery-lock-${process.pid}`;
        outlook.request = async () => ({ value: [{ id: emailId, parentFolderId: 'f1' }] });
        outlook.prepareNewMessage = async () => {
            throw apiError(503);
        };

        await outlook.syncMissedMessages({ since: Date.now() - 60 * 1000 });

        assert.equal(store.deferred.length, 1);
        assert.deepEqual(await outlook.getAnnounced([emailId]), new Set());
        await redis.del(outlook.getAccountKey());
    });
});

test('Outlook missed-notification recovery', async t => {
    await t.test('looks back past the last notification, to when Graph may have started dropping', async () => {
        const outlook = makeOutlook(null);
        const receivedAt = Date.now();
        const margin = 2 * 60 * 1000;
        // [outlookLastNotification, outlookAnnouncedSince, outlookRecoveredUntil]
        const fields = values => {
            outlook.redis = { hmget: async () => values.map(value => (value ? String(value) : null)) };
        };

        fields([receivedAt - 60 * 1000]);
        assert.equal(await outlook.missedRecoveryStart(receivedAt), receivedAt - OUTLOOK_MISSED_LOOKBACK);

        const quietSince = receivedAt - OUTLOOK_MISSED_LOOKBACK - 60 * 60 * 1000;
        fields([quietSince]);
        assert.equal(await outlook.missedRecoveryStart(receivedAt), quietSince - margin, 'an older last notification wins');

        fields([]);
        assert.equal(await outlook.missedRecoveryStart(receivedAt), receivedAt - OUTLOOK_MISSED_LOOKBACK);
    });

    await t.test('never looks back past what announced messages can be checked against', async () => {
        const outlook = makeOutlook(null);
        const receivedAt = Date.now();
        const margin = 2 * 60 * 1000;
        const fields = values => {
            outlook.redis = { hmget: async () => values.map(value => (value ? String(value) : null)) };
        };

        const start = await (async () => {
            fields([receivedAt - 3 * 24 * 60 * 60 * 1000]);
            return outlook.missedRecoveryStart(receivedAt);
        })();
        assert.ok(start >= receivedAt - OUTLOOK_ANNOUNCED_RETENTION, 'days offline are not replayed');

        const upgradedAt = receivedAt - 30 * 60 * 1000;
        fields([null, upgradedAt]);
        assert.equal(await outlook.missedRecoveryStart(receivedAt), upgradedAt, 'nothing before announced messages were first recorded');

        const lastPass = receivedAt - 10 * 60 * 1000;
        fields([null, null, lastPass]);
        assert.equal(await outlook.missedRecoveryStart(receivedAt), lastPass - margin, 'nothing a previous pass already covered');
    });

    await t.test('pages oldest first and skips messages already announced', async () => {
        const outlook = makeOutlook(stubStore());
        outlook.account = `recovery-pages-${process.pid}`;
        const ids = ['a', 'b', 'c'].map(id => `${id}-${process.pid}`);
        await outlook.markAnnounced(ids[1], 'INBOX');

        const queries = [];
        outlook.request = async (url, method, payload) => {
            queries.push({ url, payload });
            return url === 'https://graph.example/next'
                ? { value: [{ id: ids[2], parentFolderId: 'f1' }] }
                : {
                      value: [
                          { id: ids[0], parentFolderId: 'f1' },
                          { id: ids[1], parentFolderId: 'f1' }
                      ],
                      '@odata.nextLink': 'https://graph.example/next'
                  };
        };
        outlook.prepareNewMessage = async id => ({ id, path: 'INBOX' });
        const announced = [];
        outlook.processNew = clearsPath(async messageData => announced.push(messageData.id));

        const before = Date.now();
        await outlook.syncMissedMessages({ since: Date.now() - 60 * 1000, options: {} });

        assert.equal(queries[0].payload.$orderby, 'receivedDateTime asc');
        assert.equal(queries[1].payload, null, 'the next page link carries the query');
        assert.deepEqual(announced, [ids[0], ids[2]]);
        assert.deepEqual(await outlook.getAnnounced(ids), new Set(ids), 'recovered messages are remembered too');
        assert.equal(await redis.hget(outlook.dedupeBucketKeys()[1], `${ids[0]}:created`), 'INBOX', 'with the path processNew() cleared');
        assert.ok(Number(await redis.hget(outlook.getAccountKey(), 'outlookRecoveredUntil')) >= before, 'the next pass starts here');

        await redis.del(outlook.getAnnouncedKey(), outlook.getAccountKey());
        for (const id of ids) {
            await redis.hdel(outlook.dedupeBucketKeys()[1], `${id}:created`);
        }
    });

    await t.test('a failed page fails the recovery, so it is retried as a whole', async () => {
        const store = stubStore([], [{ type: 'missedRecovery', receivedAt: Date.now() }]);
        const outlook = makeOutlook(store);
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        outlook.request = async () => {
            throw apiError(503);
        };

        await outlook.processHistory();
        outlook.cancelDeferredRetryTimer();

        assert.equal(store.deferred.length, 1);
        assert.equal(store.deferred[0].event.type, 'missedRecovery');
        assert.equal(store.deferred[0].event.attempt, 1);
        assert.deepEqual(store.completed, ['member-0']);
    });

    await t.test('several requests due in one drain are served by one recovery pass', async () => {
        const now = Date.now();
        const store = stubStore(
            [],
            [
                { type: 'missedRecovery', receivedAt: now - 1000 },
                { type: 'missedRecovery', receivedAt: now }
            ]
        );
        const outlook = makeOutlook(store);
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        const passes = [];
        outlook.syncMissedMessages = async ({ since }) => passes.push(since);

        await outlook.processHistory();

        assert.deepEqual(passes, [now - 1000 - OUTLOOK_MISSED_LOOKBACK]);
        assert.deepEqual(store.completed, ['member-0', 'member-1']);
    });

    await t.test('the lifecycle hook makes the next drain look for the stored request, even mid-drain', async () => {
        const outlook = makeOutlook(stubStore());
        outlook.deferredDueAt = null;
        let drains = 0;
        let release;
        outlook.processHistory = () => {
            drains++;
            return drains === 1 ? new Promise(resolve => (release = resolve)) : Promise.resolve();
        };

        outlook.triggerSync();
        assert.equal(outlook.recoverMissedNotifications(), true);
        assert.equal(outlook.deferredDueAt, undefined, 'the next drain asks Redis');
        assert.equal(drains, 1, 'a drain is already running');

        release();
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(drains, 2, 'it runs once more after the current drain');
    });

    await t.test('announced messages are remembered for the retention window only', async () => {
        const outlook = makeOutlook(null);
        outlook.account = `announced-${process.pid}`;
        const [fresh, old] = [`fresh-${process.pid}`, `old-${process.pid}`];

        await outlook.markAnnounced(fresh, 'INBOX');
        await redis.zadd(outlook.getAnnouncedKey(), Date.now() - OUTLOOK_ANNOUNCED_RETENTION - 1000, old);

        assert.deepEqual(await outlook.getAnnounced([fresh, old, 'never']), new Set([fresh]));
        assert.ok((await redis.pttl(outlook.getAnnouncedKey())) > 0, 'the set expires with the account idle');

        await redis.del(outlook.getAnnouncedKey());
        await redis.hdel(outlook.dedupeBucketKeys()[1], `${fresh}:created`);
    });
});

test('Account.queueMissedRecovery()', async t => {
    await t.test('stores a recovery request that is due right away', async () => {
        const account = new Account({ redis, account: `queue-missed-${process.pid}`, logger: noopLogger, call: async () => {} });

        const before = Date.now();
        await account.queueMissedRecovery();
        const { due } = await account.listDueChangeEvents();

        assert.equal(due.length, 1);
        assert.equal(due[0].event.type, 'missedRecovery');
        assert.ok(due[0].event.receivedAt >= before);

        await redis.del(account.getDeferredQueueKey());
    });
});

test('OutlookClient change probes do not mistake a failed request for a missing message', async t => {
    await t.test('a 5xx throws instead of reporting a deletion or dropping the update', async () => {
        const outlook = makeOutlook(null);
        const notifications = [];
        outlook.notify = async (mailbox, event) => notifications.push(event);
        outlook.request = async () => {
            throw apiError(504);
        };

        await assert.rejects(outlook.processDeletedMessage('m1'), /OAuth2 request failed/);
        await assert.rejects(outlook.processUpdatedMessage('m1'), /OAuth2 request failed/);
        assert.deepEqual(notifications, []);
    });

    await t.test('a 404 still reports the deletion and ignores the update', async () => {
        const outlook = makeOutlook(null);
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

test('OutlookClient.resolveFolder() refreshes a stale cached listing', async t => {
    await t.test('a folder missing from the cache is looked up in a fresh listing when the folders changed', async () => {
        const outlook = makeOutlook(null);
        outlook.account = `folder-refresh-${process.pid}`;
        outlook.getCachedMailboxListing = async () => [{ id: 'old', pathName: 'Old' }];
        const folderChanges = [true, false];
        outlook.renewMailboxFolderCache = async () => folderChanges.shift();
        let crawls = 0;
        outlook.getMailboxListing = async () => {
            crawls++;
            return [
                { id: 'old', pathName: 'Old' },
                { id: 'new', pathName: 'New' }
            ];
        };

        assert.equal((await outlook.resolveFolder('new', { byId: true })).pathName, 'New');
        assert.equal(await outlook.resolveFolder('unknown', { byId: true }), undefined);
        assert.equal(crawls, 1, 'a miss with no folder change does not crawl');

        await redis.del(outlook.getAccountCacheKey());
    });

    await t.test('a failed crawl forgets the folder delta, so the next miss asks again', async () => {
        const outlook = makeOutlook(null);
        outlook.account = `folder-refresh-fail-${process.pid}`;
        outlook.getCachedMailboxListing = async () => [{ id: 'old', pathName: 'Old' }];
        outlook.renewMailboxFolderCache = async () => true;
        outlook.getMailboxListing = async () => {
            throw apiError(503);
        };
        await redis.hset(outlook.getAccountKey(), 'outlookMailFoldersDeltaUrl', 'https://graph.example/delta');

        await assert.rejects(outlook.resolveFolder('new', { byId: true }), /OAuth2 request failed/);
        assert.equal(await redis.hget(outlook.getAccountKey(), 'outlookMailFoldersDeltaUrl'), null);

        await redis.del(outlook.getAccountKey());
    });
});

test('Account.pushQueueEvents()', async t => {
    await t.test('a failed queue write is thrown, so Graph is answered with an error and redelivers', async () => {
        const account = new Account({
            redis: {
                lpush: async () => {
                    throw new Error('Redis is down');
                }
            },
            account: 'a1',
            logger: noopLogger,
            call: async () => {}
        });

        await assert.rejects(account.pushQueueEvents([{ type: 'created', message: 'm1' }]), /Redis is down/);
    });

    await t.test('all events of a delivery go in one write', async () => {
        const writes = [];
        const account = new Account({
            redis: { lpush: async (key, ...values) => writes.push(values.length) },
            account: 'a1',
            logger: noopLogger,
            call: async () => {}
        });

        await account.pushQueueEvents([
            { type: 'created', message: 'm1' },
            { type: 'deleted', message: 'm2' }
        ]);

        assert.deepEqual(writes, [2]);
    });
});

test('GmailClient history retries', async t => {
    const added = id => ({ message: { id, threadId: 't1', labelIds: ['INBOX'] } });

    await t.test('a message that fails to fetch is deferred on its own, the rest of the entry is announced', async () => {
        const store = stubStore();
        const gmail = makeGmail(store);
        gmail.prepareNewMessage = async eventEntry => {
            if (eventEntry.id === 'bad') {
                throw apiError(500);
            }
            return { id: eventEntry.id };
        };
        const announced = [];
        gmail.processNew = async messageData => announced.push(messageData.id);

        await gmail.processHistoryEntry({ id: '10', messagesAdded: [added('a'), added('bad'), added('c')] });

        assert.deepEqual(announced, ['a', 'c']);
        assert.equal(store.deferred.length, 1);
        assert.equal(store.deferred[0].event.type, 'created');
        assert.equal(store.deferred[0].event.message.id, 'bad');
    });

    await t.test('a run whose labels cannot be read announces nothing and leaves the cursor where it was', async () => {
        const account = `labels-fail-${process.pid}`;
        const store = stubStore();
        const gmail = makeGmail(store, account);
        gmail.getLabels = async () => {
            throw apiError(503);
        };
        const notifications = [];
        gmail.notify = async (mailbox, event) => notifications.push(event);
        gmail.request = async () => ({
            history: [
                {
                    id: '101',
                    labelsAdded: [{ message: { id: 'l1', labelIds: ['STARRED'] }, labelIds: ['STARRED'] }],
                    messagesAdded: [added('n1')]
                }
            ],
            historyId: '101'
        });
        await redis.hset(gmail.getAccountKey(), 'googleHistoryId', '100');

        await assert.rejects(gmail.processHistory(100, 101), /OAuth2 request failed/);

        assert.deepEqual(notifications, []);
        assert.equal(store.deferred.length, 0, 'nothing is deferred, the next run fetches the entry again');
        assert.equal(await redis.hget(gmail.getAccountKey(), 'googleHistoryId'), '100');
        assert.equal(await redis.hget(gmail.getAccountKey(), 'googleHistoryProcessing'), null, 'no strike against the entry');
        await redis.del(gmail.getAccountKey());
    });

    await t.test('due retries are processed at the start of a history run', async () => {
        const store = stubStore([], [{ type: 'created', message: { id: 'm1' }, attempt: 1 }]);
        const gmail = makeGmail(store);
        gmail.prepareNewMessage = async eventEntry => ({ id: eventEntry.id });
        const announced = [];
        gmail.processNew = async messageData => announced.push(messageData.id);
        gmail.request = async () => ({ history: [], historyId: '10' });

        await gmail.processHistory(10, 10);

        assert.deepEqual(announced, ['m1']);
        assert.deepEqual(store.completed, ['member-0']);
        assert.equal(store.deferred.length, 0);
    });

    await t.test('a queued follow-up run starts from the stored cursor', async () => {
        const gmail = makeGmail(stubStore());
        gmail.redis = { hget: async () => '150' };
        const runs = [];
        gmail.triggerSync = (current, updated) => runs.push([current, updated]);

        gmail.triggerSyncFromCursor(200);
        gmail.triggerSyncFromCursor();
        await new Promise(resolve => setImmediate(resolve));

        assert.deepEqual(runs, [
            [150, 200],
            [150, 150]
        ]);
    });

    await t.test('an expired cursor on a poll moves to the current history ID', async () => {
        const account = `expired-cursor-${process.pid}`;
        const gmail = makeGmail(stubStore(), account);
        gmail.request = async url => {
            if (/\/profile$/.test(url)) {
                return { historyId: '900' };
            }
            throw Object.assign(new Error('Not found'), { oauthRequest: { status: 404, response: { error: { code: 404 } } } });
        };

        await gmail.processHistory(100, 100);

        assert.equal(await redis.hget(gmail.getAccountKey(), 'googleHistoryId'), '900');
        await redis.del(gmail.getAccountKey());
    });
});

test('Account deferred change store', async t => {
    const accountId = `test-change-retry-${process.pid}`;
    const account = new Account({ redis, account: accountId, logger: noopLogger, call: async () => {} });

    const cleanup = () => redis.del(account.getExternalQueueKey(), account.getDeferredQueueKey(), account.getAccountKey());
    t.beforeEach(cleanup);
    t.after(cleanup);

    await t.test('only due changes are listed, and they stay stored until completed', async () => {
        const now = Date.now();
        await account.deferChangeEvent({ type: 'created', message: 'due', attempt: 1 }, now - 1000);
        await account.deferChangeEvent({ type: 'created', message: 'later', attempt: 1 }, now + 60 * 1000);

        const first = await account.listDueChangeEvents();
        assert.deepEqual(
            first.due.map(entry => entry.event),
            [{ type: 'created', message: 'due', attempt: 1 }]
        );
        assert.equal(first.next, now + 60 * 1000);

        assert.equal((await account.listDueChangeEvents()).due.length, 1, 'a worker dying here loses nothing');

        await account.completeChangeEvent(first.due[0].member);
        assert.deepEqual(await account.listDueChangeEvents(), { due: [], next: now + 60 * 1000 });
    });

    await t.test('an empty store reports nothing due', async () => {
        assert.deepEqual(await account.listDueChangeEvents(), { due: [], next: null });
    });

    await t.test('an Outlook message whose fetch failed is announced on the retry', async () => {
        const outlook = makeOutlook(account);
        outlook.account = accountId;
        const emailId = `retried-${process.pid}`;
        let fail = true;
        outlook.prepareNewMessage = async emailId => {
            if (fail) {
                throw apiError(504);
            }
            return { id: emailId, path: 'INBOX' };
        };
        const announced = [];
        outlook.processNew = clearsPath(async messageData => announced.push(messageData.id));

        try {
            await account.pushQueueEvents([{ type: 'created', message: emailId }]);

            await outlook.processHistory();
            assert.deepEqual(announced, []);
            assert.ok(outlook.deferredDueAt > Date.now(), 'the retry is due later');

            // Make the deferred change due now instead of waiting a minute
            await account.deferChangeEvent({ type: 'created', message: emailId, attempt: 1 }, Date.now() - 1);
            outlook.cancelDeferredRetryTimer();
            fail = false;
            await outlook.processHistory();

            assert.deepEqual(announced, [emailId]);
            assert.deepEqual(await account.listDueChangeEvents(), { due: [], next: null });
        } finally {
            await redis.hdel(outlook.dedupeBucketKeys()[1], `${emailId}:created`);
            await redis.del(outlook.getAnnouncedKey());
        }
    });

    await t.test('a Gmail message whose fetch failed is announced on the retry, and the cursor moves on', async () => {
        const gmail = makeGmail(account, accountId);
        let fail = true;
        gmail.prepareNewMessage = async eventEntry => {
            if (fail) {
                throw apiError(504);
            }
            return { id: eventEntry.id };
        };
        const announced = [];
        gmail.processNew = async messageData => announced.push(messageData.id);
        gmail.request = async () => ({ history: [{ id: '101', messagesAdded: [{ message: { id: 'g1', labelIds: ['INBOX'] } }] }], historyId: '101' });

        await gmail.processHistory(100, 101);
        assert.deepEqual(announced, []);
        assert.equal(await redis.hget(gmail.getAccountKey(), 'googleHistoryId'), '101');

        const [deferred] = await redis.zrange(account.getDeferredQueueKey(), 0, 0);
        await redis.zadd(account.getDeferredQueueKey(), 'XX', Date.now() - 1, deferred);
        gmail.cancelDeferredRetryTimer();
        fail = false;
        gmail.request = async () => ({ history: [], historyId: '101' });
        await gmail.processHistory(101, 101);

        assert.deepEqual(announced, ['g1']);
    });
});
