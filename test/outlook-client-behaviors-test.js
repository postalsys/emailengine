'use strict';

// Hermetic unit tests for OutlookClient behaviors fixed in the client review: a failed
// category lookup no longer lets updateMessages() overwrite categories, the webhook queue
// drain survives a failing "created" event, a message gone before its notification was
// processed is reported as missing, a single delete purges from Deleted Items the way the
// bulk delete does, and the sync path fetches without the bounce lookup only the API response
// reads. The client is built with empty options and only the collaborators each method
// touches are stubbed.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { MESSAGE_MISSING_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

function makeClient() {
    const outlook = new OutlookClient('test-account', {});
    outlook.logger = noopLogger;
    outlook.oauth2UserPath = 'me';
    outlook.prepare = async () => {};
    return outlook;
}

test('OutlookClient.updateMessages() with label add/delete', async t => {
    function makeUpdateClient(fetchResponses) {
        const outlook = makeClient();
        const batches = [];
        outlook.requestWithRetry = async (url, method, payload) => {
            batches.push(payload.requests);
            if (payload.requests[0].method === 'GET') {
                if (fetchResponses instanceof Error) {
                    throw fetchResponses;
                }
                return { responses: fetchResponses };
            }
            return { responses: payload.requests.map(req => ({ id: req.id, status: 200 })) };
        };
        return { outlook, batches };
    }

    await t.test('a failed category fetch aborts the update instead of wiping the categories', async () => {
        const { outlook, batches } = makeUpdateClient(new Error('Graph is down'));

        await assert.rejects(outlook.updateMessages('INBOX', { emailIds: ['m1', 'm2'] }, { labels: { add: ['Work'] } }), /Graph is down/);

        assert.equal(batches.length, 1, 'no PATCH batch may follow a failed fetch');
    });

    await t.test('a message whose categories could not be read is skipped, the rest are patched', async () => {
        const { outlook, batches } = makeUpdateClient([
            { id: 'fetch_1', status: 200, body: { categories: ['Old'] } },
            { id: 'fetch_2', status: 503, body: { error: { message: 'try later' } } }
        ]);

        const result = await outlook.updateMessages('INBOX', { emailIds: ['m1', 'm2'] }, { labels: { add: ['Work'] } });

        const patchBatch = batches[1];
        assert.deepEqual(
            patchBatch.map(req => [req.url, req.body.categories]),
            [['/me/messages/m1', ['Old', 'Work']]]
        );
        assert.deepEqual(result.emailIds, ['m1']);
    });
});

test('OutlookClient.processHistory()', async t => {
    await t.test('a failing created event does not abort the drain', async () => {
        const outlook = makeClient();
        const events = [
            { type: 'created', message: 'broken' },
            { type: 'updated', message: 'm2' }
        ];
        outlook.accountObject = { pullQueueEvent: async () => (events.length ? events.shift() : null) };
        outlook.getMessageFetchOptions = async () => ({});
        outlook.prepareNewMessage = async () => {
            throw new Error('Graph is down');
        };
        const updated = [];
        outlook.processUpdatedMessage = async emailId => updated.push(emailId);
        let stamped = 0;
        outlook._updateLastNotificationTime = async () => stamped++;

        await outlook.processHistory();

        assert.deepEqual(updated, ['m2'], 'the event queued behind the failing one must still be processed');
        assert.equal(stamped, 1);
    });
});

test('OutlookClient.prepareNewMessage()', async t => {
    await t.test('reports a message deleted before its notification was processed as missing', async () => {
        const outlook = makeClient();
        const notifications = [];
        outlook.getMessage = async () => {
            throw Object.assign(new Error('Unknown message'), { code: 'NotFound', statusCode: 404 });
        };
        outlook.notify = async (mailbox, event, data) => notifications.push({ event, data });

        const messageData = await outlook.prepareNewMessage('gone', {});

        assert.equal(messageData, undefined);
        assert.deepEqual(notifications, [{ event: MESSAGE_MISSING_NOTIFY, data: { id: 'gone' } }]);
    });

    await t.test('any other fetch failure still propagates', async () => {
        const outlook = makeClient();
        outlook.getMessage = async () => {
            throw Object.assign(new Error('Service unavailable'), { statusCode: 503 });
        };

        await assert.rejects(outlook.prepareNewMessage('m1', {}), /Service unavailable/);
    });
});

test('OutlookClient.deleteMessage()', async t => {
    function makeDeleteClient(parentSpecialUse) {
        const outlook = makeClient();
        const calls = [];
        let listingReads = 0;
        // the plain and the retrying request paths land in the same recorder
        outlook.request = async (url, method, payload) => {
            calls.push({ url, method, payload });
            if (method === 'get') {
                return { id: 'm1', parentFolderId: 'id-parent' };
            }
            if (method === 'post') {
                return { id: 'm1', parentFolderId: 'id-trash' };
            }
            return '';
        };
        outlook.requestWithRetry = outlook.request;
        outlook.getCachedMailboxListing = async () => {
            listingReads++;
            return [
                { id: 'id-parent', pathName: 'Parent', specialUse: parentSpecialUse },
                { id: 'id-trash', pathName: 'Deleted Items', specialUse: '\\Trash' }
            ];
        };
        return { outlook, calls, listingReads: () => listingReads };
    }

    await t.test('moves a message from a normal folder to Deleted Items', async () => {
        const { outlook, calls, listingReads } = makeDeleteClient(undefined);

        const result = await outlook.deleteMessage('m1');

        assert.deepEqual(result, { deleted: true, moved: { destination: 'Deleted Items', message: 'm1' } });
        const move = calls.find(call => call.method === 'post');
        assert.deepEqual(move.payload, { destinationId: 'deleteditems' });
        assert.equal(listingReads(), 1, 'one listing read serves both the source and the destination lookup');
    });

    await t.test('purges a message that is already in Deleted Items, like deleteMessages() does', async () => {
        const { outlook, calls } = makeDeleteClient('\\Trash');

        const result = await outlook.deleteMessage('m1');

        assert.deepEqual(result, { deleted: true });
        assert.ok(!calls.some(call => call.method === 'post'), 'no move back into Deleted Items');
        assert.ok(
            calls.some(call => call.method === 'delete' && call.url === '/me/messages/m1'),
            'expected a permanent DELETE'
        );
    });
});

test('OutlookClient.getMessage() bounce lookup', async t => {
    function makeFetchClient() {
        const outlook = makeClient();
        let lookups = 0;
        outlook.request = async () => ({ id: 'm1' });
        outlook.formatMessage = () => ({ id: 'm1', messageId: '<m1@example.com>' });
        outlook.attachBounces = async () => lookups++;
        outlook.redis = { pfadd: async () => 1 };
        return { outlook, lookups: () => lookups };
    }

    await t.test('an API fetch attaches the recorded bounces', async () => {
        const { outlook, lookups } = makeFetchClient();

        await outlook.getMessage('m1', {});

        assert.equal(lookups(), 1);
    });

    await t.test('the sync path fetches without the lookup it never reads', async () => {
        const { outlook, lookups } = makeFetchClient();

        const messageData = await outlook.prepareNewMessage('m1', {});

        assert.equal(messageData.id, 'm1');
        assert.equal(lookups(), 0);
    });
});
