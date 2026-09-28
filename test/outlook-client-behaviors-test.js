'use strict';

// Hermetic unit tests for OutlookClient behaviors fixed in the client review: a failed
// category lookup no longer lets updateMessages() overwrite categories, the webhook queue
// drain survives a failing "created" event, a message gone before its notification was
// processed is reported as missing, a single delete purges from Deleted Items the way the
// bulk delete does, and the content-based bounce check running only when the message details
// route asks for it. The client is built with empty options and only the collaborators each
// method touches are stubbed.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { MESSAGE_MISSING_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');
const { testTokenRefreshClassification } = require('./helpers/token-refresh');
const { withInstantTimers } = require('./helpers/instant-timers');

registerRedisTeardown(redis);

function makeClient() {
    // The real test Redis: the account hash does not exist, which is what the client sees for
    // a fixture account - enough for the shared bookkeeping in BaseClient to run for real
    const outlook = new OutlookClient('test-account', { redis });
    outlook.logger = noopLogger;
    outlook.oauth2UserPath = 'me';
    outlook.prepare = async () => {};
    return outlook;
}

// A token endpoint that throttles or 5xxs has not refused the refresh token. Reporting that as
// an authentication failure webhooked authenticationError, parked the account and stopped the
// worker retrying init() - and the next attempt then contradicted it with authenticationSuccess.
testTokenRefreshClassification('OutlookClient.getTokenData() classifies a failed token refresh', makeClient);

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
                return { responses: fetchResponses(payload.requests) };
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
        const { outlook, batches } = makeUpdateClient(requests =>
            requests.map(req =>
                req.url.includes('/m1?')
                    ? { id: req.id, status: 200, body: { categories: ['Old'] } }
                    : { id: req.id, status: 404, body: { error: { message: 'not found' } } }
            )
        );

        const result = await outlook.updateMessages('INBOX', { emailIds: ['m1', 'm2'] }, { labels: { add: ['Work'] } });

        const patchBatch = batches[1];
        assert.deepEqual(
            patchBatch.map(req => [req.url, req.body.categories]),
            [['/me/messages/m1', ['Old', 'Work']]]
        );
        assert.deepEqual(result.emailIds, ['m1']);
        assert.deepEqual(result.failed, { emailIds: ['m2'] }, 'the skipped message is reported');
    });
});

// Throttled $batch items used to be logged and dropped, and the bulk operation reported success
// for whatever was left
test('OutlookClient bulk operations retry throttled batch items', async t => {
    function makeBatchClient(answer) {
        const outlook = makeClient();
        const batches = [];
        outlook.requestWithRetry = async (url, method, payload) => {
            assert.equal(url, '/$batch');
            batches.push(payload.requests);
            return { responses: payload.requests.map(req => Object.assign({ id: req.id }, answer(req, batches.length))) };
        };
        return { outlook, batches };
    }

    const emailIdOf = req => req.url.split('/')[3];

    await t.test('a throttled item is sent again after its Retry-After and succeeds', async () => {
        const { outlook, batches } = makeBatchClient((req, round) =>
            emailIdOf(req) === 'm2' && round === 1 ? { status: 429, headers: { 'Retry-After': '2' } } : { status: 204 }
        );

        outlook.resolveFolder = async () => ({ id: 'f-archive', pathName: 'Archive' });

        const { result, error, delays } = await withInstantTimers(() => outlook.moveMessages('INBOX', { emailIds: ['m1', 'm2', 'm3'] }, { path: 'Archive' }));
        assert.ifError(error);

        assert.deepEqual(
            batches.map(batch => batch.map(emailIdOf)),
            [['m1', 'm2', 'm3'], ['m2']]
        );
        assert.deepEqual(result.emailIds.sort(), ['m1', 'm2', 'm3']);
        assert.equal(result.failed, undefined);
        assert.ok(
            delays.some(delay => delay >= 2000 && delay < 2500),
            `the Retry-After of the item is honoured, got ${delays}`
        );
    });

    // Each chunk used to wait on its own before re-sending its throttled items, so a call
    // spanning many chunks could sleep once per chunk per round
    await t.test('throttled items of every chunk are re-sent together after one wait', async () => {
        const emailIds = Array.from({ length: 45 }, (v, i) => `m${i}`);
        const { outlook, batches } = makeBatchClient((req, round) =>
            ['m2', 'm30', 'm44'].includes(emailIdOf(req)) && round <= 3 ? { status: 429, headers: { 'retry-after': '1' } } : { status: 204 }
        );
        outlook.resolveFolder = async () => ({ id: 'f-archive', pathName: 'Archive' });

        const { result, error, delays } = await withInstantTimers(() => outlook.moveMessages('INBOX', { emailIds }, { path: 'Archive' }));
        assert.ifError(error);

        assert.deepEqual(
            batches.map(batch => batch.length),
            [20, 20, 5, 3],
            'three chunks, then the throttled items of all of them in one batch'
        );
        assert.deepEqual(batches[3].map(emailIdOf), ['m2', 'm30', 'm44']);
        assert.equal(delays.length, 1, 'one wait for the round, not one per chunk');
        assert.equal(result.emailIds.length, 45);
        assert.equal(result.failed, undefined);
    });

    await t.test('an item still throttled after the retries is reported as failed', async () => {
        const { outlook, batches } = makeBatchClient(req => (emailIdOf(req) === 'm2' ? { status: 503 } : { status: 204 }));

        const { result, error } = await withInstantTimers(() => outlook.deleteMessages('INBOX', { emailIds: ['m1', 'm2'] }, true));
        assert.ifError(error);

        assert.equal(batches.length, 3, 'the first attempt and two retries');
        assert.equal(result.deleted, true);
        assert.deepEqual(result.deletedMessages.emailIds, ['m1']);
        assert.deepEqual(result.failed, { emailIds: ['m2'] });
    });

    await t.test('nothing deleted when every item failed', async () => {
        const { outlook } = makeBatchClient(() => ({ status: 403, body: { error: { code: 'ErrorAccessDenied' } } }));

        const result = await outlook.deleteMessages('INBOX', { emailIds: ['m1'] }, true);

        assert.equal(result.deleted, false);
        assert.deepEqual(result.failed, { emailIds: ['m1'] });
    });
});

test('OutlookClient.getMessages() export folder lookup', async t => {
    // Called once per export batch; it used to crawl the whole folder tree on every call
    await t.test('uses the cached listing and resolves only the folders missing from it', async () => {
        const outlook = makeClient();
        let liveListings = 0;
        const resolved = [];
        outlook.getCachedMailboxListing = async () => [{ id: 'f-inbox', pathName: 'INBOX', specialUse: '\\Inbox' }];
        outlook.getMailboxListing = async () => {
            liveListings++;
            return [];
        };
        outlook.resolveFolder = async id => {
            resolved.push(id);
            return id === 'f-new' ? { id, pathName: 'New' } : undefined;
        };
        outlook.request = async (url, method, payload) => ({
            responses: payload.requests.map((req, i) => ({
                id: req.id,
                status: 200,
                body: { id: `m${i}`, parentFolderId: ['f-inbox', 'f-new', 'f-new', 'f-hidden'][i] }
            }))
        });
        outlook.formatMessage = (messageData, options) => ({ id: messageData.id, path: options.path });

        const settings = require('../lib/settings');
        const realGet = settings.get;
        settings.get = async key => (key === 'outlookExportBatchSize' ? 20 : realGet.call(settings, key));
        let results;
        try {
            results = await outlook.getMessages(['m0', 'm1', 'm2', 'm3'], {});
        } finally {
            settings.get = realGet;
        }

        assert.equal(liveListings, 0, 'no live folder crawl while a cached listing exists');
        assert.deepEqual(resolved, ['f-new', 'f-hidden'], 'each missing folder is resolved once');
        assert.deepEqual(
            results.map(entry => entry.data?.path),
            ['INBOX', 'New', 'New', undefined]
        );
    });
});

test('OutlookClient.getMessage() folder resolution', async t => {
    await t.test('a message in a folder missing from the listing is returned without a path', async () => {
        const outlook = makeClient();
        outlook.request = async () => ({ id: 'm1', parentFolderId: 'hidden-folder', subject: 'x' });
        outlook.resolveFolder = async () => undefined;

        const message = await outlook.getMessage('m1', {});

        assert.equal(message.id, 'm1', 'used to answer 404, which new-message processing read as a deleted message');
        assert.equal(message.path, undefined);
    });
});

test('OutlookClient.getRawMessage()', async t => {
    await t.test('returns the raw bytes unchanged', async () => {
        const outlook = makeClient();
        // ISO-8859-1 body: a UTF-8 text round-trip turns 0xE4 into U+FFFD
        const raw = Buffer.concat([Buffer.from('Subject: x\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n'), Buffer.from([0xe4, 0xf6, 0xfc])]);
        let requestOptions;
        outlook.request = async (url, method, payload, options) => {
            requestOptions = options;
            return raw;
        };

        const result = await outlook.getRawMessage('m1');

        assert.equal(requestOptions.returnBuffer, true);
        assert.ok(Buffer.isBuffer(result));
        assert.ok(result.equals(raw));
    });
});

test('OutlookClient.convertMessageToUploadObject() cid references', async t => {
    await t.test('a Content-ID with RegExp metacharacters is rewritten literally', () => {
        const outlook = makeClient();
        const cid = 'img(1)[a]\\b@example.com';
        const upload = outlook.convertMessageToUploadObject({
            html: `<img src="cid:<${cid}>"><img src="cid:<${cid}>">`,
            attachments: [{ cid: `<${cid}>`, filename: 'a.png', contentType: 'image/png', content: 'AAAA' }]
        });

        assert.equal(upload.body.content, `<img src="cid:${cid}"><img src="cid:${cid}">`);
        assert.equal(upload.attachments[0].contentId, cid);
        assert.equal(upload.attachments[0].isInline, true);
    });
});

test('OutlookClient.close()', async t => {
    // The worker catches and logs a rejected close(); the client itself no longer swallows the
    // state write failure, so a shutdown with Redis gone is visible in the worker log
    await t.test('a failing state write rejects after the state was switched', async () => {
        const outlook = makeClient();
        outlook.state = 'connected';
        outlook.setStateVal = async () => {
            throw new Error('Connection is closed.');
        };

        await assert.rejects(outlook.close(), /Connection is closed/);
        assert.equal(outlook.state, 'disconnected');
        assert.equal(outlook.closed, true);
    });
});

test('OutlookClient.processHistory()', async t => {
    await t.test('a failing created event does not abort the drain', async () => {
        const outlook = makeClient();
        const events = [
            { type: 'created', message: 'broken' },
            { type: 'updated', message: 'm2' }
        ];
        outlook.accountObject = {
            listDueChangeEvents: async () => ({ due: [], next: null }),
            pullQueueEvent: async () => (events.length ? events.shift() : null)
        };
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

test('OutlookClient.getMessage() bounce detection option', async t => {
    await t.test('runs the content check only when asked', async () => {
        const outlook = makeClient();
        let detections = 0;
        outlook.request = async () => ({ id: 'm1' });
        outlook.formatMessage = () => ({ id: 'm1', messageId: '<m1@example.com>' });
        outlook.redis = { pfadd: async () => 1 };
        outlook.detectBounce = async () => detections++;

        await outlook.getMessage('m1', {});
        assert.equal(detections, 0);

        await outlook.getMessage('m1', { detectBounce: true });
        assert.equal(detections, 1);
    });
});
