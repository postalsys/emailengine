'use strict';

// OutlookClient.listMessages() turns a listing query into one Graph request: the folder or the
// whole mailbox (\All, where every message carries its parentFolderId to find its path), one of
// three field sets, an OData filter or a $search, and offset paging or, for $search, Graph's
// skiptoken carried inside the cursor. An ordered category filter that Graph refuses as an
// InefficientFilter is retried once without ordering and the page is sorted locally. The request
// stub records the query sent and formatMessage() is replaced by a marker.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

const INBOX = { id: 'inbox-id', pathName: 'Inbox' };
const LISTING = [
    { id: 'inbox-id', pathName: 'Inbox' },
    { id: 'archive-id', pathName: 'Archive' }
];

const EXPAND = 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)';

/**
 * @param {Function|Array} responses - A function of (url, query, options) or a list answered in turn
 * @returns {{outlook: OutlookClient, requests: Array<Object>, warnings: Array<Object>, errors: Array<Object>}}
 */
function makeListClient(responses, opts = {}) {
    const outlook = new OutlookClient('test-account', { redis });
    const warnings = [];
    const errors = [];
    outlook.logger = Object.assign({}, noopLogger, { warn: entry => warnings.push(entry), error: entry => errors.push(entry) });
    outlook.oauth2UserPath = 'me';
    outlook.prepare = async () => {};
    outlook.resolveFolder = async path => (path === 'Inbox' ? INBOX : null);
    outlook.getCachedMailboxListing = async () => opts.cachedListing;
    outlook.getMailboxListing = async () => LISTING;
    outlook.formatMessage = (messageData, formatOpts) => ({ id: messageData.id, formatOpts });

    const requests = [];
    outlook.request = async (url, method, query, options) => {
        // a copy: the client deletes $orderBy from the same object before the retry
        requests.push({ url, method, query: Object.assign({}, query), options });
        const value = typeof responses === 'function' ? responses(url, query, options) : responses[requests.length - 1];
        if (value instanceof Error) {
            throw value;
        }
        return value;
    };
    return { outlook, requests, warnings, errors };
}

test('OutlookClient.listMessages() scope', async t => {
    await t.test('lists one folder by its id and formats with the folder path', async () => {
        const { outlook, requests } = makeListClient([{ '@odata.count': 1, value: [{ id: 'm1' }] }]);

        const result = await outlook.listMessages({ path: 'Inbox' });

        assert.equal(requests[0].url, '/me/mailFolders/inbox-id/messages');
        assert.equal(requests[0].method, 'get');
        assert.ok(!requests[0].query.$select.split(',').includes('parentFolderId'));
        assert.deepEqual(result.messages, [{ id: 'm1', formatOpts: { path: 'Inbox', showPath: false, minimalFields: undefined } }]);
    });

    await t.test('\\All lists the whole mailbox and resolves each path from the cached listing', async () => {
        const { outlook, requests } = makeListClient(
            [
                {
                    '@odata.count': 2,
                    value: [
                        { id: 'm1', parentFolderId: 'archive-id' },
                        { id: 'm2', parentFolderId: 'gone-id' }
                    ]
                }
            ],
            {
                cachedListing: LISTING
            }
        );

        const result = await outlook.listMessages({ path: '\\All' });

        assert.equal(requests[0].url, '/me/messages');
        assert.ok(requests[0].query.$select.split(',').includes('parentFolderId'));
        assert.deepEqual(
            result.messages.map(m => [m.id, m.formatOpts.path, m.formatOpts.showPath]),
            [
                ['m1', 'Archive', true],
                ['m2', undefined, true]
            ]
        );
    });

    await t.test('\\All falls back to a live listing when nothing is cached', async () => {
        const { outlook } = makeListClient([{ value: [{ id: 'm1', parentFolderId: 'inbox-id' }] }]);

        const result = await outlook.listMessages({ path: ['\\All'] });

        assert.equal(result.messages[0].formatOpts.path, 'Inbox');
    });

    await t.test('an unknown folder is a 404', async () => {
        const { outlook, requests } = makeListClient([]);

        await assert.rejects(outlook.listMessages({ path: 'Missing' }), err => {
            assert.equal(err.message, 'Listing failed');
            assert.equal(err.code, 'NotFound');
            assert.equal(err.statusCode, 404);
            assert.deepEqual(err.info, { response: 'Not able to find mailbox folder' });
            return true;
        });
        assert.deepEqual(requests, []);
    });
});

test('OutlookClient.listMessages() field sets', async t => {
    await t.test('the full set expands the attachments', async () => {
        const { outlook, requests } = makeListClient([{ value: [] }]);

        await outlook.listMessages({ path: 'Inbox' });

        assert.deepEqual(requests[0].query, {
            $count: true,
            $top: 20,
            $skip: 0,
            $skiptoken: undefined,
            $orderBy: 'receivedDateTime desc',
            $select:
                'id,conversationId,receivedDateTime,isRead,isDraft,flag,body,subject,from,replyTo,sender,toRecipients,ccRecipients,bccRecipients,internetMessageId,bodyPreview,categories',
            $expand: EXPAND
        });
        assert.equal(requests[0].options, undefined);
    });

    await t.test('metadataOnly drops the recipients and the attachments', async () => {
        const { outlook, requests } = makeListClient([{ value: [] }]);

        await outlook.listMessages({ path: 'Inbox' }, { metadataOnly: true });

        assert.equal(requests[0].query.$select, 'id,conversationId,receivedDateTime,isRead,isDraft,flag,body,subject,from,replyTo,sender,internetMessageId');
        assert.equal(requests[0].query.$expand, undefined);
    });

    await t.test('metadataOnly on the query is honoured (the export worker passes it there)', async () => {
        const { outlook, requests } = makeListClient([{ value: [] }]);

        await outlook.listMessages({ path: 'Inbox', metadataOnly: true });

        assert.equal(requests[0].query.$expand, undefined);
    });

    await t.test('minimalFields asks for the ids and the date only', async () => {
        const { outlook, requests } = makeListClient([{ value: [{ id: 'm1' }] }]);

        const result = await outlook.listMessages({ path: '\\All' }, { minimalFields: true, metadataOnly: true });

        assert.equal(requests[0].query.$select, 'id,conversationId,receivedDateTime,parentFolderId');
        assert.equal(requests[0].query.$expand, undefined);
        assert.equal(result.messages[0].formatOpts.minimalFields, true);
    });
});

test('OutlookClient.listMessages() paging', async t => {
    await t.test('offset paging answers page cursors both ways', async () => {
        const { outlook, requests } = makeListClient(() => ({ '@odata.count': 45, value: [] }));

        const first = await outlook.listMessages({ path: 'Inbox', pageSize: 20 });
        assert.equal(first.total, 45);
        assert.equal(first.pages, 3);
        assert.equal(first.page, 0);
        assert.equal(first.prevPageCursor, null);

        const second = await outlook.listMessages({ path: 'Inbox', pageSize: 20, cursor: first.nextPageCursor });
        assert.equal(second.page, 1);
        assert.equal(requests[1].query.$skip, 20);
        assert.equal(requests[1].query.$skiptoken, undefined);
        assert.ok(second.prevPageCursor);

        const last = await outlook.listMessages({ path: 'Inbox', pageSize: 20, page: 2 });
        assert.equal(requests[2].query.$skip, 40);
        assert.equal(last.nextPageCursor, null);
        assert.deepEqual(outlook.decodeCursorStr(last.prevPageCursor), { cursorPage: 1, skipToken: undefined });
    });

    await t.test('a $search carries the skiptoken through the cursor', async () => {
        const { outlook, requests } = makeListClient([
            { value: [{ id: 'm1' }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/me/messages?$search=x&$skiptoken=TOKEN-1' },
            { value: [{ id: 'm2' }] }
        ]);

        const first = await outlook.listMessages({ path: 'Inbox', search: { subject: 'hello' }, useOutlookSearch: true });

        assert.ok(requests[0].query.$search);
        for (const param of ['$skip', '$orderBy', '$count']) {
            assert.ok(!(param in requests[0].query), `${param} is not allowed with $search`);
        }
        assert.equal(first.total, undefined);
        assert.equal(first.pages, undefined);
        assert.equal(first.prevPageCursor, undefined, 'no way back with a skiptoken');
        assert.deepEqual(outlook.decodeCursorStr(first.nextPageCursor), { cursorPage: 1, skipToken: 'TOKEN-1' });

        const second = await outlook.listMessages({ path: 'Inbox', search: { subject: 'hello' }, useOutlookSearch: true, cursor: first.nextPageCursor });

        assert.equal(requests[1].query.$skiptoken, 'TOKEN-1');
        assert.equal(second.page, 1);
        assert.equal(second.nextPageCursor, null);
    });

    await t.test('an OData filter keeps receivedDateTime first so ordering still works', async () => {
        const { outlook, requests } = makeListClient([{ value: [] }]);

        await outlook.listMessages({ path: 'Inbox', search: { subject: 'hello' } });

        assert.match(requests[0].query.$filter, /^receivedDateTime gt 1970-01-01T00:00:00\.000Z and /);
        assert.equal(requests[0].query.$orderBy, 'receivedDateTime desc');
        assert.equal(requests[0].options, undefined, 'no ConsistencyLevel header without a category filter');
    });
});

test('OutlookClient.listMessages() category filter fallback', async t => {
    const inefficient = () =>
        Object.assign(new Error('Bad request'), {
            oauthRequest: {
                status: 400,
                response: { error: { code: 'InefficientFilter', message: 'The restriction or sort order is too complex for this operation.' } }
            }
        });

    await t.test('retries without ordering and sorts the page newest first', async () => {
        const { outlook, requests, warnings } = makeListClient([
            inefficient(),
            {
                value: [
                    { id: 'old', receivedDateTime: '2024-01-01T00:00:00Z' },
                    { id: 'new', receivedDateTime: '2024-03-01T00:00:00Z' },
                    { id: 'mid', receivedDateTime: '2024-02-01T00:00:00Z' }
                ]
            }
        ]);

        const result = await outlook.listMessages({ path: 'Inbox', search: { labels: { has: ['Work'] } } });

        assert.equal(requests.length, 2);
        assert.deepEqual(requests[0].options, { headers: { ConsistencyLevel: 'eventual' } });
        assert.equal(requests[0].query.$orderBy, 'receivedDateTime desc');
        assert.ok(!('$orderBy' in requests[1].query));
        assert.deepEqual(requests[1].options, { headers: { ConsistencyLevel: 'eventual' } });
        assert.deepEqual(
            result.messages.map(m => m.id),
            ['new', 'mid', 'old']
        );
        assert.ok(
            warnings.some(entry => entry.msg === 'Graph rejected ordered category filter, retrying without server-side ordering' && entry.path === 'Inbox')
        );
    });

    await t.test('recognises the refusal by its message too', async () => {
        const err = Object.assign(new Error('Bad request'), {
            oauthRequest: { response: { error: { code: 'ErrorInvalidRequest', message: 'Restriction or sort order is too complex' } } }
        });
        const { outlook, requests } = makeListClient([err, { value: [] }]);

        await outlook.listMessages({ path: 'Inbox', search: { labels: { not: ['Work'] } } });

        assert.equal(requests.length, 2);
    });

    await t.test('the same refusal without a category filter is not retried', async () => {
        const { outlook, requests, errors } = makeListClient([inefficient()]);

        await assert.rejects(outlook.listMessages({ path: 'Inbox', search: { subject: 'x' } }), /Bad request/);

        assert.equal(requests.length, 1);
        assert.ok(errors.some(entry => entry.msg === 'Failed to list messages' && entry.mailboxId === 'inbox-id' && entry.path === 'Inbox'));
    });

    await t.test('any other failure of a category filter is not retried', async () => {
        const { outlook, requests } = makeListClient([Object.assign(new Error('Server error'), { statusCode: 500 })]);

        await assert.rejects(outlook.listMessages({ path: 'Inbox', search: { labels: { has: ['Work'] } } }), /Server error/);

        assert.equal(requests.length, 1);
    });

    await t.test('a failed retry is logged and thrown', async () => {
        const { outlook, requests, errors } = makeListClient([inefficient(), new Error('Still failing')]);

        await assert.rejects(outlook.listMessages({ path: 'Inbox', search: { labels: { has: ['Work'] } } }), /Still failing/);

        assert.equal(requests.length, 2);
        assert.ok(errors.some(entry => entry.msg === 'Failed to list messages'));
    });
});
