'use strict';

// GmailClient.listMessages() has four shapes: a single message looked up by emailId, a whole
// thread paged locally, an id-only listing for the export worker (metadataOnly), and the regular
// listing that fetches every listed message. Gmail pages with tokens only, so a numeric page is
// refused. The request stub answers by URL, and formatMessage() is replaced by a marker so the
// tests pin which payloads reach it and with which options.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

const API = 'https://gmail.googleapis.com/gmail/v1/users/me';

const notFound = () => Object.assign(new Error('Requested entity was not found.'), { statusCode: 404, oauthRequest: { status: 404 } });

/**
 * @param {Object} routes - Maps a URL suffix (after /users/me) to a response or a function of the params
 * @returns {{gmail: GmailClient, requests: Array<Object>}}
 */
function makeListClient(routes) {
    const gmail = new GmailClient('test-account', { redis });
    gmail.logger = noopLogger;
    gmail.prepare = async () => {};
    gmail.getLabel = async path => ({ INBOX: { id: 'INBOX' }, Work: { id: 'Label_7' } })[path] || null;
    gmail.formatMessage = (entry, opts) => ({ id: entry.id, opts });

    const requests = [];
    gmail.request = async (url, method, params) => {
        requests.push({ url: url.slice(API.length), method, params });
        const route = routes[url.slice(API.length)];
        const value = typeof route === 'function' ? route(params) : route;
        if (value instanceof Error) {
            throw value;
        }
        return value;
    };
    return { gmail, requests };
}

const ids = (prefix, count) => Array.from({ length: count }, (v, i) => ({ id: `${prefix}${i}` }));

test('GmailClient.listMessages() paging rules', async t => {
    await t.test('refuses a numeric page number', async () => {
        const { gmail, requests } = makeListClient({});

        await assert.rejects(gmail.listMessages({ page: 2 }), err => {
            assert.equal(err.code, 'InvalidInput');
            assert.equal(err.statusCode, 400);
            assert.equal(err.message, 'Invalid page number. Only paging cursors are allowed for Gmail accounts.');
            return true;
        });
        assert.deepEqual(requests, []);
    });

    await t.test('answers false for a folder that does not exist', async () => {
        const { gmail, requests } = makeListClient({});

        assert.equal(await gmail.listMessages({ path: 'Missing' }), false);
        assert.deepEqual(requests, []);
    });

    await t.test('a cursor round trip sends the next page token back to Gmail', async () => {
        const { gmail, requests } = makeListClient({
            '/messages': params =>
                params.pageToken ? { resultSizeEstimate: 30, messages: [] } : { resultSizeEstimate: 30, nextPageToken: '12345', messages: [] }
        });

        const first = await gmail.listMessages({ path: 'Work', pageSize: 10 }, { metadataOnly: true });
        assert.equal(first.page, 0);
        assert.equal(first.pages, 3);
        assert.equal(first.prevPageCursor, null);
        assert.match(first.nextPageCursor, /^gmail_/);

        const second = await gmail.listMessages({ path: 'Work', pageSize: 10, cursor: first.nextPageCursor }, { metadataOnly: true });
        assert.equal(second.page, 1);
        assert.equal(second.nextPageCursor, null);
        assert.ok(second.prevPageCursor !== null);

        assert.deepEqual(requests[0].params, { maxResults: 10, labelIds: ['Label_7'] });
        assert.deepEqual(requests[1].params, { maxResults: 10, labelIds: ['Label_7'], pageToken: '12345' });
    });

    await t.test('turns the search into a q parameter and leaves \\All unlabelled', async () => {
        const { gmail, requests } = makeListClient({ '/messages': { resultSizeEstimate: 0 } });

        await gmail.listMessages({ path: '\\All', search: { from: 'alice@example.com' } }, { metadataOnly: true });

        assert.equal(requests[0].params.labelIds, undefined);
        assert.match(requests[0].params.q, /from:/);
    });
});

test('GmailClient.listMessages() emailId shortcut', async t => {
    await t.test('fetches the one message in full and skips the listing', async () => {
        const { gmail, requests } = makeListClient({ '/messages/m%2F1': { id: 'm/1' } });

        const result = await gmail.listMessages({ path: 'INBOX', search: { emailId: 'm/1' } });

        assert.deepEqual(requests, [{ url: '/messages/m%2F1', method: 'get', params: { format: 'full' } }]);
        assert.deepEqual(result, {
            total: 1,
            page: 0,
            pages: 1,
            nextPageCursor: null,
            prevPageCursor: null,
            messages: [{ id: 'm/1', opts: { path: 'INBOX' } }]
        });
    });

    await t.test('an empty answer is an empty page', async () => {
        const { gmail } = makeListClient({ '/messages/m1': null });

        const result = await gmail.listMessages({ search: { emailId: 'm1' } });

        assert.deepEqual(result, { total: 0, page: 0, pages: 0, nextPageCursor: null, prevPageCursor: null, messages: [] });
    });
});

test('GmailClient.listMessages() thread listing', async t => {
    const thread = { messages: ids('t', 5) };

    await t.test('returns a short thread whole', async () => {
        const { gmail, requests } = makeListClient({ '/threads/th1': thread });

        const result = await gmail.listMessages({ path: 'INBOX', search: { threadId: 'th1' } });

        assert.deepEqual(requests[0].params, { format: 'full' });
        assert.equal(result.total, 5);
        assert.equal(result.pages, 1);
        assert.equal(result.nextPageCursor, null);
        assert.deepEqual(
            result.messages.map(m => m.id),
            ['t0', 't1', 't2', 't3', 't4']
        );
    });

    await t.test('pages a long thread locally and follows the cursor to the last page', async () => {
        const { gmail } = makeListClient({ '/threads/th1': () => ({ messages: ids('t', 5) }) });

        const first = await gmail.listMessages({ search: { threadId: 'th1' }, pageSize: 2 });
        assert.deepEqual(
            first.messages.map(m => m.id),
            ['t0', 't1']
        );
        assert.equal(first.total, 5);
        assert.equal(first.pages, 3);
        assert.equal(first.page, 0);

        const second = await gmail.listMessages({ search: { threadId: 'th1' }, pageSize: 2, cursor: first.nextPageCursor });
        assert.deepEqual(
            second.messages.map(m => m.id),
            ['t2', 't3']
        );
        assert.equal(second.page, 1);

        const third = await gmail.listMessages({ search: { threadId: 'th1' }, pageSize: 2, cursor: second.nextPageCursor });
        assert.deepEqual(
            third.messages.map(m => m.id),
            ['t4']
        );
        assert.equal(third.page, 2);
        assert.equal(third.nextPageCursor, null);
    });

    await t.test('a missing thread is an empty page', async () => {
        const { gmail } = makeListClient({ '/threads/th1': null });

        const result = await gmail.listMessages({ search: { threadId: 'th1' } });

        assert.equal(result.total, 0);
        assert.deepEqual(result.messages, []);
    });
});

test('GmailClient.listMessages() regular listing', async t => {
    await t.test('metadataOnly answers the ids without fetching a message', async () => {
        const { gmail, requests } = makeListClient({ '/messages': { resultSizeEstimate: 3, messages: ids('m', 3) } });

        const result = await gmail.listMessages({ path: 'INBOX' }, { metadataOnly: true });

        assert.equal(requests.length, 1);
        assert.deepEqual(result.messages, ids('m', 3));
    });

    await t.test('metadataOnly is honoured on the query too (the export worker passes it there)', async () => {
        const { gmail, requests } = makeListClient({ '/messages': { resultSizeEstimate: 1, messages: ids('m', 1) } });

        await gmail.listMessages({ path: 'INBOX', metadataOnly: true });

        assert.equal(requests.length, 1);
    });

    await t.test('fetches each listed message in listing order', async () => {
        const routes = { '/messages': { resultSizeEstimate: 25, messages: ids('m', 25) } };
        for (let i = 0; i < 25; i++) {
            routes[`/messages/m${i}`] = { id: `m${i}` };
        }
        const { gmail, requests } = makeListClient(routes);

        const result = await gmail.listMessages({ path: 'INBOX', pageSize: 25 });

        assert.equal(requests.length, 26);
        assert.equal(requests[1].params, undefined, 'the default format');
        assert.deepEqual(
            result.messages.map(m => m.id),
            ids('m', 25).map(m => m.id)
        );
        assert.deepEqual(result.messages[0].opts, { path: 'INBOX', minimalFields: undefined });
    });

    await t.test('minimalFields asks for the minimal format', async () => {
        const { gmail, requests } = makeListClient({ '/messages': { resultSizeEstimate: 1, messages: ids('m', 1) }, '/messages/m0': { id: 'm0' } });

        const result = await gmail.listMessages({ path: 'INBOX' }, { minimalFields: true });

        assert.deepEqual(requests[1].params, { format: 'minimal' });
        assert.equal(result.messages[0].opts.minimalFields, true);
    });

    await t.test('skips a message deleted between the listing and its fetch', async () => {
        const { gmail } = makeListClient({
            '/messages': { resultSizeEstimate: 3, messages: ids('m', 3) },
            '/messages/m0': { id: 'm0' },
            '/messages/m1': notFound(),
            '/messages/m2': { id: 'm2' }
        });

        const result = await gmail.listMessages({ path: 'INBOX' });

        assert.deepEqual(
            result.messages.map(m => m.id),
            ['m0', 'm2']
        );
    });

    await t.test('any other fetch failure fails the listing', async () => {
        const { gmail } = makeListClient({
            '/messages': { resultSizeEstimate: 2, messages: ids('m', 2) },
            '/messages/m0': { id: 'm0' },
            '/messages/m1': Object.assign(new Error('Backend Error'), { statusCode: 500 })
        });

        await assert.rejects(gmail.listMessages({ path: 'INBOX' }), /Backend Error/);
    });

    await t.test('an empty listing is an empty page', async () => {
        const { gmail } = makeListClient({ '/messages': { resultSizeEstimate: 0 } });

        const result = await gmail.listMessages({ path: 'INBOX' });

        assert.deepEqual(result, { total: 0, page: 0, pages: 0, nextPageCursor: null, prevPageCursor: null, messages: [] });
    });
});
