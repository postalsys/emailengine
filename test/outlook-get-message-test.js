'use strict';

// OutlookClient.getMessage() and getMessages(), the single and the batched (export) fetch of a Graph
// message. Both carried their own copy of the field list, the header parsing and the formatting, so
// they are pinned here before that moves into shared helpers: the request each one sends, how Graph
// errors are mapped, marking as seen and embedding inline images (single), and the batch retry with
// its backoff, the per-message errors and the messages a batch answer left out (batched).

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const SELECT_FULL = [
    'id',
    'conversationId',
    'receivedDateTime',
    'isRead',
    'isDraft',
    'flag',
    'body',
    'subject',
    'from',
    'replyTo',
    'sender',
    'toRecipients',
    'ccRecipients',
    'bccRecipients',
    'internetMessageId',
    'bodyPreview',
    'internetMessageHeaders',
    'parentFolderId',
    'categories'
].join(',');

const EXPAND = 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)';

function captureLogger() {
    const logs = [];
    const logger = {};
    for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = entry => logs.push([level, entry]);
    }
    logger.child = () => logger;
    return { logger, logs };
}

function makeClient() {
    const outlook = new OutlookClient('test-account', { redis });
    const { logger, logs } = captureLogger();
    outlook.logger = logger;
    outlook.oauth2UserPath = 'me';
    outlook.prepare = async () => {};
    return { outlook, logs };
}

function graphError(status, body, message) {
    return Object.assign(new Error(message || 'OAuth2 request failed'), { statusCode: status, oauthRequest: { status, response: body } });
}

test('OutlookClient.getMessage()', async t => {
    await t.test('asks for every field it formats and the attachment list, with the body format asked for', async () => {
        const { outlook } = makeClient();
        const requests = [];
        outlook.request = async (...args) => {
            requests.push(args);
            return { id: 'm1' };
        };
        await outlook.getMessage('m1', {});
        await outlook.getMessage('m1', { textType: 'plain' });
        await outlook.getMessage('m1', { textType: 'html' });
        await outlook.getMessage('m1', { textType: '*' });

        const query = { $select: SELECT_FULL, $expand: EXPAND };
        assert.deepStrictEqual(requests, [
            ['/me/messages/m1', 'get', query, {}],
            ['/me/messages/m1', 'get', query, { headers: { Prefer: 'outlook.body-content-type="text"' } }],
            ['/me/messages/m1', 'get', query, { headers: { Prefer: 'outlook.body-content-type="html"' } }],
            ['/me/messages/m1', 'get', query, {}]
        ]);
    });

    await t.test('a 404 is an unknown message', async () => {
        const { outlook, logs } = makeClient();
        outlook.request = async () => {
            throw graphError(404, { error: { code: 'ErrorItemNotFound', message: 'Not found' } });
        };
        const err = await outlook.getMessage('m1', {}).catch(err => err);
        assert.deepStrictEqual(Object.keys(err), ['info', 'code', 'statusCode']);
        assert.strictEqual(err.message, 'Unknown message');
        assert.deepStrictEqual(err.info, { response: 'Message does not exist' });
        assert.strictEqual(err.code, 'NotFound');
        assert.strictEqual(err.statusCode, 404);
        assert.deepStrictEqual(logs, []);
    });

    await t.test('a 400 carries what Graph said', async () => {
        const { outlook } = makeClient();
        outlook.request = async () => {
            throw graphError(400, { error: { code: 'ErrorInvalidIdMalformed', message: 'Id is malformed.' } });
        };
        const err = await outlook.getMessage('m1', {}).catch(err => err);
        assert.deepStrictEqual(Object.keys(err), ['info', 'code', 'statusCode']);
        assert.strictEqual(err.message, 'Invalid request');
        assert.deepStrictEqual(err.info, { response: 'Id is malformed.' });
        assert.strictEqual(err.code, 'ErrorInvalidIdMalformed');
        assert.strictEqual(err.statusCode, 400);
    });

    await t.test('a 400 without a body has generic values', async () => {
        const { outlook } = makeClient();
        outlook.request = async () => {
            throw graphError(400, undefined);
        };
        const err = await outlook.getMessage('m1', {}).catch(err => err);
        assert.deepStrictEqual(err.info, { response: 'Invalid request' });
        assert.strictEqual(err.code, 'InvalidRequest');
        assert.strictEqual(err.statusCode, 400);
    });

    await t.test('any other failure is logged and thrown as is', async () => {
        const { outlook, logs } = makeClient();
        const failure = graphError(503, {});
        outlook.request = async () => {
            throw failure;
        };
        const err = await outlook.getMessage('m1', {}).catch(err => err);
        assert.strictEqual(err, failure);
        assert.deepStrictEqual(logs, [['error', { msg: 'Failed to fetch message data', emailId: 'm1', err: failure }]]);
    });

    await t.test('collects the headers, the In-Reply-To, the folder and its special use', async () => {
        const { outlook } = makeClient();
        outlook.request = async () => ({
            id: 'm1',
            parentFolderId: 'f1',
            internetMessageHeaders: [
                { name: ' Received ', value: ' first ' },
                { name: 'received', value: 'second' },
                { name: 'In-Reply-To', value: ' <parent@example.com> ' },
                { name: '', value: 'nameless' },
                { name: 'X-Empty' }
            ]
        });
        outlook.resolveFolder = async (id, opts) => {
            assert.deepStrictEqual([id, opts], ['f1', { byId: true }]);
            return { pathName: 'Inbox/Sub', specialUse: '\\Archive' };
        };
        let formatted;
        outlook.formatMessage = (messageData, options) => {
            formatted = { messageData, options };
            return { id: messageData.id };
        };
        const message = await outlook.getMessage('m1', { textType: 'html', maxBytes: 100, showPath: true, markAsSeen: false });
        assert.deepStrictEqual(message, { id: 'm1', messageSpecialUse: '\\Archive' });
        assert.deepStrictEqual(formatted.options, { extended: true, path: 'Inbox/Sub', textType: 'html', maxBytes: 100, showPath: true });
        assert.strictEqual(formatted.messageData.inReplyTo, '<parent@example.com>');
        assert.deepStrictEqual(Object.assign({}, formatted.messageData.headers), {
            received: ['first', 'second'],
            'in-reply-to': ['<parent@example.com>'],
            '': ['nameless'],
            'x-empty': ['']
        });
    });

    await t.test('marks an unseen message as seen and reports the flags it ended with', async () => {
        const { outlook } = makeClient();
        const updates = [];
        outlook.request = async () => ({ id: 'm1', isRead: false });
        outlook.updateMessage = async (id, changes) => {
            updates.push([id, changes]);
            return { flags: { result: ['\\Seen', '\\Flagged'] } };
        };
        const message = await outlook.getMessage('m1', { markAsSeen: true });
        assert.deepStrictEqual(updates, [['m1', { flags: { add: ['\\Seen'] } }]]);
        assert.deepStrictEqual(message.flags, ['\\Seen', '\\Flagged']);
    });

    await t.test('keeps its flags when the update answers none', async () => {
        const { outlook } = makeClient();
        outlook.request = async () => ({ id: 'm1', isRead: false, flag: { flagStatus: 'flagged' } });
        outlook.updateMessage = async () => ({});
        const message = await outlook.getMessage('m1', { markAsSeen: true });
        assert.deepStrictEqual(message.flags, ['\\Flagged']);
    });

    await t.test('does not mark a seen message again', async () => {
        const { outlook } = makeClient();
        let updates = 0;
        outlook.request = async () => ({ id: 'm1', isRead: true });
        outlook.updateMessage = async () => updates++;
        await outlook.getMessage('m1', { markAsSeen: true });
        assert.strictEqual(updates, 0);
    });

    await t.test('a failure to mark as seen is logged and the message still returned', async () => {
        const { outlook, logs } = makeClient();
        const failure = new Error('nope');
        outlook.request = async () => ({ id: 'm1', isRead: false });
        outlook.updateMessage = async () => {
            throw failure;
        };
        const message = await outlook.getMessage('m1', { markAsSeen: true });
        assert.strictEqual(message.id, 'm1');
        assert.deepStrictEqual(logs, [['debug', { msg: 'Failed to mark message as Seen', message: 'm1', err: failure }]]);
    });

    await t.test('embeds the inline images the html refers to, each fetched once', async () => {
        const { outlook } = makeClient();
        const fetched = [];
        outlook.request = async () => ({
            id: 'm1',
            body: { contentType: 'html', content: '<p><img src="cid:logo@x"><img src="cid:logo@x"><img src="cid:gone@x"></p>' },
            attachments: [
                { id: 'A1', name: 'logo.png', contentType: 'image/png', isInline: true, contentId: '<logo@x>', size: 3 },
                { id: 'A2', name: 'logo-copy.png', contentType: 'image/png', isInline: true, contentId: 'logo@x', size: 3 },
                { id: 'A3', name: 'other.png', contentType: 'image/png', isInline: true, contentId: '<other@x>', size: 3 },
                { id: 'A4', name: 'gone.png', contentType: 'image/png', isInline: true, contentId: '<gone@x>', size: 3 }
            ]
        });
        outlook.getAttachmentContent = async (id, options) => {
            fetched.push([id, options]);
            // the second download (gone@x) finds nothing
            return fetched.length === 2 ? null : { contentType: 'image/png', content: 'QUJD' };
        };
        const message = await outlook.getMessage('m1', { embedAttachedImages: true, textType: 'html' });
        // logo@x once though two attachments carry it, gone@x tried, other@x not referenced
        const attachmentIds = message.attachments.map(attachment => attachment.id);
        assert.deepStrictEqual(fetched, [
            [attachmentIds[0], { returnBase64: true }],
            [attachmentIds[3], { returnBase64: true }]
        ]);
        assert.strictEqual(message.text.html, '<p><img src="data:image/png;base64,QUJD"><img src="data:image/png;base64,QUJD"><img src="cid:gone@x"></p>');
    });

    await t.test('does not embed images unless asked to', async () => {
        const { outlook } = makeClient();
        let fetched = 0;
        outlook.request = async () => ({
            id: 'm1',
            body: { contentType: 'html', content: '<img src="cid:logo@x">' },
            attachments: [{ id: 'A1', name: 'logo.png', contentType: 'image/png', isInline: true, contentId: '<logo@x>', size: 3 }]
        });
        outlook.getAttachmentContent = async () => fetched++;
        const message = await outlook.getMessage('m1', { textType: 'html' });
        assert.strictEqual(fetched, 0);
        assert.strictEqual(message.text.html, '<img src="cid:logo@x">');
    });
});

test('OutlookClient.getMessages()', async t => {
    let batchSize;
    const realGet = settings.get;
    t.before(() => {
        settings.get = async key => (key === 'outlookExportBatchSize' ? batchSize : realGet.call(settings, key));
    });
    t.after(() => {
        settings.get = realGet;
    });
    t.beforeEach(() => {
        batchSize = 20;
    });

    function makeBatchClient(answer) {
        const { outlook, logs } = makeClient();
        const posts = [];
        outlook.getCachedMailboxListing = async () => [{ id: 'f-inbox', pathName: 'INBOX', specialUse: '\\Inbox' }];
        outlook.resolveFolder = async () => null;
        outlook.request = async (url, method, payload) => {
            posts.push({ url, method, payload });
            return answer(payload.requests, posts.length);
        };
        outlook.formatMessage = (messageData, options) => {
            if (messageData.broken) {
                throw Object.assign(new Error('Cannot format'), { code: 'EFORMAT', statusCode: 500 });
            }
            return { id: messageData.id, path: options.path, inReplyTo: messageData.inReplyTo, options };
        };
        return { outlook, logs, posts };
    }

    const ok = requests => ({ responses: requests.map(req => ({ id: req.id, status: 200, body: { id: req.url.split('?')[0].split('/').pop() } })) });

    // The retry waits 5s, 10s and 20s plus up to a second of jitter; mocked timers run them at once
    async function withMockedTimers(t, fn) {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        t.mock.method(Math, 'random', () => 0.5);
        try {
            const promise = fn();
            let settled = false;
            promise.then(
                () => (settled = true),
                () => (settled = true)
            );
            while (!settled) {
                await new Promise(resolve => setImmediate(resolve));
                t.mock.timers.tick(30000);
            }
            return await promise;
        } finally {
            t.mock.timers.reset();
        }
    }

    await t.test('sends one batch request per batch with the full field list', async () => {
        batchSize = 2;
        const { outlook, posts } = makeBatchClient(ok);
        const results = await outlook.getMessages(['a', 'b', 'c'], { textType: 'plain', maxBytes: 10, showPath: true });

        assert.deepStrictEqual(
            posts.map(post => [post.url, post.method]),
            [
                ['/$batch', 'post'],
                ['/$batch', 'post']
            ]
        );
        assert.deepStrictEqual(posts[0].payload, {
            requests: [
                {
                    id: 'msg_1',
                    method: 'GET',
                    url: `/me/messages/a?$select=${SELECT_FULL}&$expand=${EXPAND}`,
                    headers: { Prefer: 'outlook.body-content-type="text"' }
                },
                {
                    id: 'msg_2',
                    method: 'GET',
                    url: `/me/messages/b?$select=${SELECT_FULL}&$expand=${EXPAND}`,
                    headers: { Prefer: 'outlook.body-content-type="text"' }
                }
            ]
        });
        // request ids keep counting across batches
        assert.deepStrictEqual(
            posts[1].payload.requests.map(req => req.id),
            ['msg_3']
        );
        assert.deepStrictEqual(results, [
            {
                messageId: 'a',
                data: {
                    id: 'a',
                    path: undefined,
                    inReplyTo: undefined,
                    options: { extended: true, path: undefined, textType: 'plain', maxBytes: 10, showPath: true }
                },
                error: null
            },
            {
                messageId: 'b',
                data: {
                    id: 'b',
                    path: undefined,
                    inReplyTo: undefined,
                    options: { extended: true, path: undefined, textType: 'plain', maxBytes: 10, showPath: true }
                },
                error: null
            },
            {
                messageId: 'c',
                data: {
                    id: 'c',
                    path: undefined,
                    inReplyTo: undefined,
                    options: { extended: true, path: undefined, textType: 'plain', maxBytes: 10, showPath: true }
                },
                error: null
            }
        ]);
    });

    await t.test('asks for html, or for the default body format without a Prefer header', async () => {
        const { outlook, posts } = makeBatchClient(ok);
        await outlook.getMessages(['a'], { textType: 'html' });
        await outlook.getMessages(['a'], {});
        assert.deepStrictEqual(posts[0].payload.requests[0].headers, { Prefer: 'outlook.body-content-type="html"' });
        assert.strictEqual('headers' in posts[1].payload.requests[0], false);
    });

    await t.test('the batch size setting is capped at the Graph limit', async () => {
        batchSize = 50;
        const { outlook, posts } = makeBatchClient(ok);
        const ids = Array.from({ length: 25 }, (v, i) => `m${i}`);
        await outlook.getMessages(ids, {});
        assert.deepStrictEqual(
            posts.map(post => post.payload.requests.length),
            [20, 5]
        );
    });

    await t.test('parses headers, folder and special use of each message', async () => {
        const { outlook } = makeBatchClient(requests => ({
            responses: [
                {
                    id: requests[0].id,
                    status: 200,
                    body: {
                        id: 'a',
                        parentFolderId: 'f-inbox',
                        internetMessageHeaders: [
                            { name: 'In-Reply-To', value: ' <p@example.com> ' },
                            { name: 'X-A', value: '1' }
                        ]
                    }
                }
            ]
        }));
        let seen;
        const format = outlook.formatMessage;
        outlook.formatMessage = (messageData, options) => {
            seen = messageData;
            return format(messageData, options);
        };
        const results = await outlook.getMessages(['a'], {});
        assert.strictEqual(results[0].data.path, 'INBOX');
        assert.strictEqual(results[0].data.messageSpecialUse, '\\Inbox');
        assert.strictEqual(results[0].data.inReplyTo, '<p@example.com>');
        assert.deepStrictEqual(Object.assign({}, seen.headers), { 'in-reply-to': ['<p@example.com>'], 'x-a': ['1'] });
    });

    await t.test('reports the errors of single messages, and the ones the batch left out', async () => {
        const { outlook } = makeBatchClient(requests => ({
            responses: [
                { id: 'unknown', status: 200, body: { id: 'x' } },
                { id: requests[4].id, status: 200, body: { id: 'e' } },
                { id: requests[0].id, status: 404, body: { error: { code: 'ErrorItemNotFound', message: 'The item was not found' } } },
                { id: requests[1].id, status: 503 },
                { id: requests[2].id, status: 200 },
                { id: requests[3].id, status: 200, body: { id: 'd', broken: true } }
            ]
        }));
        const results = await outlook.getMessages(['a', 'b', 'c', 'd', 'e', 'f', 'g'], {});
        assert.deepStrictEqual(
            results.map(entry => Object.assign({}, entry, { data: entry.data && entry.data.id })),
            [
                { messageId: 'e', data: 'e', error: null },
                { messageId: 'a', data: null, error: { message: 'The item was not found', code: 'ErrorItemNotFound', statusCode: 404 } },
                { messageId: 'b', data: null, error: { message: 'Request failed', code: undefined, statusCode: 503 } },
                { messageId: 'c', data: null, error: { message: 'Request failed', code: undefined, statusCode: 200 } },
                { messageId: 'd', data: null, error: { message: 'Cannot format', code: 'EFORMAT' } },
                { messageId: 'f', data: null, error: { message: 'No response received from batch API', code: 'EMISSING_RESPONSE' } },
                { messageId: 'g', data: null, error: { message: 'No response received from batch API', code: 'EMISSING_RESPONSE' } }
            ]
        );
    });

    await t.test('an answer without responses reports every message as missing', async () => {
        const { outlook } = makeBatchClient(() => ({}));
        const results = await outlook.getMessages(['a', 'b'], {});
        assert.deepStrictEqual(
            results.map(entry => [entry.messageId, entry.error.code]),
            [
                ['a', 'EMISSING_RESPONSE'],
                ['b', 'EMISSING_RESPONSE']
            ]
        );
    });

    await t.test('retries a throttled or failing batch with a growing delay', async t => {
        const { outlook, logs, posts } = makeBatchClient((requests, attempt) => {
            if (attempt === 1) {
                throw graphError(429, {});
            }
            if (attempt === 2) {
                throw graphError(502, {});
            }
            return ok(requests);
        });
        const results = await withMockedTimers(t, () => outlook.getMessages(['a', 'b'], {}));
        assert.strictEqual(posts.length, 3);
        assert.deepStrictEqual(
            results.map(entry => entry.data.id),
            ['a', 'b']
        );
        assert.deepStrictEqual(logs, [
            ['warn', { msg: 'Batch request failed, retrying', account: 'test-account', attempt: 1, maxAttempts: 4, statusCode: 429, delayMs: 5500 }],
            ['warn', { msg: 'Batch request failed, retrying', account: 'test-account', attempt: 2, maxAttempts: 4, statusCode: 502, delayMs: 10500 }]
        ]);
    });

    await t.test('gives up after the retries and fails the batch, then goes on with the next one', async t => {
        batchSize = 2;
        const { outlook, logs, posts } = makeBatchClient((requests, attempt) => {
            if (attempt <= 4) {
                throw Object.assign(graphError(503, {}, 'Service unavailable'), { code: 'EUNAVAILABLE' });
            }
            return ok(requests);
        });
        const results = await withMockedTimers(t, () => outlook.getMessages(['a', 'b', 'c'], {}));
        assert.strictEqual(posts.length, 5);
        assert.deepStrictEqual(
            logs.map(entry => entry[1].delayMs),
            [5500, 10500, 20500]
        );
        assert.deepStrictEqual(results, [
            { messageId: 'a', data: null, error: { message: 'Service unavailable', code: 'EUNAVAILABLE', statusCode: 503 } },
            { messageId: 'b', data: null, error: { message: 'Service unavailable', code: 'EUNAVAILABLE', statusCode: 503 } },
            {
                messageId: 'c',
                data: {
                    id: 'c',
                    path: undefined,
                    inReplyTo: undefined,
                    options: { extended: true, path: undefined, textType: undefined, maxBytes: undefined, showPath: undefined }
                },
                error: null
            }
        ]);
    });

    await t.test('does not retry any other failure', async () => {
        const { outlook, logs, posts } = makeBatchClient(() => {
            throw graphError(400, {}, 'Bad batch');
        });
        const results = await outlook.getMessages(['a'], {});
        assert.strictEqual(posts.length, 1);
        assert.deepStrictEqual(logs, []);
        assert.deepStrictEqual(results, [{ messageId: 'a', data: null, error: { message: 'Bad batch', code: undefined, statusCode: 400 } }]);
    });

    await t.test('a failure without a response status is not retried either', async () => {
        const { outlook, posts } = makeBatchClient(() => {
            throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
        });
        const results = await outlook.getMessages(['a'], {});
        assert.strictEqual(posts.length, 1);
        assert.deepStrictEqual(results, [{ messageId: 'a', data: null, error: { message: 'socket hang up', code: 'ECONNRESET', statusCode: undefined } }]);
    });
});
