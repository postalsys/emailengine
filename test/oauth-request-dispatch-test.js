'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');

// Body-capturing server shared with test/outlook-client-sendmail-test.js
const { stopServer, withCapturingServer } = require('./helpers/capture-http-server');
// The real endpoint/encoding selection GmailClient.submitMessage() calls
const { buildSendRequest, JSON_SEND_LIMIT } = require('../lib/email-client/gmail/send-request');

async function startTestServer(behavior) {
    const requestCounts = {};

    const server = http.createServer((req, res) => {
        const path = req.url.split('?')[0];
        requestCounts[path] = (requestCounts[path] || 0) + 1;
        const count = requestCounts[path];

        req.on('data', () => {});
        req.on('end', () => {
            if (behavior === 'always-429') {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '0' });
                res.end(JSON.stringify({ error: 'rate_limited' }));
            } else if (behavior === '429-then-200' && count === 1) {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '0' });
                res.end(JSON.stringify({ error: 'rate_limited' }));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ok: true, attempt: count }));
            }
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        requestCounts
    };
}

test('Buffer payload dispatcher and Gmail endpoint selection', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    const { GmailOauth } = require('../lib/oauth/gmail');
    const { OutlookOauth } = require('../lib/oauth/outlook');
    const { MailRuOauth } = require('../lib/oauth/mail-ru');

    const baseOpts = { clientId: 'test-id', clientSecret: 'test-secret', redirectUrl: 'http://localhost/callback', setFlag: async () => {} };

    function createGmail() {
        return new GmailOauth(baseOpts);
    }

    function createOutlook() {
        return new OutlookOauth({ ...baseOpts, authority: 'common' });
    }

    function createMailRu() {
        return new MailRuOauth(baseOpts);
    }

    // The OAuth2 clients send a provider API request exactly once, whatever the payload shape:
    // which failures are worth repeating is decided by the request layer above them
    // (lib/email-client/api-retry.js), which knows the method and the provider's answers. The
    // transport used to retry on its own as well, and one throttled call became up to 24 requests
    for (const [label, createClient, method, payload] of [
        ['Gmail: an empty Buffer payload', createGmail, 'post', Buffer.alloc(0)],
        ['Gmail: a non-empty Buffer payload', createGmail, 'post', Buffer.from('binary-data')],
        ['Gmail: a JSON object payload', createGmail, 'post', { key: 'value' }],
        ['Gmail: a GET', createGmail, 'get', null],
        ['Outlook: an empty Buffer payload', createOutlook, 'delete', Buffer.alloc(0)],
        ['Outlook: a non-empty Buffer payload', createOutlook, 'post', Buffer.from('data')],
        ['Outlook: a JSON object payload', createOutlook, 'post', { key: 'value' }],
        ['Outlook: a GET', createOutlook, 'get', null]
    ]) {
        await t.test(`${label} is sent once and a 429 surfaces with its Retry-After`, async () => {
            const { server, baseUrl, requestCounts } = await startTestServer('always-429');
            try {
                await assert.rejects(
                    () => createClient().request('fake-token', `${baseUrl}/once`, method, payload),
                    err => {
                        assert.strictEqual(err.statusCode, 429);
                        assert.strictEqual(err.oauthRequest.status, 429);
                        assert.strictEqual(err.retryAfter, 0, 'the Retry-After header is parsed for the retry layer');
                        assert.strictEqual(err.oauthRequest.retryAfter, 0);
                        return true;
                    }
                );
                assert.strictEqual(requestCounts['/once'], 1);
            } finally {
                await stopServer(server);
            }
        });
    }

    // Mail.ru keeps the transport-level retry (its API is only asked for the user profile)
    await t.test('Mail.ru: empty Buffer payload retries on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const result = await createMailRu().request('fake-token', `${baseUrl}/mailru-empty-buf`, 'post', Buffer.alloc(0));
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.ok(requestCounts['/mailru-empty-buf'] >= 2, 'Empty buffer POST should be retried on 429');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Mail.ru: non-empty Buffer payload does not retry on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            await assert.rejects(
                () => createMailRu().request('fake-token', `${baseUrl}/mailru-nonempty-buf`, 'post', Buffer.from('data')),
                err => {
                    assert.strictEqual(err.oauthRequest.status, 429);
                    return true;
                }
            );
            assert.strictEqual(requestCounts['/mailru-nonempty-buf'], 1, 'Non-empty buffer should not retry');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Outlook: the send requests are marked noRetry', async () => {
        const { buildStructuredSendMailRequest, buildDraftSendRequest, buildRawSendMailRequest } = require('../lib/email-client/outlook/send-request');
        assert.strictEqual(buildStructuredSendMailRequest({ subject: 'x' }, 'me').options.noRetry, true);
        assert.strictEqual(buildDraftSendRequest('msg-1', 'me').options.noRetry, true);
        assert.strictEqual(buildRawSendMailRequest(Buffer.from('raw'), 'me').options.noRetry, true);
    });

    // The retry layer, driven through the real OAuth2 clients against the local server: a
    // throttled read is repeated after the Retry-After the server sent, a send is not
    const gmailApi = require('../lib/email-client/gmail/gmail-api');
    const graphApi = require('../lib/email-client/outlook/graph-api');
    const { noopLogger } = require('./helpers/auth-failure');

    function apiContext(oAuth2Client) {
        return {
            account: 'test-account',
            logger: noopLogger,
            getTokenData: async () => ({ accessToken: 'fake-token', cached: false }),
            invalidateAccessToken: async () => {},
            oAuth2Client
        };
    }

    await t.test('Gmail: the request layer repeats a throttled read once the server allows it', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const result = await gmailApi.request(apiContext(createGmail()), `${baseUrl}/gmail-throttled-get`, 'get');
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.strictEqual(requestCounts['/gmail-throttled-get'], 2);
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Gmail: a noRetry send is sent exactly once', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            await assert.rejects(
                () => gmailApi.request(apiContext(createGmail()), `${baseUrl}/gmail-send`, 'post', { raw: 'abc' }, { noRetry: true }),
                err => err.oauthRequest.status === 429
            );
            assert.strictEqual(requestCounts['/gmail-send'], 1);
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Outlook: the request layer repeats a throttled read once the server allows it', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const outlook = createOutlook();
            outlook.apiBase = baseUrl;
            const result = await graphApi.requestWithRetry(apiContext(outlook), '/outlook-throttled-get', 'get');
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.strictEqual(requestCounts['/v1.0/outlook-throttled-get'], 2);
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Outlook: a noRetry send is sent exactly once', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            const { buildStructuredSendMailRequest } = require('../lib/email-client/outlook/send-request');
            const outlook = createOutlook();
            outlook.apiBase = baseUrl;
            const structured = buildStructuredSendMailRequest({ subject: 'x' }, 'me');
            await assert.rejects(
                () => graphApi.requestWithRetry(apiContext(outlook), structured.path, 'post', structured.body, structured.options),
                err => err.oauthRequest.status === 429
            );
            assert.strictEqual(requestCounts['/v1.0/me/sendMail'], 1);
        } finally {
            await stopServer(server);
        }
    });

    // $value endpoints return raw MIME; a text round-trip replaced every non-UTF-8 byte with U+FFFD
    await t.test('Outlook: returnBuffer keeps 8-bit bytes intact', async () => {
        const body = Buffer.from([0x53, 0x75, 0x62, 0x6a, 0x3a, 0x20, 0xe4, 0xf6, 0xfc, 0xff, 0x80]);
        const binServer = http.createServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            res.end(body);
        });
        await new Promise(resolve => binServer.listen(0, '127.0.0.1', resolve));
        try {
            const result = await createOutlook().request('fake-token', `http://127.0.0.1:${binServer.address().port}/$value`, 'get', Buffer.alloc(0), {
                returnBuffer: true
            });
            assert.ok(Buffer.isBuffer(result));
            assert.ok(result.equals(body));
        } finally {
            await stopServer(binServer);
        }
    });

    // Gmail send endpoint selection - drives lib/email-client/gmail/send-request.js, the module
    // GmailClient.submitMessage() actually calls. These cases used to run against a copy of the
    // branch declared in this file (including its own JSON_SEND_LIMIT), so moving the threshold,
    // renaming an endpoint or dropping the base64url encoding left every assertion green while
    // outbound mail broke.
    const jsonMessage = size => Buffer.alloc(size, 'a');

    await t.test('Gmail endpoint: small message uses the JSON endpoint with base64url', async () => {
        const raw = Buffer.from('From: a@b.com\r\nSubject: Small\r\n\r\nBody');
        const { targetEndpoint, contentType, payload } = buildSendRequest(raw);

        assert.strictEqual(targetEndpoint, '/gmail/v1/users/me/messages/send');
        assert.strictEqual(contentType, 'application/json');
        assert.strictEqual(payload.threadId, undefined);
        assert.deepStrictEqual(Buffer.from(payload.raw, 'base64url'), raw, 'the message must round trip through base64url');
    });

    await t.test('Gmail endpoint: small threaded reply keeps the threadId in the JSON body', async () => {
        const raw = Buffer.from('From: a@b.com\r\nSubject: Reply\r\n\r\nBody');
        const { targetEndpoint, contentType, payload } = buildSendRequest(raw, 'thread-123');

        assert.strictEqual(targetEndpoint, '/gmail/v1/users/me/messages/send');
        assert.strictEqual(contentType, 'application/json');
        assert.strictEqual(payload.threadId, 'thread-123', 'a dropped threadId detaches the reply from its conversation');
    });

    await t.test('Gmail endpoint: a large non-threaded message uses the simple upload', async () => {
        const raw = jsonMessage(JSON_SEND_LIMIT + 1);
        const { targetEndpoint, contentType, payload } = buildSendRequest(raw);

        assert.strictEqual(targetEndpoint, '/upload/gmail/v1/users/me/messages/send');
        assert.strictEqual(contentType, 'message/rfc822');
        assert.strictEqual(payload, raw, 'the upload endpoint takes the raw RFC822 buffer unencoded');
    });

    await t.test('Gmail endpoint: the JSON limit is inclusive, one byte over switches to upload', async () => {
        // The boundary is the whole point of the branch: base64url inflates the body by ~4/3, so
        // a message above the limit would be rejected by the 5MB JSON endpoint.
        assert.strictEqual(buildSendRequest(jsonMessage(JSON_SEND_LIMIT)).targetEndpoint, '/gmail/v1/users/me/messages/send');
        assert.strictEqual(buildSendRequest(jsonMessage(JSON_SEND_LIMIT + 1)).targetEndpoint, '/upload/gmail/v1/users/me/messages/send');
    });

    await t.test('Gmail endpoint: a large threaded reply is uploaded as multipart/related', async () => {
        const raw = Buffer.concat([Buffer.from('From: a@b.com\r\nSubject: Big reply\r\n\r\n'), jsonMessage(JSON_SEND_LIMIT + 1)]);
        const { targetEndpoint, contentType, payload } = buildSendRequest(raw, 'thread-abc123');

        assert.strictEqual(targetEndpoint, '/upload/gmail/v1/users/me/messages/send?uploadType=multipart');

        const boundary = /boundary=(\S+)/.exec(contentType)[1];
        assert.ok(boundary, `content type must carry the boundary, got ${contentType}`);
        assert.ok(contentType.startsWith('multipart/related;'));

        const body = payload.toString('binary');
        assert.ok(body.startsWith(`--${boundary}\r\n`), 'the body must open with the declared boundary');
        assert.ok(body.includes('Content-Type: application/json'), 'the metadata part carries the threadId');
        assert.ok(body.includes('"threadId":"thread-abc123"'));
        assert.ok(body.includes('Content-Type: message/rfc822'), 'the second part is the message itself');
        assert.ok(body.includes('Subject: Big reply'));
        assert.ok(body.endsWith(`\r\n--${boundary}--`), 'the body must close the boundary');
        assert.ok(!raw.toString('binary').includes(boundary), 'a random boundary must not collide with the message content');
    });

    await t.test('Gmail endpoint: each multipart send gets its own boundary', async () => {
        const raw = jsonMessage(JSON_SEND_LIMIT + 1);
        const first = buildSendRequest(raw, 'thread-1').contentType;
        const second = buildSendRequest(raw, 'thread-1').contentType;

        assert.notStrictEqual(first, second, 'a fixed boundary would collide with message content sooner or later');
    });

    await t.test('Gmail endpoint: the encodings stay inside the provider limits', async () => {
        // base64url expands by ~4/3, so the JSON threshold has to leave room under Gmail's 5MB
        // JSON body limit, and the multipart overhead has to leave room under the 35MB upload
        // limit. Both are computed from the real payloads rather than from a re-declared constant.
        const jsonBody = JSON.stringify(buildSendRequest(jsonMessage(JSON_SEND_LIMIT), 'some-thread-id-value').payload);
        assert.ok(jsonBody.length < 5 * 1024 * 1024, `a maximum JSON send body is ${jsonBody.length} bytes, over Gmail's 5MB limit`);

        const nearLimit = 34 * 1024 * 1024;
        const multipart = buildSendRequest(jsonMessage(nearLimit), 'thread-id').payload;
        assert.ok(multipart.length < 35 * 1024 * 1024, `multipart overhead pushes a ${nearLimit} byte message to ${multipart.length}, over the 35MB limit`);
    });

    // Outlook sendMail: Buffer payload with text/plain must not be JSON-quoted
    await t.test('Outlook: Buffer payload with text/plain contentType is sent without JSON quoting', async () => {
        const respondWithJson = res => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
        };

        await withCapturingServer(respondWithJson, async ({ baseUrl, getCaptured }) => {
            const outlook = createOutlook();
            const base64Content = Buffer.from('From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nHello').toString('base64');
            const payload = Buffer.from(base64Content);

            await outlook.request('fake-token', `${baseUrl}/me/sendMail`, 'post', payload, {
                contentType: 'text/plain',
                returnText: true
            });

            const receivedBody = getCaptured().body.toString();

            // The body must be the raw base64 string, not wrapped in JSON quotes
            assert.strictEqual(receivedBody, base64Content, 'Body should be raw base64, not JSON-stringified');
            assert.ok(!receivedBody.startsWith('"'), 'Body must not start with a JSON quote');
            assert.ok(!receivedBody.endsWith('"'), 'Body must not end with a JSON quote');
        });
    });
});
