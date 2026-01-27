'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');

/**
 * Creates and starts a test HTTP server.
 *
 * @param {'always-429'|'429-then-200'|'always-200'} behavior
 *   - 'always-429': every request returns 429
 *   - '429-then-200': first request per path returns 429, subsequent return 200
 *   - 'always-200': every request returns 200
 * @returns {Promise<{server: http.Server, baseUrl: string, requestCounts: Object}>}
 */
async function startTestServer(behavior) {
    const requestCounts = {};

    const server = http.createServer((req, res) => {
        // Strip query params for path-based counting (Mail.ru appends access_token)
        const path = req.url.split('?')[0];
        requestCounts[path] = (requestCounts[path] || 0) + 1;
        const count = requestCounts[path];

        // Consume request body
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

async function stopServer(server) {
    await new Promise(resolve => server.close(resolve));
}

/**
 * Creates and starts a test HTTP server that captures the raw request body.
 *
 * @returns {Promise<{server: http.Server, baseUrl: string, getBody: () => Buffer}>}
 */
async function startBodyCapturingServer() {
    let capturedBody = null;

    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            capturedBody = Buffer.concat(chunks);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        getBody: () => capturedBody
    };
}

test('Buffer payload dispatcher and Gmail endpoint selection', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    const { GmailOauth } = require('../lib/oauth/gmail');
    const { OutlookOauth } = require('../lib/oauth/outlook');
    const { MailRuOauth } = require('../lib/oauth/mail-ru');

    // ---------------------------------------------------------------
    // Fix 1: Empty Buffer payloads should use retryAgent (retry on 429),
    //         non-empty Buffer payloads should use fetchAgent (no retry).
    //
    // Tested by calling the real request() method against a local HTTP
    // server that returns 429 on the first request. If the dispatcher is
    // retryAgent, undici retries and the request succeeds. If fetchAgent,
    // no retry occurs and the request throws.
    // ---------------------------------------------------------------

    await t.test('Gmail: empty Buffer payload retries on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const gmail = new GmailOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            const result = await gmail.request('fake-token', `${baseUrl}/gmail-empty-buf`, 'post', Buffer.alloc(0));
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.ok(requestCounts['/gmail-empty-buf'] >= 2, 'Empty buffer POST should be retried on 429');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Gmail: non-empty Buffer payload does not retry on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            const gmail = new GmailOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            await assert.rejects(
                () => gmail.request('fake-token', `${baseUrl}/gmail-nonempty-buf`, 'post', Buffer.from('binary-data')),
                err => {
                    assert.strictEqual(err.oauthRequest.status, 429);
                    return true;
                }
            );
            assert.strictEqual(requestCounts['/gmail-nonempty-buf'], 1, 'Non-empty buffer should not retry');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Gmail: JSON object payload retries on 429 (baseline)', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const gmail = new GmailOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            const result = await gmail.request('fake-token', `${baseUrl}/gmail-json`, 'post', { key: 'value' });
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.ok(requestCounts['/gmail-json'] >= 2, 'JSON payload should be retried on 429');
        } finally {
            await stopServer(server);
        }
    });

    // Outlook: empty Buffer retry is critical because deleteMessage(force)
    // and deleteMailbox() use Buffer.alloc(0) via plain request() with
    // no app-level retry wrapper.

    await t.test('Outlook: empty Buffer payload retries on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const outlook = new OutlookOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                authority: 'common',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            const result = await outlook.request('fake-token', `${baseUrl}/outlook-empty-buf`, 'delete', Buffer.alloc(0));
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.ok(requestCounts['/outlook-empty-buf'] >= 2, 'Empty buffer DELETE should be retried on 429');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Outlook: non-empty Buffer payload does not retry on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            const outlook = new OutlookOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                authority: 'common',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            await assert.rejects(
                () => outlook.request('fake-token', `${baseUrl}/outlook-nonempty-buf`, 'post', Buffer.from('data')),
                err => {
                    assert.strictEqual(err.oauthRequest.status, 429);
                    return true;
                }
            );
            assert.strictEqual(requestCounts['/outlook-nonempty-buf'], 1, 'Non-empty buffer should not retry');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Mail.ru: empty Buffer payload retries on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('429-then-200');
        try {
            const mailru = new MailRuOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            const result = await mailru.request('fake-token', `${baseUrl}/mailru-empty-buf`, 'post', Buffer.alloc(0));
            assert.deepStrictEqual(result, { ok: true, attempt: 2 });
            assert.ok(requestCounts['/mailru-empty-buf'] >= 2, 'Empty buffer POST should be retried on 429');
        } finally {
            await stopServer(server);
        }
    });

    await t.test('Mail.ru: non-empty Buffer payload does not retry on 429', async () => {
        const { server, baseUrl, requestCounts } = await startTestServer('always-429');
        try {
            const mailru = new MailRuOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            await assert.rejects(
                () => mailru.request('fake-token', `${baseUrl}/mailru-nonempty-buf`, 'post', Buffer.from('data')),
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

    // ---------------------------------------------------------------
    // Fix 2: Gmail send endpoint selection.
    //
    // gmail-client.js submitMessage() selects between the JSON endpoint
    // (5MB body limit) and the upload endpoint (35MB limit) based on
    // raw message size. The fix ensures large threaded replies use the
    // upload endpoint instead of being forced through JSON.
    //
    // This mirrors the endpoint selection logic from gmail-client.js
    // (same pattern as retry-logic-test.js mirrors retry logic).
    // ---------------------------------------------------------------

    /**
     * Mirrors the endpoint selection logic in gmail-client.js submitMessage().
     * @param {number} rawLength - Size of the raw RFC822 message in bytes
     * @param {string|null} threadId - Thread ID for threaded replies, or null
     * @returns {{contentType: string, targetEndpoint: string, hasThreadId: boolean, isMultipart: boolean}}
     */
    function selectGmailSendEndpoint(rawLength, threadId) {
        const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;

        if (rawLength <= JSON_SEND_LIMIT) {
            let payload = { raw: '<base64url>' };
            if (threadId) {
                payload.threadId = threadId;
            }
            return {
                contentType: 'application/json',
                targetEndpoint: '/gmail/v1/users/me/messages/send',
                hasThreadId: !!payload.threadId,
                isMultipart: false
            };
        } else if (threadId) {
            return {
                contentType: 'multipart/related',
                targetEndpoint: '/upload/gmail/v1/users/me/messages/send?uploadType=multipart',
                hasThreadId: true,
                isMultipart: true
            };
        } else {
            return {
                contentType: 'message/rfc822',
                targetEndpoint: '/upload/gmail/v1/users/me/messages/send',
                hasThreadId: false,
                isMultipart: false
            };
        }
    }

    await t.test('Gmail endpoint: small message uses JSON endpoint', async () => {
        const result = selectGmailSendEndpoint(1024, null);
        assert.strictEqual(result.targetEndpoint, '/gmail/v1/users/me/messages/send');
        assert.strictEqual(result.contentType, 'application/json');
        assert.strictEqual(result.hasThreadId, false);
    });

    await t.test('Gmail endpoint: large message uses upload endpoint', async () => {
        const result = selectGmailSendEndpoint(4 * 1024 * 1024, null);
        assert.strictEqual(result.targetEndpoint, '/upload/gmail/v1/users/me/messages/send');
        assert.strictEqual(result.contentType, 'message/rfc822');
    });

    await t.test('Gmail endpoint: small threaded reply uses JSON endpoint with threadId', async () => {
        const result = selectGmailSendEndpoint(1024, 'thread-123');
        assert.strictEqual(result.targetEndpoint, '/gmail/v1/users/me/messages/send');
        assert.strictEqual(result.contentType, 'application/json');
        assert.strictEqual(result.hasThreadId, true);
    });

    await t.test('Gmail endpoint: large threaded reply uses multipart upload with threadId', async () => {
        // Large threaded replies use multipart/related upload to preserve explicit
        // threadId via JSON metadata alongside the raw RFC822 message body.
        const result = selectGmailSendEndpoint(4 * 1024 * 1024, 'thread-456');
        assert.strictEqual(result.targetEndpoint, '/upload/gmail/v1/users/me/messages/send?uploadType=multipart');
        assert.strictEqual(result.contentType, 'multipart/related');
        assert.strictEqual(result.hasThreadId, true);
        assert.strictEqual(result.isMultipart, true);
    });

    await t.test('Gmail endpoint: message exactly at JSON_SEND_LIMIT uses JSON endpoint', async () => {
        const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;
        const result = selectGmailSendEndpoint(JSON_SEND_LIMIT, null);
        assert.strictEqual(result.targetEndpoint, '/gmail/v1/users/me/messages/send');
    });

    await t.test('Gmail endpoint: message one byte over JSON_SEND_LIMIT uses upload endpoint', async () => {
        const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;
        const result = selectGmailSendEndpoint(JSON_SEND_LIMIT + 1, null);
        assert.strictEqual(result.targetEndpoint, '/upload/gmail/v1/users/me/messages/send');
    });

    await t.test('Gmail endpoint: large non-threaded message uses simple upload', async () => {
        const result = selectGmailSendEndpoint(4 * 1024 * 1024, null);
        assert.strictEqual(result.targetEndpoint, '/upload/gmail/v1/users/me/messages/send');
        assert.strictEqual(result.contentType, 'message/rfc822');
        assert.strictEqual(result.hasThreadId, false);
        assert.strictEqual(result.isMultipart, false);
    });

    await t.test('Gmail multipart upload body contains valid structure', async () => {
        const crypto = require('node:crypto');
        const threadId = 'thread-abc123';
        const rawMessage = Buffer.from('From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody');

        const boundary = `ee_${crypto.randomBytes(16).toString('hex')}`;
        const metadata = JSON.stringify({ threadId });
        const preamble = Buffer.from(
            `--${boundary}\r\n` +
                `Content-Type: application/json; charset=UTF-8\r\n` +
                `\r\n` +
                `${metadata}\r\n` +
                `--${boundary}\r\n` +
                `Content-Type: message/rfc822\r\n` +
                `\r\n`
        );
        const epilogue = Buffer.from(`\r\n--${boundary}--`);
        const body = Buffer.concat([preamble, rawMessage, epilogue]);
        const bodyStr = body.toString();

        // Verify multipart structure
        assert.ok(bodyStr.startsWith(`--${boundary}\r\n`), 'Should start with boundary');
        assert.ok(bodyStr.includes('Content-Type: application/json'), 'Should contain JSON part');
        assert.ok(bodyStr.includes(`"threadId":"${threadId}"`), 'Should contain threadId in metadata');
        assert.ok(bodyStr.includes('Content-Type: message/rfc822'), 'Should contain RFC822 part');
        assert.ok(bodyStr.includes('From: a@b.com'), 'Should contain the raw message');
        assert.ok(bodyStr.endsWith(`\r\n--${boundary}--`), 'Should end with closing boundary');

        // Verify boundary does not appear in the raw message content
        assert.ok(!rawMessage.toString().includes(boundary), 'Boundary should not collide with message content');
    });

    await t.test('Gmail multipart body overhead stays well under 35MB upload limit', async () => {
        // A message just under 35MB should produce a multipart body that
        // still fits within the upload limit (overhead is ~200 bytes).
        const nearLimit = 34 * 1024 * 1024;
        const boundary = `ee_${'a'.repeat(32)}`;
        const metadata = JSON.stringify({ threadId: 'thread-id' });
        const preambleLen =
            `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: message/rfc822\r\n\r\n`.length;
        const epilogueLen = `\r\n--${boundary}--`.length;
        const totalOverhead = preambleLen + epilogueLen;

        assert.ok(nearLimit + totalOverhead < 35 * 1024 * 1024, `Multipart overhead (${totalOverhead} bytes) should not push payload over 35MB`);
    });

    await t.test('Gmail endpoint: base64url overhead keeps JSON payload under 5MB limit', async () => {
        // Verify the JSON_SEND_LIMIT (3.5MB) provides adequate safety margin.
        // base64url expands data by ~4/3, so 3.5MB raw -> ~4.67MB encoded,
        // plus JSON wrapper overhead, well under Gmail's 5MB JSON body limit.
        const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;
        const base64urlSize = Math.ceil((JSON_SEND_LIMIT * 4) / 3);
        const jsonOverhead = '{"raw":"","threadId":"some-thread-id-value"}'.length;
        const totalJsonBody = base64urlSize + jsonOverhead;
        const GMAIL_JSON_LIMIT = 5 * 1024 * 1024;

        assert.ok(totalJsonBody < GMAIL_JSON_LIMIT, `Max JSON body (${totalJsonBody} bytes) should be under Gmail 5MB limit (${GMAIL_JSON_LIMIT} bytes)`);
    });

    // ---------------------------------------------------------------
    // Fix 3: Outlook sendMail base64 body must not be JSON-quoted.
    //
    // When outlook-client.js sends a base64-encoded MIME message via
    // sendMail, the payload must arrive as a raw base64 string with
    // Content-Type: text/plain. If the payload is passed as a JS string
    // instead of a Buffer, the non-Buffer branch in outlook.js wraps it
    // with JSON.stringify(), adding quotes around the base64 content.
    // The fix wraps the base64 string in a Buffer so it takes the
    // Buffer code path, which sends the body as-is.
    // ---------------------------------------------------------------

    await t.test('Outlook: Buffer payload with text/plain contentType is sent without JSON quoting', async () => {
        const { server, baseUrl, getBody } = await startBodyCapturingServer();
        try {
            const outlook = new OutlookOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                authority: 'common',
                redirectUrl: 'http://localhost/callback',
                setFlag: async () => {}
            });

            const base64Content = Buffer.from('From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nHello').toString('base64');
            const payload = Buffer.from(base64Content);

            await outlook.request('fake-token', `${baseUrl}/me/sendMail`, 'post', payload, {
                contentType: 'text/plain',
                returnText: true
            });

            const receivedBody = getBody().toString();

            // The body must be the raw base64 string, not wrapped in JSON quotes
            assert.strictEqual(receivedBody, base64Content, 'Body should be raw base64, not JSON-stringified');
            assert.ok(!receivedBody.startsWith('"'), 'Body must not start with a JSON quote');
            assert.ok(!receivedBody.endsWith('"'), 'Body must not end with a JSON quote');
        } finally {
            await stopServer(server);
        }
    });
});
