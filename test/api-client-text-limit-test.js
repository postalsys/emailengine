'use strict';

// Unit coverage for the maxBytes text limit on the API clients (Gmail, MS Graph).
//
// The IMAP path truncates fetched text to options.maxBytes (mailbox.js getText),
// but the API clients used to ignore the option: the notifyTextSize setting and
// the REST maxBytes query parameter had no effect on Gmail and Outlook accounts.
// These tests pin the option at the two places it now applies per client: the
// formatMessage() path getMessage()/prepareNewMessage() use, and getText().

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const msgpack = require('../lib/msgpack');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring the clients pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

const PLAIN_TEXT = 'plain text content that is long enough to truncate';
const HTML_TEXT = '<p>html content that is also long enough to truncate</p>';

const noopLogger = { trace: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

// A minimal Gmail API message (format=full) with one plain and one html part
const gmailMessage = () => ({
    id: 'msg1',
    threadId: 'thread1',
    internalDate: '1787332482000',
    sizeEstimate: 1024,
    labelIds: ['INBOX', 'UNREAD'],
    snippet: 'snippet',
    payload: {
        partId: '',
        mimeType: 'multipart/alternative',
        headers: [
            { name: 'From', value: 'Sender <sender@example.com>' },
            { name: 'To', value: 'rcpt@example.com' },
            { name: 'Subject', value: 'Test' },
            { name: 'Message-ID', value: '<m1@example.com>' },
            { name: 'Date', value: 'Fri, 21 Aug 2026 10:14:42 -0700' }
        ],
        body: { size: 0 },
        parts: [
            { partId: '1', mimeType: 'text/plain', body: { size: PLAIN_TEXT.length, data: Buffer.from(PLAIN_TEXT).toString('base64') } },
            { partId: '2', mimeType: 'text/html', body: { size: HTML_TEXT.length, data: Buffer.from(HTML_TEXT).toString('base64') } }
        ]
    }
});

// A minimal MS Graph message with an html body
const graphMessage = () => ({
    id: 'gm1',
    conversationId: 'conv1',
    receivedDateTime: '2026-08-21T17:00:00.000Z',
    isRead: false,
    flag: { flagStatus: 'notFlagged' },
    subject: 'Test',
    bodyPreview: 'preview',
    body: { contentType: 'html', content: HTML_TEXT },
    from: { emailAddress: { name: 'Sender', address: 'sender@example.com' } },
    toRecipients: [{ emailAddress: { address: 'rcpt@example.com' } }],
    internetMessageId: '<m1@example.com>'
});

test('API client text limits', async t => {
    await t.test('Gmail formatMessage() truncates text to maxBytes and flags hasMore', async () => {
        const client = new GmailClient('text-limit-test', {});
        client.logger = noopLogger;

        const limited = client.formatMessage(gmailMessage(), { extended: true, textType: '*', maxBytes: 10 });
        assert.strictEqual(limited.text.plain, PLAIN_TEXT.substr(0, 10));
        assert.strictEqual(limited.text.html, HTML_TEXT.substr(0, 10));
        assert.strictEqual(limited.text.hasMore, true);

        const full = client.formatMessage(gmailMessage(), { extended: true, textType: '*' });
        assert.strictEqual(full.text.plain, PLAIN_TEXT);
        assert.strictEqual(full.text.html, HTML_TEXT);
        assert.strictEqual(full.text.hasMore, false);
    });

    await t.test('Gmail getText() truncates text to maxBytes and flags hasMore', async () => {
        const client = new GmailClient('text-limit-test', {});
        client.logger = noopLogger;
        client.prepare = async () => {};
        client.request = async () => gmailMessage();

        const textId = msgpack.encode(['msg1', [['1'], ['2'], []]]).toString('base64url');

        const limited = await client.getText(textId, { textType: '*', maxBytes: 10 });
        assert.strictEqual(limited.plain, PLAIN_TEXT.substr(0, 10));
        assert.strictEqual(limited.html, HTML_TEXT.substr(0, 10));
        assert.strictEqual(limited.hasMore, true);

        const full = await client.getText(textId, { textType: '*' });
        assert.strictEqual(full.plain, PLAIN_TEXT);
        assert.strictEqual(full.html, HTML_TEXT);
        assert.strictEqual(full.hasMore, false);
    });

    await t.test('Outlook formatMessage() truncates text to maxBytes and flags hasMore', async () => {
        const client = new OutlookClient('text-limit-test', {});
        client.logger = noopLogger;

        const limited = client.formatMessage(graphMessage(), { extended: true, textType: '*', maxBytes: 10 });
        assert.strictEqual(limited.text.html, HTML_TEXT.substr(0, 10));
        assert.strictEqual(limited.text.hasMore, true);

        const full = client.formatMessage(graphMessage(), { extended: true, textType: '*' });
        assert.strictEqual(full.text.html, HTML_TEXT);
        assert.strictEqual(full.text.hasMore, false);
    });

    await t.test('Outlook getText() truncates text to maxBytes and flags hasMore', async () => {
        const client = new OutlookClient('text-limit-test', {});
        client.logger = noopLogger;
        client.prepare = async () => {};
        client.request = async () => ({ body: { contentType: 'html', content: HTML_TEXT } });

        const limited = await client.getText('gm1', { textType: '*', maxBytes: 10 });
        assert.strictEqual(limited.html, HTML_TEXT.substr(0, 10));
        assert.strictEqual(limited.hasMore, true);

        const full = await client.getText('gm1', { textType: '*' });
        assert.strictEqual(full.html, HTML_TEXT);
        assert.strictEqual(full.hasMore, false);
    });
});
