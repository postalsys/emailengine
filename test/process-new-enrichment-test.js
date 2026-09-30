'use strict';

// The arrival enrichment in both processNew() implementations: BaseClient's (the Gmail and Graph
// clients) and Mailbox's (IMAP). Each step here either decides what a messageNew / emailBounce
// webhook says, or can throw and so decide whether one is sent at all.
//
// - A DSN is parsed with the HTML left alone (MAILPARSER-1): without the options, simpleParser
//   inlines every cid: reference as a whole data URL, once per reference, and a small message can
//   grow past the string limit and crash the worker from inside the parser.
// - Only a failed delivery is a bounce (CONTENT-4): a delayed or delivered DSN that lands in Junk
//   reached the bounce path with its structured action and fired emailBounce.
// - A web-safe conversion failure is rendered as escaped text by messageWebSafeHtml() itself
//   (TEXTTOOLS-2), so the notification is neither lost nor delivered with unsanitized HTML.
// - A message with no text part has no text object, which the LLM gate dereferenced (IMAP-11).
// - Inline images end up embedded in the web-safe copy too (CONTENT-5), which is what webhooks
//   deliver in place of the HTML, and an image the inline pass skipped as too large is not
//   downloaded after all.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

// Everything below is patched before the modules under test destructure it at load
const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];

const parserCalls = [];
const mailparser = require('mailparser');
const realSimpleParser = mailparser.simpleParser;
mailparser.simpleParser = async (input, options) => {
    parserCalls.push(options || {});
    return realSimpleParser(input, options);
};

let bounceResult = null;
const bounceDetectModule = require('../lib/bounce-detect');
bounceDetectModule.bounceDetect = async () => bounceResult;

let webSafeHtml = async messageData => messageData.text.html || '';
const webSafeModule = require('../lib/web-safe-html');
const realMessageWebSafeHtml = webSafeModule.messageWebSafeHtml;
webSafeModule.messageWebSafeHtml = async messageData => webSafeHtml(messageData);

let llmDecision = false;
const { llmPreProcess } = require('../lib/llm-pre-process');
llmPreProcess.run = async () => llmDecision;

const { BaseClient } = require('../lib/email-client/base-client');
const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { MAX_INLINE_ATTACHMENT_SIZE } = require('../lib/consts');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

const DSN_HEADERS = { 'content-type': ['multipart/report; report-type=delivery-status; boundary="b"'] };
const RAW_DSN = Buffer.from('Content-Type: text/plain\r\nSubject: DSN\r\n\r\nhello\r\n');

function reset() {
    parserCalls.length = 0;
    bounceResult = null;
    webSafeHtml = async messageData => messageData.text.html || '';
    llmDecision = false;
    for (const key of Object.keys(settingsValues)) {
        delete settingsValues[key];
    }
}

// A BaseClient stand-in: the real prototype, with the provider round trips stubbed
function createApiClient(messageData) {
    const notifications = [];
    const downloads = [];
    const ctx = Object.assign(Object.create(BaseClient.prototype), {
        account: 'test-account',
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        logger: noopLogger,
        redis: { set: async () => 'OK', del: async () => 1 },
        getRawMessage: async () => RAW_DSN,
        getAttachment: async id => {
            downloads.push(id);
            if (id === 'failing') {
                throw Object.assign(new Error('Service unavailable'), { statusCode: 503 });
            }
            return { data: Buffer.from('image-bytes') };
        },
        call: async () => ({}),
        notify: async (mailbox, event, data) => {
            notifications.push({ event, data });
        }
    });
    return { ctx, notifications, downloads, run: () => ctx.processNew(messageData, {}) };
}

// A Mailbox stand-in in the shape test/mailbox-process-new-checks-test.js uses
function createMailbox(messageInfo, { dsn = false, bounce = false } = {}) {
    const notifications = [];
    const downloads = [];
    const imapClient = {
        download: async () => ({ content: RAW_DSN }),
        downloadMany: async (uid, parts) => {
            downloads.push(...parts);
            return Object.fromEntries(parts.map(part => [part, { content: Buffer.from('image-bytes') }]));
        }
    };
    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        logger: noopLogger,
        connection: {
            account: 'test-account',
            imapClient,
            getImapConnection: async () => ({ fetchOne: async () => ({ uid: 42, flags: new Set() }) }),
            notifyFrom: false,
            redis: { pfadd: async () => 1 },
            mightBeAComplaint: () => false,
            mightBeDSNResponse: () => dsn,
            mightBeABounce: () => bounce,
            call: async () => ({}),
            async notify(mailbox, event, data) {
                notifications.push({ event, data });
            }
        },
        getMessageInfo: async () => Object.assign({ id: 'AAAAAQAAAAI', uid: 42, messageSpecialUse: '\\Inbox' }, messageInfo),
        getSeenMessagesKey: () => 'seen:test-account:INBOX'
    });
    return { ctx, notifications, downloads, run: () => ctx.processNew({ uid: 42, flags: new Set() }, {}, {}) };
}

const events = notifications => notifications.map(entry => entry.event);

test('DSN parsing leaves cid: links alone', async t => {
    t.beforeEach(reset);

    await t.test('BaseClient.processNew()', async () => {
        const { run } = createApiClient({ id: 'm1', messageSpecialUse: '\\Inbox', headers: DSN_HEADERS });
        await run();

        assert.equal(parserCalls.length, 1);
        assert.equal(parserCalls[0].keepDeliveryStatus, true);
        assert.equal(parserCalls[0].skipImageLinks, true);
        assert.equal(parserCalls[0].keepCidLinks, true);
    });

    await t.test('Mailbox.processNew()', async () => {
        const { run } = createMailbox({ headers: DSN_HEADERS }, { dsn: true });
        await run();

        assert.equal(parserCalls.length, 1);
        assert.equal(parserCalls[0].keepDeliveryStatus, true);
        assert.equal(parserCalls[0].skipImageLinks, true);
        assert.equal(parserCalls[0].keepCidLinks, true);
    });
});

test('only a failed delivery is a bounce', async t => {
    t.beforeEach(reset);

    const bounceFrom = { name: 'Mail Delivery System', address: 'mailer-daemon@example.com' };

    for (const action of ['delayed', 'delivered', 'relayed', 'expanded']) {
        await t.test(`a ${action} report in Junk sends no emailBounce (BaseClient)`, async () => {
            bounceResult = { action, recipient: 'user@example.com', messageId: '<original@example.com>' };
            const messageData = { id: 'm1', messageSpecialUse: '\\Junk', from: bounceFrom };
            const { run, notifications } = createApiClient(messageData);

            await run();

            assert.deepEqual(events(notifications), ['messageNew']);
            assert.ok(!messageData.isBounce);
        });
    }

    await t.test('a delayed report sends no emailBounce (Mailbox)', async () => {
        bounceResult = { action: 'delayed', recipient: 'user@example.com', messageId: '<original@example.com>' };
        const { run, notifications } = createMailbox({}, { bounce: true });

        await run();

        assert.deepEqual(events(notifications), ['messageNew']);
        assert.ok(!notifications[0].data.isBounce);
    });

    await t.test('a failed delivery is still reported (BaseClient)', async () => {
        bounceResult = { action: 'failed', recipient: 'user@example.com', messageId: '<original@example.com>' };
        const { run, notifications } = createApiClient({ id: 'm1', messageSpecialUse: '\\Junk', from: bounceFrom });

        await run();

        assert.deepEqual(events(notifications), ['messageNew', 'messageBounce']);
    });

    await t.test('a failed delivery is still reported (Mailbox)', async () => {
        bounceResult = { action: 'Failed', recipient: 'user@example.com', messageId: '<original@example.com>' };
        const { run, notifications } = createMailbox({}, { bounce: true });

        await run();

        assert.deepEqual(events(notifications), ['messageNew', 'messageBounce']);
    });

    await t.test('the report-type parameter is compared without regard to case', () => {
        const client = Object.create(BaseClient.prototype);
        assert.equal(client.looksLikeDSNResponse({ headers: { 'content-type': ['multipart/report; report-type=Delivery-Status; boundary=x'] } }), true);
        assert.equal(client.looksLikeDSNResponse({ headers: { 'content-type': ['multipart/report; report-type=disposition-notification'] } }), false);
    });
});

// Hostile nesting makes the sanitizer throw. messageWebSafeHtml() renders such a message as escaped
// text itself (test/web-safe-html-test.js), so neither processNew() guards the call any more, and
// what reaches the webhook is that fallback, never the unsanitized HTML
test('a web-safe conversion failure does not drop messageNew', async t => {
    t.beforeEach(reset);

    const hostile = '<div>'.repeat(4000) + 'deep' + '</div>'.repeat(4000);

    const assertFallbackDelivered = notifications => {
        assert.deepEqual(events(notifications), ['messageNew']);
        const text = notifications[0].data.text;
        assert.equal(text.webSafe, true, 'the fallback is what webhooks deliver as the web-safe copy');
        assert.match(text._generatedHtml, /deep/);
        assert.ok(!text._generatedHtml.includes('<div>'), 'escaped text, not the unsanitized HTML');
    };

    await t.test('BaseClient.processNew()', async () => {
        settingsValues.notifyWebSafeHtml = true;
        webSafeHtml = realMessageWebSafeHtml;
        const { run, notifications } = createApiClient({ id: 'm1', messageSpecialUse: '\\Inbox', text: { html: hostile } });

        await run();

        assertFallbackDelivered(notifications);
    });

    await t.test('Mailbox.processNew()', async () => {
        settingsValues.notifyWebSafeHtml = true;
        webSafeHtml = realMessageWebSafeHtml;
        const { run, notifications } = createMailbox({ text: { html: hostile } });

        await run();

        assertFallbackDelivered(notifications);
    });
});

test('the LLM step copes with a message that has no text part', async t => {
    t.beforeEach(reset);

    await t.test('BaseClient.processNew()', async () => {
        llmDecision = { generateEmailSummary: true };
        const { run, notifications } = createApiClient({ id: 'm1', messageSpecialUse: '\\Inbox' });

        await run();

        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('Mailbox.processNew()', async () => {
        llmDecision = { generateEmailSummary: true };
        const { run, notifications } = createMailbox({});

        await run();

        assert.deepEqual(events(notifications), ['messageNew']);
    });
});

test('inline images in the web-safe copy', async t => {
    t.beforeEach(reset);

    const html = '<p><img src="cid:small@x"><img src="cid:big@x"></p>';

    await t.test('BaseClient.processNew() embeds an already loaded image in both copies', async () => {
        settingsValues.notifyWebSafeHtml = true;
        const messageData = {
            id: 'm1',
            messageSpecialUse: '\\Inbox',
            text: { html },
            attachments: [
                { id: 'small', contentId: '<small@x>', contentType: 'image/png', encodedSize: 100 },
                { id: 'big', contentId: '<big@x>', contentType: 'image/png', encodedSize: MAX_INLINE_ATTACHMENT_SIZE + 1 }
            ]
        };
        const { run, notifications, downloads } = createApiClient(messageData);

        await run();

        const text = notifications[0].data.text;
        const dataUri = `data:image/png;base64,${Buffer.from('image-bytes').toString('base64')}`;
        // The earlier inline pass loaded the small image; the embed step used to `continue` past it
        assert.ok(text.html.includes(dataUri), 'embedded in the HTML');
        assert.ok(text._generatedHtml.includes(dataUri), 'and in the web-safe copy webhooks deliver');
        assert.ok(text._generatedHtml.includes('cid:big@x'), 'a skipped image keeps its reference');
        assert.deepEqual(downloads, ['small'], 'the oversized image is not downloaded after all');
    });

    await t.test('BaseClient.processNew() survives a failing image download', async () => {
        settingsValues.notifyWebSafeHtml = true;
        const messageData = {
            id: 'm1',
            messageSpecialUse: '\\Inbox',
            text: { html: '<img src="cid:img@x">' },
            attachments: [{ id: 'failing', contentId: '<img@x>', contentType: 'image/png', encodedSize: 100 }]
        };
        const { run, notifications } = createApiClient(messageData);

        await run();

        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('Mailbox.processNew() embeds downloaded images in the web-safe copy', async () => {
        settingsValues.notifyWebSafeHtml = true;
        const partId = part => Buffer.concat([Buffer.alloc(8), Buffer.from(part)]).toString('base64url');
        const { run, notifications, downloads } = createMailbox({
            text: { html },
            attachments: [
                { id: partId('2'), contentId: '<small@x>', contentType: 'image/png', encodedSize: 100 },
                { id: partId('3'), contentId: '<big@x>', contentType: 'image/png', encodedSize: MAX_INLINE_ATTACHMENT_SIZE + 1 }
            ]
        });

        await run();

        const text = notifications[0].data.text;
        assert.ok(text._generatedHtml.includes('data:image/png;base64,'), 'the web-safe copy carries the image');
        assert.ok(text._generatedHtml.includes('cid:big@x'));
        assert.deepEqual(downloads, ['2'], 'the oversized image is not downloaded');
    });
});
