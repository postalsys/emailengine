'use strict';

// Pins the whole output of formatMessage() on both API backends. Gmail's and MS Graph's
// formatMessage() turn every listed or fetched message into the API's message shape, so these
// tests compare whole outputs against payloads shaped as the providers return them
// (test/fixtures/api-messages): deepStrictEqual tells a key holding undefined from a missing one,
// and the JSON comparison pins the key order the REST response is serialized in.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const gmailFixtures = require('./fixtures/api-messages/gmail.json');
const graphFixtures = require('./fixtures/api-messages/graph.json');

const clone = value => JSON.parse(JSON.stringify(value));

function assertMessage(actual, expected) {
    assert.deepStrictEqual(actual, expected);
    assert.equal(JSON.stringify(actual), JSON.stringify(expected), 'key order');
}

const GMAIL_ATTACHMENTS = [
    {
        id: 'lbAxOGYyYTljNGI3ZDEwZTU1qWltYWdlL3BuZ6ZpbmxpbmWobG9nby5wbmerQU5HamRKOGxvZ28',
        contentType: 'image/png',
        encodedSize: 2048,
        size: 2048,
        embedded: true,
        inline: true,
        encodedInMessage: false,
        filename: 'logo.png',
        contentId: '<logo@example.com>'
    },
    {
        id: 'lbAxOGYyYTljNGI3ZDEwZTU1r2FwcGxpY2F0aW9uL3BkZqphdHRhY2htZW50qnJlcG9ydC5wZGatQU5HamRKOHJlcG9ydA',
        contentType: 'application/pdf',
        encodedSize: 40960,
        size: 40960,
        embedded: false,
        inline: false,
        encodedInMessage: false,
        filename: 'report.pdf',
        contentId: '<f_report>'
    },
    {
        id: 'lbAxOGYyYTljNGI3ZDEwZTU1rXRleHQvY2FsZW5kYXKqYXR0YWNobWVudKppbnZpdGUuaWNzrUFOR2pkSjhpbnZpdGU',
        contentType: 'text/calendar',
        encodedSize: 900,
        size: 900,
        embedded: false,
        inline: false,
        encodedInMessage: false,
        filename: 'invite.ics',
        method: 'REQUEST'
    }
];

const GMAIL_HEADERS = {
    'delivered-to': ['user@example.com'],
    'return-path': ['<sender@example.net>'],
    'mime-version': ['1.0'],
    date: ['Fri, 21 Aug 2026 10:14:42 -0700'],
    'message-id': [' <CAF=report.1@mail.example.net> '],
    'in-reply-to': ['<CAF=request.0@mail.example.com>'],
    subject: ['Q3 report'],
    from: ['Report Sender <sender@example.net>'],
    sender: ['Mailer <mailer@example.net>'],
    'reply-to': ['replies@example.net'],
    to: ['User One <user@example.com>, second@example.com'],
    cc: ['Copy <copy@example.com>'],
    bcc: ['hidden@example.com'],
    'content-type': ['multipart/mixed; boundary="000000000000b1"']
};

const GMAIL_FULL_EXTENDED = {
    id: '18f2a9c4b7d10e55',
    uid: undefined,
    path: 'INBOX',
    emailId: '18f2a9c4b7d10e55',
    threadId: '18f2a9c4b7d10e55',
    date: '2026-08-21T17:14:42.000Z',
    flags: ['\\Seen', '\\Flagged'],
    labels: ['Label_3141592', '\\Inbox'],
    category: 'updates',
    unseen: undefined,
    flagged: true,
    draft: undefined,
    size: 48213,
    subject: 'Q3 report',
    from: { address: 'sender@example.net', name: 'Report Sender' },
    replyTo: [{ address: 'replies@example.net', name: '' }],
    sender: { address: 'mailer@example.net', name: 'Mailer' },
    to: [
        { address: 'user@example.com', name: 'User One' },
        { address: 'second@example.com', name: '' }
    ],
    cc: [{ address: 'copy@example.com', name: 'Copy' }],
    bcc: [{ address: 'hidden@example.com', name: '' }],
    attachments: GMAIL_ATTACHMENTS,
    messageId: '<CAF=report.1@mail.example.net>',
    inReplyTo: '<CAF=request.0@mail.example.com>',
    headers: GMAIL_HEADERS,
    text: {
        id: 'krAxOGYyYTljNGI3ZDEwZTU1k5GlMC4wLjCRpTAuMC4xkA',
        encodedSize: { plain: 32, html: 74 },
        plain: 'Hi,\r\n\r\nThe report is attached.\r\n',
        html: '<div>Hi,<br><img src="cid:logo@example.com"> The report is attached.</div>',
        hasMore: false
    },
    preview: 'Hi, The report is attached. "Q3" & more',
    messageSpecialUse: '\\Inbox'
};

const GMAIL_AUTO_REPLY = {
    id: '18f2a9c4b7d10e77',
    uid: undefined,
    path: undefined,
    emailId: '18f2a9c4b7d10e77',
    threadId: '18f2a9c4b7d10e70',
    date: undefined,
    flags: ['\\Draft'],
    labels: ['\\Junk', '\\Inbox', '\\Drafts'],
    category: 'primary',
    unseen: true,
    flagged: undefined,
    draft: true,
    size: 1200,
    subject: 'Re: Q3 report',
    from: { address: 'away@example.org', name: '' },
    replyTo: undefined,
    sender: undefined,
    to: undefined,
    cc: undefined,
    bcc: undefined,
    attachments: undefined,
    messageId: '<away.1@example.org>',
    inReplyTo: undefined,
    headers: {
        subject: ['Re: Q3 report'],
        from: ['away@example.org'],
        'auto-submitted': ['auto-replied'],
        'message-id': ['<away.1@example.org>']
    },
    text: { id: 'krAxOGYyYTljNGI3ZDEwZTc3k5GgkJA', encodedSize: { plain: 0 }, plain: undefined, html: undefined, hasMore: undefined },
    preview: 'I am away',
    isAutoReply: true,
    messageSpecialUse: '\\Junk'
};

test('Gmail formatMessage()', async t => {
    const client = new GmailClient('format-message-test', {});
    const format = (message, options) => client.formatMessage(clone(message), options);

    await t.test('an extended fetch with every text part', () => {
        assertMessage(format(gmailFixtures.full, { extended: true, path: 'INBOX', textType: '*' }), GMAIL_FULL_EXTENDED);
    });

    await t.test('a listing entry leaves out the extended fields and the text', () => {
        assertMessage(
            format(gmailFixtures.full, { path: 'INBOX' }),
            Object.assign({}, GMAIL_FULL_EXTENDED, {
                path: undefined,
                sender: undefined,
                bcc: undefined,
                headers: undefined,
                text: { id: GMAIL_FULL_EXTENDED.text.id, encodedSize: { plain: 32, html: 74 }, plain: undefined, html: undefined, hasMore: undefined }
            })
        );
    });

    await t.test('one text type, truncated', () => {
        assertMessage(
            format(gmailFixtures.full, { extended: true, textType: 'html', maxBytes: 20 }),
            Object.assign({}, GMAIL_FULL_EXTENDED, {
                path: undefined,
                text: { id: GMAIL_FULL_EXTENDED.text.id, encodedSize: { plain: 32, html: 74 }, plain: undefined, html: '<div>Hi,<br><img src', hasMore: true }
            })
        );
    });

    await t.test('an auto-reply in spam, a draft with no usable date', () => {
        assertMessage(format(gmailFixtures.autoReply, { extended: true }), GMAIL_AUTO_REPLY);
    });

    await t.test('the auto-reply check runs without headers too', () => {
        // Unlike MS Graph, Gmail checks every message: the subject alone can mark one
        const message = clone(gmailFixtures.autoReply);
        message.payload.headers.find(header => header.name === 'Subject').value = 'Out of Office: Q3';
        assertMessage(
            format(message, {}),
            Object.assign({}, GMAIL_AUTO_REPLY, { subject: 'Out of Office: Q3', headers: undefined, isAutoReply: true, messageSpecialUse: '\\Junk' })
        );

        const plain = clone(gmailFixtures.autoReply);
        const result = format(plain, {});
        assert.equal('isAutoReply' in result, false, 'the Auto-Submitted header is only seen on an extended fetch');
    });

    await t.test('minimal format', () => {
        assertMessage(format(gmailFixtures.minimal, { minimalFields: true }), {
            id: '18f2a9c4b7d10e99',
            emailId: '18f2a9c4b7d10e99',
            threadId: '18f2a9c4b7d10e90',
            date: '2026-08-21T17:14:42.000Z',
            flags: ['\\Seen'],
            labels: ['\\Sent', '\\Trash'],
            category: 'social',
            unseen: undefined,
            flagged: undefined,
            draft: undefined,
            size: 3021,
            messageSpecialUse: '\\Sent'
        });
    });

    await t.test('minimal format with no labels and an out of range date', () => {
        assertMessage(format(gmailFixtures.minimalEmpty, { minimalFields: true }), {
            id: '18f2a9c4b7d10e9a',
            emailId: '18f2a9c4b7d10e9a',
            threadId: undefined,
            date: undefined,
            flags: ['\\Seen'],
            labels: [],
            category: undefined,
            unseen: undefined,
            flagged: undefined,
            draft: undefined,
            size: 10
        });
    });
});

const GRAPH_ATTACHMENTS = [
    {
        id: 'krBBQU1rQUdJMlRHOTNBQUE9rUFBTWtBR0kyYXR0MT0',
        contentType: 'image/png',
        encodedSize: 2048,
        size: 2048,
        inline: true,
        filename: 'logo.png',
        contentId: '<logo@example.com>',
        embedded: true
    },
    {
        id: 'krBBQU1rQUdJMlRHOTNBQUE9rUFBTWtBR0kyYXR0Mj0',
        contentType: 'application/pdf',
        encodedSize: 40960,
        size: 40960,
        inline: false,
        filename: 'report.pdf',
        contentId: '<f_report>'
    },
    { id: 'krBBQU1rQUdJMlRHOTNBQUE9rUFBTWtBR0kyYXR0Mz0', contentType: null, encodedSize: 900, size: 900, inline: false }
];

// Without the html text the inline image cannot be seen as embedded
const GRAPH_ATTACHMENTS_NOT_EMBEDDED = [
    {
        id: 'krBBQU1rQUdJMlRHOTNBQUE9rUFBTWtBR0kyYXR0MT0',
        contentType: 'image/png',
        encodedSize: 2048,
        size: 2048,
        inline: true,
        filename: 'logo.png',
        contentId: '<logo@example.com>'
    },
    GRAPH_ATTACHMENTS[1],
    GRAPH_ATTACHMENTS[2]
];

const GRAPH_FULL_EXTENDED = {
    id: 'AAMkAGI2TG93AAA=',
    path: 'Inbox',
    emailId: 'AAMkAGI2TG93AAA=',
    threadId: 'AAQkAGI2conv=',
    date: '2026-08-21T17:14:42.000Z',
    flags: ['\\Seen', '\\Draft', '\\Flagged'],
    labels: ['Blue category', 'Project'],
    unseen: undefined,
    flagged: true,
    draft: true,
    subject: 'Q3 report',
    from: { name: 'Report Sender', address: 'sender@example.net' },
    replyTo: [{ name: '', address: 'replies@example.net' }],
    sender: { name: 'Mailer', address: 'mailer@example.net' },
    to: [
        { name: 'User One', address: 'user@example.com' },
        { name: '', address: 'second@example.com' }
    ],
    cc: [{ name: 'Copy', address: 'copy@example.com' }],
    bcc: [{ name: '', address: 'hidden@example.com' }],
    messageId: '<CAF=report.1@mail.example.net>',
    inReplyTo: undefined,
    headers: { 'auto-submitted': ['no'], 'x-mailer': ['Example'], 'message-id': ['<CAF=report.1@mail.example.net>'] },
    text: {
        id: 'AAMkAGI2TG93AAA=',
        encodedSize: { html: 74 },
        plain: undefined,
        html: '<div>Hi,<br><img src="cid:logo@example.com"> The report is attached.</div>',
        hasMore: false
    },
    preview: 'Hi, The report is attached.',
    attachments: GRAPH_ATTACHMENTS
};

const GRAPH_PLAIN = {
    id: 'AAMkAGI2TG94AAA=',
    path: undefined,
    emailId: 'AAMkAGI2TG94AAA=',
    threadId: undefined,
    date: undefined,
    flags: [],
    labels: undefined,
    unseen: true,
    flagged: undefined,
    draft: undefined,
    subject: 'Automatic reply: Q3 report',
    from: { address: 'away@example.org' },
    replyTo: undefined,
    sender: undefined,
    to: undefined,
    cc: undefined,
    bcc: undefined,
    messageId: '<away.1@example.org>',
    inReplyTo: undefined,
    headers: undefined,
    text: { id: 'AAMkAGI2TG94AAA=', encodedSize: { plain: 23 }, plain: 'I am away until Monday.', html: undefined, hasMore: false },
    preview: 'I am away'
};

test('MS Graph formatMessage()', async t => {
    const client = new OutlookClient('format-message-test', {});
    const format = (message, options) => client.formatMessage(clone(message), options);

    await t.test('an extended fetch with every text part', () => {
        assertMessage(format(graphFixtures.full, { extended: true, path: 'Inbox', textType: '*' }), GRAPH_FULL_EXTENDED);
    });

    await t.test('showPath, one text type, truncated', () => {
        assertMessage(
            format(graphFixtures.full, { showPath: true, path: 'Inbox', textType: 'html', maxBytes: 20 }),
            Object.assign({}, GRAPH_FULL_EXTENDED, {
                sender: undefined,
                bcc: undefined,
                headers: undefined,
                text: { id: 'AAMkAGI2TG93AAA=', encodedSize: { html: 74 }, plain: undefined, html: '<div>Hi,<br><img src', hasMore: true },
                attachments: GRAPH_ATTACHMENTS_NOT_EMBEDDED
            })
        );
    });

    await t.test('a listing entry', () => {
        assertMessage(
            format(graphFixtures.full, { path: 'Inbox' }),
            Object.assign({}, GRAPH_FULL_EXTENDED, {
                path: undefined,
                sender: undefined,
                bcc: undefined,
                headers: undefined,
                text: { id: 'AAMkAGI2TG93AAA=', encodedSize: { html: 74 }, plain: undefined, html: undefined, hasMore: undefined },
                attachments: GRAPH_ATTACHMENTS_NOT_EMBEDDED
            })
        );
    });

    await t.test('the auto-reply check runs only when headers are present', () => {
        assertMessage(format(graphFixtures.plain, { extended: true, textType: 'plain' }), GRAPH_PLAIN);

        assertMessage(
            format(Object.assign(clone(graphFixtures.plain), { headers: {} }), { extended: true, textType: 'html' }),
            Object.assign({}, GRAPH_PLAIN, {
                headers: {},
                text: { id: 'AAMkAGI2TG94AAA=', encodedSize: { html: 0, plain: 23 }, plain: undefined, html: '', hasMore: undefined },
                isAutoReply: true
            })
        );
    });

    await t.test('a message with nothing but an id', () => {
        assertMessage(format(graphFixtures.bare), {
            id: 'AAMkAGI2TG95AAA=',
            path: undefined,
            emailId: 'AAMkAGI2TG95AAA=',
            threadId: undefined,
            date: undefined,
            flags: [],
            labels: undefined,
            unseen: true,
            flagged: undefined,
            draft: undefined,
            subject: undefined,
            from: undefined,
            replyTo: undefined,
            sender: undefined,
            to: undefined,
            cc: undefined,
            bcc: undefined,
            messageId: undefined,
            inReplyTo: undefined,
            headers: undefined,
            text: { id: 'AAMkAGI2TG95AAA=', encodedSize: {}, plain: undefined, html: undefined, hasMore: undefined },
            preview: undefined
        });
    });

    await t.test('minimal fields', () => {
        assertMessage(format(graphFixtures.full, { minimalFields: true }), {
            id: 'AAMkAGI2TG93AAA=',
            emailId: 'AAMkAGI2TG93AAA=',
            threadId: 'AAQkAGI2conv=',
            date: '2026-08-21T17:14:42.000Z',
            uid: 1157707754,
            size: 0
        });
        assertMessage(format(graphFixtures.bare, { minimalFields: true }), {
            id: 'AAMkAGI2TG95AAA=',
            emailId: 'AAMkAGI2TG95AAA=',
            threadId: undefined,
            date: undefined,
            uid: 1155860712,
            size: 0
        });
    });
});
