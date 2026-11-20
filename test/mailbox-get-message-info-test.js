'use strict';

// Pins the whole output of Mailbox.getMessageInfo(), which shapes every message an IMAP account
// lists, fetches or announces. The comparison is deepStrictEqual (a key holding undefined is not a
// missing key, and the function strips undefined values) plus the JSON key order.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time. getMessageInfo() never reaches Redis.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { BaseClient } = require('../lib/email-client/base-client');
const { createMockLogger } = require('./helpers/mock-logger');

const PACKED_UID = 'AAAAAQAAAAIAAAAq';

const OTP_HEADER = '"123456"; origin="https://login.example.com"';

function createContext(extra) {
    return Object.assign(
        {
            path: 'INBOX',
            logger: createMockLogger(),
            connection: {
                account: 'test-account',
                packUid: async () => PACKED_UID,
                isAutoreply: BaseClient.prototype.isAutoreply
            },
            getAttachmentList: Mailbox.prototype.getAttachmentList
        },
        extra
    );
}

const BODY_STRUCTURE = {
    type: 'multipart/mixed',
    childNodes: [
        {
            type: 'multipart/related',
            part: '1',
            childNodes: [
                {
                    type: 'multipart/alternative',
                    part: '1.1',
                    childNodes: [
                        { part: '1.1.1', type: 'text/plain', parameters: { charset: 'utf-8' }, encoding: 'quoted-printable', size: 120 },
                        { part: '1.1.2', type: 'text/html', parameters: { charset: 'utf-8' }, encoding: 'quoted-printable', size: 480 }
                    ]
                },
                { part: '1.2', type: 'image/png', parameters: { name: 'logo.png' }, id: '<logo@example.com>', encoding: 'base64', size: 2048 }
            ]
        },
        {
            part: '2',
            type: 'application/pdf',
            parameters: { name: 'report.pdf' },
            disposition: 'attachment',
            dispositionParameters: { filename: 'report.pdf' },
            encoding: 'base64',
            size: 40960
        },
        { part: '3', type: 'text/calendar', parameters: { method: 'REQUEST' }, disposition: 'attachment', encoding: 'base64', size: 900 }
    ]
};

const HEADERS = [
    'Return-Path: <sender@example.net>',
    'From: Report Sender <sender@example.net>',
    'To: User One <user@example.com>',
    'Subject: Q3 report',
    'Auto-Submitted: auto-replied',
    `OTP-Token: ${OTP_HEADER}`,
    ''
].join('\r\n');

function messageData(extra) {
    return Object.assign(
        {
            seq: 12,
            uid: 42,
            emailId: 'M18f2a9c4b7d10e55',
            threadId: 'T18f2a9c4b7d10e55',
            size: 48213,
            flags: new Set(['\\Seen', '\\Flagged', '\\Answered', '\\Recent', '$Label1']),
            labels: new Set(['\\Inbox', 'Project']),
            internalDate: new Date('2026-08-21T17:14:45.000Z'),
            envelope: {
                date: new Date('2026-08-21T17:14:42.000Z'),
                subject: 'Q3 report',
                from: [{ name: 'Report Sender', address: 'sender@example.net' }],
                sender: [{ name: 'Mailer', address: 'mailer@example.net' }],
                replyTo: [{ name: '', address: 'replies@example.net' }],
                to: [{ name: 'User One', address: 'user@example.com' }],
                cc: [{ name: 'Copy', address: 'copy@example.com' }],
                bcc: [{ name: '', address: 'hidden@example.com' }],
                inReplyTo: '<CAF=request.0@mail.example.com>',
                messageId: ' <CAF=report.1@mail.example.net> '
            },
            bodyStructure: BODY_STRUCTURE,
            headers: Buffer.from(HEADERS)
        },
        extra
    );
}

const ATTACHMENTS = [
    {
        id: 'AAAAAQAAAAIAAAAqMS4y',
        contentType: 'image/png',
        encodedSize: 2048,
        // the file size, from the base64 part size less its line breaks
        size: 1497,
        embedded: true,
        inline: true,
        encodedInMessage: false,
        filename: 'logo.png',
        contentId: '<logo@example.com>'
    },
    {
        id: 'AAAAAQAAAAIAAAAqMg',
        contentType: 'application/pdf',
        encodedSize: 40960,
        size: 29932,
        embedded: false,
        inline: false,
        encodedInMessage: false,
        filename: 'report.pdf'
    },
    {
        id: 'AAAAAQAAAAIAAAAqMw',
        contentType: 'text/calendar',
        encodedSize: 900,
        size: 658,
        embedded: false,
        inline: false,
        encodedInMessage: false,
        method: 'REQUEST'
    }
];

const EXTENDED = {
    id: PACKED_UID,
    uid: 42,
    path: 'INBOX',
    emailId: 'M18f2a9c4b7d10e55',
    threadId: 'T18f2a9c4b7d10e55',
    date: '2026-08-21T17:14:42.000Z',
    flags: ['\\Seen', '\\Flagged', '\\Answered', '$Label1'],
    labels: ['\\Inbox', 'Project'],
    flagged: true,
    answered: true,
    size: 48213,
    subject: 'Q3 report',
    from: { name: 'Report Sender', address: 'sender@example.net' },
    replyTo: [{ name: '', address: 'replies@example.net' }],
    sender: { name: 'Mailer', address: 'mailer@example.net' },
    to: [{ name: 'User One', address: 'user@example.com' }],
    cc: [{ name: 'Copy', address: 'copy@example.com' }],
    bcc: [{ name: '', address: 'hidden@example.com' }],
    attachments: ATTACHMENTS,
    messageId: '<CAF=report.1@mail.example.net>',
    inReplyTo: '<CAF=request.0@mail.example.com>',
    headers: {
        'return-path': ['<sender@example.net>'],
        from: ['Report Sender <sender@example.net>'],
        to: ['User One <user@example.com>'],
        subject: ['Q3 report'],
        'auto-submitted': ['auto-replied'],
        'otp-token': [OTP_HEADER]
    },
    text: { id: 'AAAAAQAAAAIAAAAqk5GlMS4xLjGRpTEuMS4ykA', encodedSize: { plain: 120, html: 480 } },
    isAutoReply: true,
    otp: { code: '123456', origin: 'https://login.example.com', authenticated: false }
};

function assertMessage(actual, expected) {
    assert.deepStrictEqual(actual, expected);
    assert.equal(JSON.stringify(actual), JSON.stringify(expected), 'key order');
}

async function messageInfo(data, extended, ctx) {
    ctx = ctx || createContext();
    return Mailbox.prototype.getMessageInfo.call(ctx, data, extended);
}

test('Mailbox.getMessageInfo()', async t => {
    await t.test('an extended fetch', async () => {
        const data = messageData();
        assertMessage(await messageInfo(data, true), EXTENDED);
        // the session specific flag is removed from the fetched data itself
        assert.deepStrictEqual(Array.from(data.flags), ['\\Seen', '\\Flagged', '\\Answered', '$Label1']);
    });

    await t.test('a listing entry leaves out the extended fields, the auto-reply check and the otp', async () => {
        const expected = Object.assign({}, EXTENDED);
        for (const key of ['path', 'sender', 'bcc', 'headers', 'isAutoReply', 'otp']) {
            delete expected[key];
        }
        assertMessage(await messageInfo(messageData(), false), expected);

        // without headers not even the subject is checked
        const subjectOnly = await messageInfo(messageData({ envelope: { subject: 'Automatic reply: Q3 report' } }), false);
        assert.equal('isAutoReply' in subjectOnly, false);
    });

    await t.test('an unseen draft, detected from its labels, with every optional field absent', async () => {
        const info = await messageInfo(
            {
                uid: 7,
                flags: new Set(['\\Recent']),
                labels: new Set(['\\Draft']),
                internalDate: new Date('2026-08-21T17:14:45.000Z'),
                envelope: { date: new Date('invalid') }
            },
            true
        );
        assertMessage(info, {
            id: PACKED_UID,
            uid: 7,
            path: 'INBOX',
            date: '2026-08-21T17:14:45.000Z',
            flags: [],
            labels: ['\\Draft'],
            unseen: true,
            draft: true
        });
    });

    await t.test('a draft detected from its flags, no flags or labels at all', async () => {
        const draft = await messageInfo({ uid: 8, flags: new Set(['\\Draft', '\\Seen']) }, false);
        assertMessage(draft, { id: PACKED_UID, uid: 8, flags: ['\\Draft', '\\Seen'], draft: true });

        const bare = await messageInfo({ uid: 9, envelope: { subject: '' } }, false);
        assertMessage(bare, { id: PACKED_UID, uid: 9 });
    });

    await t.test('the envelope date wins over the internal date while it is valid', async () => {
        const info = await messageInfo(messageData({ envelope: { date: new Date('2026-01-01T00:00:00.000Z') } }), false);
        assert.equal(info.date, '2026-01-01T00:00:00.000Z');
        const fallback = await messageInfo(messageData({ envelope: { date: 'Fri, 21 Aug 2026' } }), false);
        assert.equal(fallback.date, '2026-08-21T17:14:45.000Z');
        const none = await messageInfo(messageData({ envelope: {}, internalDate: undefined }), false);
        assert.equal('date' in none, false);
    });

    await t.test('without a body structure the attachment list keeps its shape', () => {
        assert.deepStrictEqual(Mailbox.prototype.getAttachmentList.call(createContext(), PACKED_UID, undefined), {
            attachments: [],
            textId: undefined,
            encodedTextSize: {}
        });
    });

    await t.test('no message data', async () => {
        assert.equal(await messageInfo(null, true), false);
    });

    await t.test('a uid that cannot be packed', async () => {
        const failing = extra =>
            createContext(
                Object.assign(
                    {
                        connection: { account: 'test-account', packUid: async () => false, isAutoreply: () => false }
                    },
                    extra
                )
            );

        const ctx = failing({ getStoredStatus: async () => ({ uidValidity: 1234, uidNext: 99 }) });
        await assert.rejects(messageInfo(messageData(), true, ctx), {
            message: 'Failed to generate message ID (uid=42;uv=1234;path=INBOX;n=99)'
        });
        assert.deepStrictEqual(ctx.logger.entries, [
            {
                level: 'error',
                msg: 'Failed to generate message ID',
                uid: 42,
                messageId: undefined,
                mailbox: 'INBOX',
                storedStatus: { uidValidity: 1234, uidNext: 99 }
            }
        ]);

        const statusError = new Error('Redis gone');
        const broken = failing({
            getStoredStatus: async () => {
                throw statusError;
            }
        });
        await assert.rejects(messageInfo(messageData({ messageId: '<m@example.com>' }), true, broken), {
            message: 'Failed to generate message ID (uid=42;uv=undefined;path=INBOX;n=err)'
        });
        assert.deepStrictEqual(broken.logger.entries[0].storedStatus, { err: statusError });
        assert.equal(broken.logger.entries[0].messageId, '<m@example.com>');
    });
});
