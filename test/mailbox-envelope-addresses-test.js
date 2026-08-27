'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time. getMessageInfo() never reaches Redis.
require('./helpers/mock-db').installDbMock();

const { Mailbox, notificationHeaderFields } = require('../lib/email-client/imap/mailbox');

// Regression tests for the address fields Mailbox.getMessageInfo() exposes.
//
// The fallback to header-parsed addresses only fired when the ENVELOPE list was
// EMPTY, which is the shape Lark Mail produces. A server that mis-parses a
// malformed header produces a different shape: a non-empty list holding a display
// name and no address at all. That list is not empty, so the good addresses parsed
// from the raw header were discarded in favour of it.
//
// Reported against CoreLogic Credco notifications carrying
// "To: user@example.com user@example.com" - two bare addresses with no separating
// comma. The recipient's IMAP server turned that into an ENVELOPE address with a
// NIL host, which is RFC 9051 7.5.2 group syntax, and consumers downstream got a
// recipient they could not use.

function createContext({ envelope, headers }) {
    return {
        path: 'INBOX',
        logger: {
            trace() {},
            debug() {},
            info() {},
            warn() {},
            error() {}
        },
        connection: {
            account: 'test-account',
            packUid: async () => 'AAAAAAAAAAAA',
            isAutoreply: () => false
        },
        // The real implementation, so the payload is shaped as in production
        getAttachmentList: Mailbox.prototype.getAttachmentList,
        messageData: {
            uid: 42,
            size: 1024,
            envelope,
            headers: headers ? Buffer.from(headers) : undefined,
            internalDate: new Date('2026-08-20T10:47:39.000Z')
        }
    };
}

async function messageInfo(options, extended = true) {
    const ctx = createContext(options);
    return Mailbox.prototype.getMessageInfo.call(ctx, ctx.messageData, extended);
}

test('Mailbox.getMessageInfo() address fields', async t => {
    await t.test('prefers the ENVELOPE when it carries a usable address', async () => {
        const info = await messageInfo({
            envelope: {
                from: [{ name: 'Sender', address: 'sender@example.com' }],
                to: [{ name: 'Recipient', address: 'recipient@example.com' }]
            },
            headers: 'From: Someone Else <other@example.com>\r\nTo: other@example.com\r\n'
        });

        assert.deepEqual(info.from, { name: 'Sender', address: 'sender@example.com' });
        assert.deepEqual(info.to, [{ name: 'Recipient', address: 'recipient@example.com' }]);
    });

    await t.test('falls back to the header when the ENVELOPE list holds no address', async () => {
        // What an IMAP server reports for "To: user@example.com user@example.com":
        // the whole thing becomes a display name and the host field comes back NIL
        const info = await messageInfo({
            envelope: {
                from: [{ name: 'CoreLogic Credco', address: 'no-reply.credco@example.com' }],
                to: [{ name: 'user@example.com user@', address: '' }]
            },
            headers: 'From: CoreLogic Credco <no-reply.credco@example.com>\r\nTo: user@example.com user@example.com\r\n'
        });

        assert.deepEqual(info.to, [{ name: '', address: 'user@example.com' }], 'the recipient must be recovered from the raw header');
    });

    await t.test('falls back for from and cc as well', async () => {
        const info = await messageInfo({
            envelope: {
                from: [{ name: 'sender@example.com sender@', address: '' }],
                cc: [{ name: 'copy@example.com copy@', address: '' }]
            },
            headers: 'From: sender@example.com sender@example.com\r\nCc: copy@example.com copy@example.com\r\n'
        });

        assert.deepEqual(info.from, { name: '', address: 'sender@example.com' });
        assert.deepEqual(info.cc, [{ name: '', address: 'copy@example.com' }]);
    });

    await t.test('keeps the ENVELOPE entry when no header was fetched', async () => {
        // The message listing path fetches no headers, so a group name is all there is
        const info = await messageInfo({
            envelope: {
                to: [{ name: 'undisclosed-recipients', address: '' }]
            }
        });

        assert.deepEqual(info.to, [{ name: 'undisclosed-recipients', address: '' }]);
    });

    await t.test('keeps the ENVELOPE entry when the header parses to nothing either', async () => {
        const info = await messageInfo({
            envelope: {
                to: [{ name: 'undisclosed-recipients', address: '' }]
            },
            headers: 'To: undisclosed-recipients:;\r\n'
        });

        assert.deepEqual(info.to, [{ name: 'undisclosed-recipients', address: '' }]);
    });

    await t.test('a partially usable ENVELOPE list is kept whole', async () => {
        // One real address is enough to trust the ENVELOPE - dropping the group marker
        // here would lose a recipient the header parse does not necessarily recover
        const info = await messageInfo({
            envelope: {
                to: [
                    { name: 'Team', address: '' },
                    { name: 'Member', address: 'member@example.com' }
                ]
            },
            headers: 'To: Team:member@example.com;\r\n'
        });

        assert.deepEqual(info.to, [
            { name: 'Team', address: '' },
            { name: 'Member', address: 'member@example.com' }
        ]);
    });

    await t.test('falls back when the ENVELOPE address carries whitespace', async () => {
        // Gmail reports the whole run as the address when the two copies of the recipient
        // were separated by a non-breaking space. Unquoted whitespace is not addr-spec, so
        // this list is wreckage too even though the address field is not empty
        const info = await messageInfo({
            envelope: {
                to: [{ name: '', address: 'user@example.com\u00a0user@example.com' }]
            },
            headers: 'To: user@example.com user@example.com\r\n'
        });

        assert.deepEqual(info.to, [{ name: '', address: 'user@example.com' }], 'a whitespace-carrying ENVELOPE address must not block the header fallback');
    });

    await t.test('keeps an ENVELOPE address whose whitespace sits inside a quoted local part', async () => {
        // RFC 5321 allows it, so this is a real mailbox and the header must not override it
        const info = await messageInfo({
            envelope: {
                to: [{ name: 'Quoted', address: '"user name"@example.com' }]
            },
            headers: 'To: someone.else@example.com\r\n'
        });

        assert.deepEqual(info.to, [{ name: 'Quoted', address: '"user name"@example.com' }]);
    });

    await t.test('does not replace one wreck with another', async () => {
        // The header parses to an address that carries whitespace as well, which is worth no
        // more than the ENVELOPE entry - keep the ENVELOPE so the display name survives
        const info = await messageInfo({
            envelope: {
                to: [{ name: 'Recipients', address: '' }]
            },
            headers: 'To: <foo bar@>\r\n'
        });

        assert.deepEqual(info.to, [{ name: 'Recipients', address: '' }]);
    });

    await t.test('reports no address list at all when neither source has one', async () => {
        const info = await messageInfo({ envelope: { subject: 'No recipients' } });

        assert.equal(info.to, undefined);
        assert.equal(info.cc, undefined);
        assert.equal(info.from, undefined);
    });

    await t.test('bcc uses the parsed header too, and stays behind the extended flag', async () => {
        const options = {
            envelope: { bcc: [{ name: 'blind@example.com blind@', address: '' }] },
            headers: 'Bcc: blind@example.com blind@example.com\r\n'
        };

        const extended = await messageInfo(options, true);
        assert.deepEqual(extended.bcc, [{ name: '', address: 'blind@example.com' }]);

        const plain = await messageInfo(options, false);
        assert.equal(plain.bcc, undefined, 'bcc is only exposed on an extended fetch');
    });
});

// The fallback above is only reachable on the notification path if the address headers are
// actually fetched. They used to be requested for Lark Mail accounts only, which is why the
// fallback never fired for anyone else.
test('notificationHeaderFields()', async t => {
    await t.test('always requests the address headers', () => {
        const fields = notificationHeaderFields(undefined);

        for (const key of ['from', 'to', 'cc', 'bcc']) {
            assert.ok(fields.includes(key), `${key} must be fetched for every account, not just Lark Mail`);
        }
    });

    await t.test('keeps the headers the operator asked for', () => {
        const fields = notificationHeaderFields(['x-mailer', 'list-id']);

        assert.ok(fields.includes('x-mailer'));
        assert.ok(fields.includes('list-id'));
        assert.ok(fields.includes('to'));
    });

    await t.test('still requests what the notification path needs for itself', () => {
        const fields = notificationHeaderFields(undefined);

        for (const key of ['x-autoreply', 'x-autorespond', 'auto-submitted', 'precedence', 'in-reply-to', 'references', 'content-type']) {
            assert.ok(fields.includes(key), `${key} is needed for auto-reply, threading or bounce detection`);
        }
    });

    await t.test('does not duplicate an operator header that it also needs', () => {
        const fields = notificationHeaderFields(['to', 'content-type']);

        assert.equal(fields.filter(key => key === 'to').length, 1);
        assert.equal(fields.filter(key => key === 'content-type').length, 1);
    });

    await t.test('tolerates the non-array values the setting can produce', () => {
        // notifyHeaders resolves to false when the setting is present but empty
        assert.ok(notificationHeaderFields(false).includes('to'));
        assert.ok(notificationHeaderFields(undefined).includes('to'));
    });
});
