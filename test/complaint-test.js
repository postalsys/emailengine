'use strict';

// Test fixtures in fixtures/complaints/ are from:
// https://github.com/sisimai/set-of-emails/
// Licensed under BSD 2-Clause License, Copyright (C) 2014, azumakuniyuki

const test = require('node:test');
const assert = require('node:assert').strict;

const { arfDetect } = require('../lib/arf-detect');
const { simpleParser } = require('mailparser');
const fs = require('fs');

// Exercise the real complaint heuristic instead of a copy. The IMAP sync path
// uses Mailbox.mightBeAComplaint (lib/email-client/imap/mailbox.js); it only
// reads `this.path` and `this.isAllMail`, so we bind a minimal receiver that
// represents an INBOX folder. A regression in the shipping heuristic now fails
// this suite.
const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

const inboxReceiver = { path: 'INBOX', isAllMail: false };
const mightBeAComplaint = messageInfo => Mailbox.prototype.mightBeAComplaint.call(inboxReceiver, messageInfo);

const Path = require('path');
const path = fname => Path.join(__dirname, 'fixtures', 'complaints', fname);

registerRedisTeardown(redis);

// Helper to parse email and prepare messageInfo for arfDetect
async function parseForArfDetect(filePath) {
    const content = await fs.promises.readFile(filePath);
    const parsed = await simpleParser(content, { keepDeliveryStatus: true });

    return {
        from: parsed.from?.value?.[0] || {},
        subject: parsed.subject || '',
        messageSpecialUse: '\\Inbox',
        attachments: (parsed.attachments || []).map(att => ({
            contentType: att.contentType,
            content: att.content
        }))
    };
}

test('ARF complaint detection tests', async t => {
    await t.test('handles missing attachments gracefully', async () => {
        const cases = [
            { label: 'undefined', attachments: undefined },
            { label: 'null', attachments: null },
            { label: 'empty array', attachments: [] }
        ];

        for (const { label, attachments } of cases) {
            const messageInfo = {
                from: { address: 'test@example.com' },
                subject: 'Test',
                attachments
            };
            const report = await arfDetect(messageInfo);
            assert.ok(report, `should return report for ${label} attachments`);
            assert.deepStrictEqual(report.arf, {}, `arf should be empty for ${label} attachments`);
            assert.deepStrictEqual(report.headers, {}, `headers should be empty for ${label} attachments`);
        }
    });

    await t.test('Yahoo ARF abuse report', async () => {
        const messageInfo = await parseForArfDetect(path('yahoo.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this
        assert.strictEqual(mightBeAComplaint(messageInfo), true);

        // Verify ARF parsing
        assert.strictEqual(report.arf['feedback-type'], 'abuse');
        assert.ok(report.arf['original-rcpt-to'].includes('this-local-part-does-not-exist-on-yahoo@yahoo.com'));
        assert.strictEqual(report.arf['user-agent'], 'Yahoo!-Mail-Feedback/1.0');
        assert.strictEqual(report.arf['original-mail-from'], 'shironeko@example.com');
    });

    await t.test('Amazon SES complaint', async () => {
        const messageInfo = await parseForArfDetect(path('amazonses.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this
        assert.strictEqual(mightBeAComplaint(messageInfo), true);

        // Verify ARF parsing
        assert.strictEqual(report.arf['feedback-type'], 'abuse');
        assert.ok(report.arf['original-rcpt-to'].includes('kijitora@y.example.com'));
        // Amazon SES uses bounce address format for mail-from
        assert.ok(report.arf['original-mail-from'].includes('amazonses.com'));
    });

    await t.test('Hotmail complaint (special handling)', async () => {
        const messageInfo = await parseForArfDetect(path('hotmail.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this (Hotmail pattern)
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
        assert.strictEqual(messageInfo.from.address, 'staff@hotmail.com');
        assert.ok(/complaint/i.test(messageInfo.subject));

        // Verify ARF parsing - Hotmail uses special defaults
        assert.strictEqual(report.arf['feedback-type'], 'abuse');
        assert.strictEqual(report.arf.source, 'Hotmail');
        assert.strictEqual(report.arf['abuse-type'], 'complaint');
    });

    await t.test('DMARC auth-failure report', async () => {
        const messageInfo = await parseForArfDetect(path('dmarc.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this
        assert.strictEqual(mightBeAComplaint(messageInfo), true);

        // Verify ARF parsing - DMARC reports have auth-failure type
        assert.strictEqual(report.arf['feedback-type'], 'auth-failure');
        assert.ok(report.arf['original-rcpt-to'].includes('kijitora@example.com'));
        assert.strictEqual(report.arf['original-mail-from'], 'sironeko@example.org');
    });

    await t.test('Standard ARF abuse report with multiple recipients', async () => {
        const messageInfo = await parseForArfDetect(path('standard-arf.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this
        assert.strictEqual(mightBeAComplaint(messageInfo), true);

        // Verify ARF parsing
        assert.strictEqual(report.arf['feedback-type'], 'abuse');
        assert.ok(Array.isArray(report.arf['original-rcpt-to']));
        assert.ok(report.arf['original-rcpt-to'].length >= 1);
        assert.ok(report.arf['original-rcpt-to'].includes('kijitora@example.com'));
    });

    await t.test('Opt-out (unsubscribe) report', async () => {
        const messageInfo = await parseForArfDetect(path('optout.eml'));
        const report = await arfDetect(messageInfo);

        // Verify mightBeAComplaint would detect this
        assert.strictEqual(mightBeAComplaint(messageInfo), true);

        // Verify ARF parsing - opt-out is a different feedback type
        assert.strictEqual(report.arf['feedback-type'], 'opt-out');
        // Opt-out reports contain removal-recipient instead of original-rcpt-to
        assert.ok(report.arf['removal-recipient']);
        assert.ok(report.arf['removal-recipient'].includes('user@example.com'));
    });

    await t.test('Original message headers extraction', async () => {
        // optout.eml has text/rfc822-header attachment with extractable headers
        const messageInfo = await parseForArfDetect(path('optout.eml'));
        const report = await arfDetect(messageInfo);

        // Verify original message headers are extracted from text/rfc822-header
        assert.ok(report.headers);
        assert.ok(report.headers['message-id']);
        assert.ok(report.headers.from);
        assert.ok(report.headers.subject);
    });

    await t.test('text/rfc822-header content type support', async () => {
        // optout.eml uses text/rfc822-header (singular)
        const messageInfo = await parseForArfDetect(path('optout.eml'));

        // Verify the attachment type is detected
        const hasTextRfc822Header = messageInfo.attachments.some(att => att.contentType === 'text/rfc822-header');
        assert.strictEqual(hasTextRfc822Header, true);

        // Verify headers are still extracted
        const report = await arfDetect(messageInfo);
        assert.ok(report.headers);
        assert.ok(report.headers['message-id']);
    });
});

test('mightBeAComplaint heuristics', async t => {
    await t.test('Detects message/feedback-report attachment', async () => {
        const messageInfo = {
            from: { address: 'unknown@example.com' },
            subject: 'Random subject',
            attachments: [{ contentType: 'message/feedback-report' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Detects Hotmail complaint pattern', async () => {
        const messageInfo = {
            from: { address: 'staff@hotmail.com' },
            subject: 'complaint about message from 192.0.2.1',
            attachments: []
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Rejects non-complaint Hotmail email', async () => {
        const messageInfo = {
            from: { address: 'staff@hotmail.com' },
            subject: 'Welcome to Hotmail',
            attachments: []
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), false);
    });

    await t.test('Detects feedbackloop sender with abuse subject', async () => {
        const messageInfo = {
            from: { address: 'feedbackloop@example.com' },
            subject: 'Abuse Report',
            attachments: []
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Detects complaints sender with embedded message', async () => {
        const messageInfo = {
            from: { address: 'complaints@example.com' },
            subject: 'Random',
            attachments: [{ contentType: 'message/rfc822' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Detects abuse report subject with embedded message', async () => {
        const messageInfo = {
            from: { address: 'noreply@example.com' },
            subject: 'Spam Report for your domain',
            attachments: [{ contentType: 'message/rfc822-headers' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Supports text/rfc822-headers content type', async () => {
        const messageInfo = {
            from: { address: 'fbl@example.com' },
            subject: 'FBL Report',
            attachments: [{ contentType: 'text/rfc822-headers' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Supports text/rfc822-header content type (singular)', async () => {
        const messageInfo = {
            from: { address: 'abuse@example.com' },
            subject: 'Complaint',
            attachments: [{ contentType: 'text/rfc822-header' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), true);
    });

    await t.test('Rejects unrelated email', async () => {
        const messageInfo = {
            from: { address: 'newsletter@example.com' },
            subject: 'Weekly Newsletter',
            attachments: [{ contentType: 'image/png' }]
        };
        assert.strictEqual(mightBeAComplaint(messageInfo), false);
    });
});

// BaseClient.mightBeAComplaint (the Gmail/Outlook path) has drifted from the
// Mailbox.mightBeAComplaint (IMAP path) heuristic above: it gates on
// messageSpecialUse === '\\Inbox', requires an embedded message for the Hotmail
// case, and does NOT recognize the generic feedback-loop sender patterns. These
// tests pin that real (narrower) behavior so a future change to either copy is
// caught. If the two are ever consolidated, update these expectations together.
test('mightBeAComplaint drift between BaseClient and Mailbox', async t => {
    const baseClientComplaint = messageData => BaseClient.prototype.mightBeAComplaint.call(null, messageData);

    await t.test('BaseClient requires messageSpecialUse Inbox', () => {
        const msg = { attachments: [{ contentType: 'message/feedback-report' }] };
        // Without the Inbox special-use marker the base-client heuristic bails out.
        assert.strictEqual(baseClientComplaint(msg), false);
        assert.strictEqual(baseClientComplaint({ ...msg, messageSpecialUse: '\\Inbox' }), true);
    });

    await t.test('BaseClient ignores generic FBL sender patterns that Mailbox detects', () => {
        const msg = {
            messageSpecialUse: '\\Inbox',
            from: { address: 'fbl@example.com' },
            subject: 'FBL Report',
            attachments: [{ contentType: 'text/rfc822-headers' }]
        };
        // Mailbox path: FBL sender + embedded message -> complaint.
        assert.strictEqual(mightBeAComplaint(msg), true);
        // BaseClient path: no feedback-report, text/rfc822-headers is not treated
        // as an embedded message, no FBL pattern -> not a complaint.
        assert.strictEqual(baseClientComplaint(msg), false);
    });

    await t.test('BaseClient Hotmail case requires an embedded message', () => {
        const base = {
            messageSpecialUse: '\\Inbox',
            from: { address: 'staff@hotmail.com' },
            subject: 'complaint about message'
        };
        // Without an embedded message BaseClient rejects, Mailbox accepts.
        assert.strictEqual(baseClientComplaint({ ...base, attachments: [] }), false);
        assert.strictEqual(mightBeAComplaint({ ...base, attachments: [] }), true);
        // With an embedded message both accept.
        assert.strictEqual(baseClientComplaint({ ...base, attachments: [{ contentType: 'message/rfc822' }] }), true);
    });
});
