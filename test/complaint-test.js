'use strict';

// Test fixtures in fixtures/complaints/ are from:
// https://github.com/sisimai/set-of-emails/
// Licensed under BSD 2-Clause License, Copyright (C) 2014, azumakuniyuki

const test = require('node:test');
const assert = require('node:assert').strict;

const { arfDetect } = require('../lib/arf-detect');
const { simpleParser } = require('mailparser');
const fs = require('fs');

const Path = require('path');
const path = fname => Path.join(__dirname, 'fixtures', 'complaints', fname);

// Helper to parse email and prepare messageInfo for arfDetect
async function parseForArfDetect(filePath) {
    const content = await fs.promises.readFile(filePath);
    const parsed = await simpleParser(content, { keepDeliveryStatus: true });

    return {
        from: parsed.from?.value?.[0] || {},
        subject: parsed.subject || '',
        attachments: (parsed.attachments || []).map(att => ({
            contentType: att.contentType,
            content: att.content
        }))
    };
}

// Replicate mightBeAComplaint logic for testing
function mightBeAComplaint(messageInfo) {
    let hasEmbeddedMessage = false;
    for (let attachment of messageInfo.attachments || []) {
        if (attachment.contentType === 'message/feedback-report') {
            return true;
        }
        if (['message/rfc822', 'message/rfc822-headers', 'text/rfc822-headers', 'text/rfc822-header'].includes(attachment.contentType)) {
            hasEmbeddedMessage = true;
        }
    }

    let fromAddress = (messageInfo.from && messageInfo.from.address) || '';

    if (fromAddress === 'staff@hotmail.com' && /complaint/i.test(messageInfo.subject)) {
        return true;
    }

    if (/^(feedbackloop|fbl|complaints|abuse)@/i.test(fromAddress)) {
        if (hasEmbeddedMessage || /abuse|complaint|feedback|report/i.test(messageInfo.subject)) {
            return true;
        }
    }

    if (hasEmbeddedMessage && /abuse report|feedback report|spam report/i.test(messageInfo.subject)) {
        return true;
    }

    return false;
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
