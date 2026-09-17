'use strict';

// Test fixtures in fixtures/complaints/ are from:
// https://github.com/sisimai/set-of-emails/
// Licensed under BSD 2-Clause License, Copyright (C) 2014, azumakuniyuki

const test = require('node:test');
const assert = require('node:assert').strict;

const { arfDetect, camelCaseComplaint, ORIGINAL_MESSAGE_TYPES } = require('../lib/arf-detect');
const { simpleParser } = require('mailparser');
const fs = require('fs');

// Exercise the real complaint heuristic instead of a copy: BaseClient.mightBeAComplaint is the one
// check both arrival paths run, gated on the message being in the Inbox, which is what the
// messages here represent.
const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

const mightBeAComplaint = messageInfo => BaseClient.prototype.mightBeAComplaint.call(BaseClient.prototype, { messageSpecialUse: '\\Inbox', ...messageInfo });

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

    await t.test('Tolerates a message without attachments', async () => {
        // The Gmail API and Graph clients leave `attachments` unset when there are none, and the
        // sender and subject rules qualify such a message on their own
        assert.strictEqual(mightBeAComplaint({ from: { address: 'abuse@isp.example' }, subject: 'Abuse report' }), true);
    });
});

// The arrival paths gate and download on the exported type lists, and arfDetect() has to parse
// every type they name, or a message admitted on one of them is parsed against nothing
test('every original-message attachment type is parsed', async t => {
    for (const contentType of ORIGINAL_MESSAGE_TYPES) {
        await t.test(contentType, async () => {
            const report = await arfDetect({
                attachments: [{ contentType, content: 'Message-ID: <original@example.com>\r\nSubject: Hello\r\n\r\nbody' }]
            });

            assert.strictEqual(report.headers['message-id'], '<original@example.com>');
        });
    }
});

test('camelCaseComplaint', async t => {
    await t.test('camelCases both sections of a report', () => {
        const complaint = camelCaseComplaint({
            arf: { 'feedback-type': 'abuse', 'original-rcpt-to': ['user@example.com'] },
            headers: { 'message-id': '<a@b>', subject: 'x' }
        });

        assert.deepStrictEqual(complaint, {
            arf: { feedbackType: 'abuse', originalRcptTo: ['user@example.com'] },
            headers: { messageId: '<a@b>', subject: 'x' }
        });
    });

    await t.test('leaves a section out when it holds no fields', () => {
        const complaint = camelCaseComplaint({ arf: { 'feedback-type': 'abuse' }, headers: {} });

        assert.deepStrictEqual(Object.keys(complaint), ['arf']);
    });
});

// A feedback report is an attacker-supplied attachment, and libmime.decodeHeaders() hands back
// "__proto__" as a real own key, which arfDetect() would otherwise write into report.arf. No
// global pollution is possible, and the reportDefaults merge at the end of arfDetect() already
// discards the resulting prototype swap on its own - so this pins the observable contract, and
// only fails if BOTH that merge and the key guard are dropped.
test('ARF reports with prototype-shaped field names', async t => {
    await t.test('drops a field name the camelCase step turns into "__proto__"', async () => {
        // The name published in the complaint is not the name in the report: camelCaseComplaint()
        // rebuilds it, and "_-_proto__" camelCases straight into "__proto__". Nothing before that
        // has a reason to refuse the name, and the assignment then swaps the prototype of the
        // section rather than storing a field - so unlike the case below, no later merge hides it
        // and this fails on its own if the guard goes.
        const report = await arfDetect({
            from: { address: 'complaints@example.com' },
            subject: 'complaint about message',
            messageSpecialUse: '\\Inbox',
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from('Feedback-Type: abuse\r\n_-_proto__: injected\r\nUser-Agent: SomeUA\r\n')
                }
            ]
        });

        const complaint = camelCaseComplaint(report);

        assert.strictEqual(Object.getPrototypeOf(complaint.arf), Object.prototype);
        assert.deepStrictEqual(Object.keys(complaint.arf), ['feedbackType', 'userAgent']);
        assert.strictEqual(complaint.arf.length, undefined, 'the section must not inherit the injected value');
        assert.deepStrictEqual(JSON.parse(JSON.stringify(complaint)).arf, complaint.arf);
    });

    await t.test('returns a clean report that survives the webhook round-trip', async () => {
        // Field names go into the raw report body rather than an object literal, since a literal
        // keyed by "__proto__" would set the literal's prototype instead of a key.
        const report = await arfDetect({
            from: { address: 'complaints@example.com' },
            subject: 'complaint about message',
            messageSpecialUse: '\\Inbox',
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from('Feedback-Type: abuse\r\n__proto__: injected\r\nUser-Agent: SomeUA\r\n')
                }
            ]
        });

        assert.strictEqual(Object.getPrototypeOf(report.arf), Object.prototype);
        assert.strictEqual(report.arf['feedback-type'], 'abuse');
        assert.ok(!Object.keys(report.arf).includes('__proto__'));

        const complaint = camelCaseComplaint(report);
        assert.strictEqual(Object.getPrototypeOf(complaint.arf), Object.prototype);
        assert.strictEqual(complaint.arf.feedbackType, 'abuse');
        // The payload is published as JSON, so it has to survive a round-trip unchanged
        assert.deepStrictEqual(JSON.parse(JSON.stringify(complaint)).arf, complaint.arf);
    });

    await t.test('drops a field name the camelCase step turns into an Object.prototype method name', async () => {
        // "to-string" is a name the parse boundary has no reason to refuse, but camelCased it
        // shadows Object.prototype.toString as an own string property - the first consumer that
        // string-coerces the published report then throws "Cannot convert object to a primitive
        // value". Same for "has-own-property" and hasOwnProperty().
        const report = await arfDetect({
            from: { address: 'complaints@example.com' },
            subject: 'complaint about message',
            messageSpecialUse: '\\Inbox',
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from('Feedback-Type: abuse\r\nTo-String: injected\r\nHas-Own-Property: injected\r\nUser-Agent: SomeUA\r\n')
                }
            ]
        });

        const complaint = camelCaseComplaint(report);

        assert.deepStrictEqual(Object.keys(complaint.arf), ['feedbackType', 'userAgent']);
        assert.strictEqual(typeof complaint.arf.toString, 'function', 'toString stays the inherited method');
        assert.strictEqual(typeof complaint.arf.hasOwnProperty, 'function', 'hasOwnProperty stays the inherited method');
        assert.strictEqual(typeof `${complaint.arf}`, 'string', 'the section still string-coerces');
    });
});

test('ARF Source-IP precedence', async t => {
    await t.test('the feedback report Source-IP wins over an X-Sender-IP header', async () => {
        const report = await arfDetect({
            from: { address: 'complaints@example.com' },
            subject: 'complaint about message',
            messageSpecialUse: '\\Inbox',
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from('Feedback-Type: abuse\r\nSource-IP: 192.0.2.1\r\n')
                },
                {
                    contentType: 'message/rfc822-headers',
                    content: Buffer.from('X-Sender-IP: 198.51.100.2\r\nSubject: original\r\n\r\n')
                }
            ]
        });

        assert.strictEqual(report.arf['source-ip'], '192.0.2.1', 'the authoritative Source-IP is kept');
    });

    await t.test('X-Sender-IP fills in when the feedback report has no Source-IP', async () => {
        const report = await arfDetect({
            from: { address: 'complaints@example.com' },
            subject: 'complaint about message',
            messageSpecialUse: '\\Inbox',
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from('Feedback-Type: abuse\r\n')
                },
                {
                    contentType: 'message/rfc822-headers',
                    content: Buffer.from('X-Sender-IP: 198.51.100.2\r\nSubject: original\r\n\r\n')
                }
            ]
        });

        assert.strictEqual(report.arf['source-ip'], '198.51.100.2', 'the fallback header is used');
    });
});
