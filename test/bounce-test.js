'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { bounceDetect, decodeDeliveryStatus, parseDeliveryReport, applyDeliveryReport } = require('../lib/bounce-detect');
const msgpack = require('msgpack5')();
const fs = require('fs');

const Path = require('path');
const path = fname => Path.join(__dirname, 'fixtures', 'bounces', fname);

test('Bounce parsing tests', async t => {
    await t.test('163', async () => {
        const content = await fs.promises.readFile(path('163.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'jgfhhoiyfjhhugjhv@ethereal.email');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, 'SMTP error, RCPT TO: Host ethereal.email(54.36.85.113) RCPT TO said 550 No such user here');
        assert.strictEqual(bounce.messageId, '<cc799ab9-ab11-0960-f3c2-2e4b9a5e8fb6@163.com>');
    });

    await t.test('fastmail', async () => {
        const content = await fs.promises.readFile(path('fastmail.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'htfgvhyufthdgcvhgjyfthgc@ethereal.email');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, '550 No such user here');
        assert.strictEqual(bounce.messageId, '<e85f1c9b-9b51-4028-8ec0-0a657155028e@app.fastmail.com>');
    });

    await t.test('gmail', async () => {
        const content = await fs.promises.readFile(path('gmail.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'jhfthgfuyfhvjkugjhvjuyfv@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '550 5.1.1 <jhfthgfuyfhvjkugjhvjuyfv@hot.ee>: Recipient address rejected: User unknown in relay recipient table'
        );
        assert.strictEqual(bounce.messageId, '<CAPacwgw3pCyVcmW4nVy8VPX5u5ksn_wZB2jZ_tLUM2es7LaiEA@mail.gmail.com>');
    });

    await t.test('hotmail', async () => {
        const content = await fs.promises.readFile(path('hotmail.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'sdfadsdfwedsfcasfeqwefwq@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '550 5.1.1 <sdfadsdfwedsfcasfeqwefwq@hot.ee>: Recipient address rejected: User unknown in relay recipient table'
        );
        assert.strictEqual(bounce.messageId, '<DB6PR0902MB194406730EDCF3E12EE16DCF90209@DB6PR0902MB1944.eurprd09.prod.outlook.com>');
    });

    await t.test('mailru', async () => {
        const content = await fs.promises.readFile(path('mailru.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'tfhgyuftghjyftghv@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, '550 5.1.1 <tfhgyuftghjyftghv@hot.ee>: Recipient address rejected: User unknown in relay recipient table');
        assert.strictEqual(bounce.messageId, '<1665380146.431729680@f705.i.mail.ru>');
    });

    await t.test('outlook', async () => {
        const content = await fs.promises.readFile(path('outlook.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'wfsddaSdasffasdqwqw@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '550 5.1.1 <wfsddaSdasffasdqwqw@hot.ee>: Recipient address rejected: User unknown in relay recipient table'
        );
        assert.strictEqual(bounce.messageId, '<PR1PR07MB57558E5D11D6C2BA6F950391D7209@PR1PR07MB5755.eurprd07.prod.outlook.com>');
    });

    await t.test('postfix', async () => {
        const content = await fs.promises.readFile(path('postfix.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'sdagfsdfgdasfsdf@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, '550 5.1.1 <sdagfsdfgdasfsdf@hot.ee>: Recipient address rejected: User unknown in relay recipient table');
        assert.strictEqual(bounce.queueId, 'DF59B82305');
        assert.strictEqual(bounce.messageId, '<0f51267b17be7a93bb0017205b6c4fca@ekiri.ee>');
    });

    await t.test('rambler', async () => {
        const content = await fs.promises.readFile(path('rambler.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'yhfgcvjyutfdchgyufthgc@ethereal.email');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, '550 No such user here');
        assert.strictEqual(bounce.messageId, '<18c57ad7166403358c3893f62d7e3a7f@mail.rambler.ru>');
    });

    await t.test('workmail', async () => {
        const content = await fs.promises.readFile(path('workmail.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'gfdutydrfghutydrfcuftydh@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '550 5.1.1 <gfdutydrfghutydrfcuftydh@hot.ee>: Recipient address rejected: User unknown in relay recipient table'
        );
        assert.strictEqual(bounce.messageId, '<mail.6343b157.093e.5156c64350ef7e50@storage.wm.amazon.com>');
    });

    await t.test('Yahoo', async () => {
        const content = await fs.promises.readFile(path('yahoo.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'thgdcgrfchvutycfgxcvg@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '550: 5.1.1 <thgdcgrfchvutycfgxcvg@hot.ee>: Recipient address rejected: User unknown in relay recipient table'
        );
        assert.strictEqual(bounce.messageId, '<1956854879.3770605.1665380049620@mail.yahoo.com>');
    });

    await t.test('zonemta', async () => {
        const content = await fs.promises.readFile(path('zonemta.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'sdffasdfgfasfadas@hot.ee');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.message, '550 5.1.1 <sdffasdfgfasfadas@hot.ee>: Recipient address rejected: User unknown in relay recipient table');
        assert.strictEqual(bounce.messageId, '<48a84e64-d471-cfa6-3ea5-f10cd8571135@zone.ee>');
    });

    await t.test('zoho', async () => {
        const content = await fs.promises.readFile(path('zoho.eml'));
        const bounce = await bounceDetect(content);

        assert.strictEqual(bounce.recipient, 'recipient@example.com');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(
            bounce.response.message,
            '5.2.1 The email account that you tried to reach is disabled. Learn more at 5.2.1  https://support.google.com/mail/?p=DisabledUser j8-20020a170903024800b001946612570csi19333477plh.316 - gsmtp'
        );
        assert.strictEqual(bounce.messageId, '<63d982c2660381675199170@smtppro.zoho.com>');
    });
});

test('decodeDeliveryStatus', async t => {
    await t.test('reads the per-recipient block that follows the per-message block', () => {
        const entries = decodeDeliveryStatus(
            [
                'Reporting-MTA: dns; mx.example.com',
                'Arrival-Date: Mon, 10 Oct 2022 01:37:21 -0400 (EDT)',
                '',
                'Final-Recipient: rfc822; user@example.com',
                'Action: failed',
                'Status: 5.1.1',
                ''
            ].join('\r\n')
        );

        assert.deepStrictEqual(entries['reporting-mta'], ['dns; mx.example.com']);
        assert.deepStrictEqual(entries['final-recipient'], ['rfc822; user@example.com']);
        assert.deepStrictEqual(entries.action, ['failed']);
        assert.deepStrictEqual(entries.status, ['5.1.1']);
    });

    await t.test('reports only the first recipient when several are listed', () => {
        const entries = decodeDeliveryStatus(
            [
                'Reporting-MTA: dns; mx.example.com',
                '',
                'Final-Recipient: rfc822; first@example.com',
                'Action: failed',
                '',
                'Final-Recipient: rfc822; second@example.com',
                'Action: delayed'
            ].join('\r\n')
        );

        assert.deepStrictEqual(entries['final-recipient'], ['rfc822; first@example.com']);
        assert.deepStrictEqual(entries.action, ['failed']);
        // per-message fields still come through
        assert.deepStrictEqual(entries['reporting-mta'], ['dns; mx.example.com']);
    });

    await t.test('does not pair a recipient with the diagnostic code of another', () => {
        const entries = decodeDeliveryStatus(
            [
                'Reporting-MTA: dns; mx.example.com',
                '',
                'Final-Recipient: rfc822; first@example.com',
                'Action: failed',
                '',
                'Final-Recipient: rfc822; second@example.com',
                'Action: failed',
                'Diagnostic-Code: smtp; 550 No such user'
            ].join('\r\n')
        );

        assert.deepStrictEqual(entries['final-recipient'], ['rfc822; first@example.com']);
        assert.strictEqual(entries['diagnostic-code'], undefined);
    });

    await t.test('merges the whole body when no recipient is reported', () => {
        const entries = decodeDeliveryStatus(['Reporting-MTA: dns; mx.example.com', '', 'Action: failed'].join('\r\n'));

        assert.deepStrictEqual(entries['reporting-mta'], ['dns; mx.example.com']);
        assert.deepStrictEqual(entries.action, ['failed']);
    });

    await t.test('a "__proto__" field does not reach Object.prototype', () => {
        const entries = decodeDeliveryStatus(['__proto__: polluted', '', 'Action: failed'].join('\r\n'));

        assert.deepStrictEqual(entries['__proto__'], ['polluted']);
        assert.deepStrictEqual(entries.action, ['failed']);
        assert.strictEqual({}.polluted, undefined);
    });

    await t.test('tolerates an empty body', () => {
        assert.deepStrictEqual(Object.keys(decodeDeliveryStatus('')), []);
        assert.deepStrictEqual(Object.keys(decodeDeliveryStatus(null)), []);
    });
});

test('parseDeliveryReport', async t => {
    const body = [
        'Reporting-MTA: dns; mx.example.com',
        'Arrival-Date: Mon, 10 Oct 2022 01:37:21 -0400 (EDT)',
        '',
        'Final-Recipient: rfc822; user@example.com',
        'Action: delivered',
        'Status: 2.0.0',
        ''
    ].join('\r\n');

    await t.test('camelCases the field names and reads the per-recipient block', () => {
        const report = parseDeliveryReport(body);

        assert.strictEqual(report.action, 'delivered');
        assert.strictEqual(report.status, '2.0.0');
    });

    await t.test('normalizes Arrival-Date to an ISO timestamp', () => {
        assert.strictEqual(parseDeliveryReport(body).arrivalDate, new Date('Mon, 10 Oct 2022 01:37:21 -0400').toISOString());
    });

    await t.test('leaves an unparseable Arrival-Date as it was', () => {
        assert.strictEqual(parseDeliveryReport('Arrival-Date: whenever').arrivalDate, 'whenever');
    });

    await t.test('reports a field that carries an address type as label and value', () => {
        const report = parseDeliveryReport(body);

        assert.deepStrictEqual(report.finalRecipient, { label: 'rfc822', value: 'user@example.com' });
        assert.deepStrictEqual(report.reportingMta, { label: 'dns', value: 'mx.example.com' });
    });

    await t.test('reports the diagnostic code of the recipient it describes', () => {
        const report = parseDeliveryReport(
            [
                'Reporting-MTA: dns; mx.example.com',
                '',
                'Final-Recipient: rfc822; first@example.com',
                'Action: delayed',
                'Diagnostic-Code: smtp; 450 Greylisted',
                '',
                'Final-Recipient: rfc822; second@example.com',
                'Action: failed',
                'Diagnostic-Code: smtp; 550 No such user'
            ].join('\r\n')
        );

        assert.deepStrictEqual(report.finalRecipient, { label: 'rfc822', value: 'first@example.com' });
        assert.strictEqual(report.action, 'delayed');
        assert.deepStrictEqual(report.diagnosticCode, { label: 'smtp', value: '450 Greylisted' });
    });

    await t.test('unfolds a Diagnostic-Code split over several lines', () => {
        const report = parseDeliveryReport(
            ['Final-Recipient: rfc822; user@example.com', 'Diagnostic-Code: smtp; 550 5.1.1 <user@example.com>: Recipient address', '    rejected'].join('\r\n')
        );

        assert.deepStrictEqual(report.diagnosticCode, { label: 'smtp', value: '550 5.1.1 <user@example.com>: Recipient address rejected' });
    });

    await t.test('tolerates an empty body', () => {
        assert.deepStrictEqual(parseDeliveryReport(''), {});
        assert.deepStrictEqual(parseDeliveryReport(null), {});
    });

    await t.test('drops a "__proto__" field instead of reporting it', () => {
        // An address-typed value is an object, so assigning it would swap the report's prototype
        // for attacker-supplied data, and keeping it as an own key makes msgpack refuse to decode
        const report = parseDeliveryReport(['Final-Recipient: rfc822; user@example.com', '__proto__: rfc822; injected'].join('\r\n'));

        assert.strictEqual(Object.getPrototypeOf(report), Object.prototype);
        assert.deepStrictEqual(Object.keys(report), ['finalRecipient']);
        assert.deepStrictEqual(report.finalRecipient, { label: 'rfc822', value: 'user@example.com' });
        assert.strictEqual({}.label, undefined);
        assert.deepStrictEqual(msgpack.decode(msgpack.encode(report)), { finalRecipient: { label: 'rfc822', value: 'user@example.com' } });
    });

    await t.test('ignores a block that is only a continuation line', () => {
        // decodeHeaders returns a single empty key for such a block, which is not a header
        const report = parseDeliveryReport(['Reporting-MTA: dns; mx.example.com', '', '  orphaned continuation', '', 'Action: failed'].join('\r\n'));

        assert.deepStrictEqual(Object.keys(report).sort(), ['action', 'reportingMta']);
        assert.strictEqual(report.action, 'failed');
    });
});

test('applyDeliveryReport', async t => {
    const logger = { debug: () => false };
    const dsn = action => ({
        attachments: [
            {
                contentType: 'message/delivery-status',
                content: ['Reporting-MTA: dns; mx.example.com', '', 'Final-Recipient: rfc822; user@example.com', `Action: ${action}`].join('\r\n')
            }
        ]
    });

    await t.test('sets deliveryReport for a delivered notification', () => {
        const messageInfo = {};

        assert.strictEqual(applyDeliveryReport(dsn('delivered'), messageInfo, logger), true);
        assert.deepStrictEqual(messageInfo.deliveryReport.finalRecipient, { label: 'rfc822', value: 'user@example.com' });
    });

    await t.test('sets deliveryReport for a delayed notification', () => {
        const messageInfo = {};

        assert.strictEqual(applyDeliveryReport(dsn('delayed'), messageInfo, logger), true);
        assert.strictEqual(messageInfo.deliveryReport.action, 'delayed');
    });

    await t.test('leaves a failure to the bounce path', () => {
        const messageInfo = {};

        assert.strictEqual(applyDeliveryReport(dsn('failed'), messageInfo, logger), false);
        assert.strictEqual(messageInfo.deliveryReport, undefined);
    });

    await t.test('does nothing without a delivery-status part', () => {
        const messageInfo = {};

        assert.strictEqual(applyDeliveryReport({ attachments: [{ contentType: 'text/plain', content: 'x' }] }, messageInfo, logger), false);
        assert.strictEqual(messageInfo.deliveryReport, undefined);
    });
});
