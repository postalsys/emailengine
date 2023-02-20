'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { bounceDetect } = require('../lib/bounce-detect');
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
