'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

test('Outlook sendMail base64 encoding tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('raw.toString("base64") produces valid base64 string', async () => {
        const rawMimeMessage = Buffer.from(
            'From: sender@example.com\r\n' +
                'To: recipient@example.com\r\n' +
                'Subject: Test Message\r\n' +
                'Content-Type: text/plain\r\n' +
                '\r\n' +
                'This is the message body.'
        );

        const base64String = rawMimeMessage.toString('base64');

        assert.strictEqual(typeof base64String, 'string');
        assert.ok(base64String.length > 0);
        assert.ok(/^[A-Za-z0-9+/]*={0,2}$/.test(base64String), 'Should contain only valid base64 characters');

        const decoded = Buffer.from(base64String, 'base64');
        assert.deepStrictEqual(decoded, rawMimeMessage);
    });

    await t.test('toString("base64") is equivalent to the previous Buffer.from(raw.toString("base64")) approach', async () => {
        const rawMimeMessage = Buffer.from('Test message content');

        // Old: Buffer.from(raw.toString('base64')) created a Buffer of base64 chars
        // New: raw.toString('base64') directly produces the string
        const oldImplementation = Buffer.from(rawMimeMessage.toString('base64'));
        const newImplementation = rawMimeMessage.toString('base64');

        assert.strictEqual(oldImplementation.toString('utf-8'), newImplementation);
    });

    await t.test('base64 string is not a Buffer', async () => {
        const rawMimeMessage = Buffer.from(
            'MIME-Version: 1.0\r\n' + 'From: sender@example.com\r\n' + 'To: recipient@example.com\r\n' + 'Subject: Test\r\n' + '\r\n' + 'Message body.'
        );

        const base64Body = rawMimeMessage.toString('base64');

        assert.strictEqual(typeof base64Body, 'string');
        assert.ok(!Buffer.isBuffer(base64Body));
    });

    await t.test('large message encoding roundtrips correctly', async () => {
        const largeContent = 'A'.repeat(100000);
        const rawMimeMessage = Buffer.from(
            'From: sender@example.com\r\n' + 'To: recipient@example.com\r\n' + 'Subject: Large Test\r\n' + '\r\n' + largeContent
        );

        const base64String = rawMimeMessage.toString('base64');
        const decoded = Buffer.from(base64String, 'base64').toString();

        assert.ok(decoded.includes(largeContent));
    });

    await t.test('binary content is properly encoded', async () => {
        const binaryData = Buffer.alloc(256);
        for (let i = 0; i < 256; i++) {
            binaryData[i] = i;
        }

        const base64String = binaryData.toString('base64');
        const decoded = Buffer.from(base64String, 'base64');

        assert.deepStrictEqual(decoded, binaryData);
    });

    await t.test('string payload passes through without conversion', async () => {
        const base64Payload = 'SGVsbG8gV29ybGQ=';

        // Simulates the outlook.js request method logic for string payloads
        const result = typeof base64Payload === 'string' ? base64Payload : JSON.stringify(base64Payload);

        assert.strictEqual(result, base64Payload);
    });
});
