'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const libmime = require('libmime');

const { parseEmail, getHeader, hasHeader, contentToString, contentToBase64 } = require('../lib/parse-helpers');

test('parse-helpers tests', async t => {
    // Sample email for testing
    const sampleEmail = Buffer.from(
        [
            'From: sender@example.com',
            'To: recipient@example.com',
            'Subject: =?UTF-8?B?VGVzdCBTdWJqZWN0?=',
            'Date: Mon, 1 Jan 2024 12:00:00 +0000',
            'Message-ID: <test-123@example.com>',
            'Content-Type: text/plain; charset=utf-8',
            'X-Custom-Header: custom value',
            '',
            'Hello, this is a test email body.'
        ].join('\r\n')
    );

    await t.test('parseEmail returns parsed email object', async () => {
        const parsed = await parseEmail(sampleEmail);

        assert.ok(parsed, 'parsed result should exist');
        assert.ok(parsed.from, 'from should exist');
        assert.ok(parsed.to, 'to should exist');
        assert.ok(parsed.subject, 'subject should exist');
        assert.ok(parsed.text, 'text should exist');
    });

    await t.test('parsed.headerLines exists and has correct format for libmime.decodeHeader', async () => {
        // This tests the specific usage in routes-ui.js:1778
        // headers: parsed.headerLines.map(header => libmime.decodeHeader(header.line))
        const parsed = await parseEmail(sampleEmail);

        assert.ok(Array.isArray(parsed.headerLines), 'headerLines should be an array');
        assert.ok(parsed.headerLines.length > 0, 'headerLines should not be empty');

        // Each headerLine should have 'key' and 'line' properties
        for (const header of parsed.headerLines) {
            assert.ok(typeof header.key === 'string', `header.key should be a string, got ${typeof header.key}`);
            assert.ok(typeof header.line === 'string', `header.line should be a string, got ${typeof header.line}`);
        }

        // Test that libmime.decodeHeader works with header.line (as used in routes-ui.js)
        const decodedHeaders = parsed.headerLines.map(header => libmime.decodeHeader(header.line));
        assert.ok(Array.isArray(decodedHeaders), 'decoded headers should be an array');
        assert.strictEqual(decodedHeaders.length, parsed.headerLines.length, 'should have same number of decoded headers');

        // Find and verify Subject header is decoded correctly
        const subjectIndex = parsed.headerLines.findIndex(h => h.key === 'subject');
        assert.ok(subjectIndex >= 0, 'should find subject header');
        const decodedSubject = decodedHeaders[subjectIndex];
        assert.ok(decodedSubject, 'decoded subject should exist');
    });

    await t.test('headerLines contains expected headers', async () => {
        const parsed = await parseEmail(sampleEmail);

        const headerKeys = parsed.headerLines.map(h => h.key);
        assert.ok(headerKeys.includes('from'), 'should include from header');
        assert.ok(headerKeys.includes('to'), 'should include to header');
        assert.ok(headerKeys.includes('subject'), 'should include subject header');
        assert.ok(headerKeys.includes('date'), 'should include date header');
        assert.ok(headerKeys.includes('message-id'), 'should include message-id header');
        assert.ok(headerKeys.includes('x-custom-header'), 'should include custom header');
    });

    await t.test('headerLines.line contains full header line', async () => {
        const parsed = await parseEmail(sampleEmail);

        const fromHeader = parsed.headerLines.find(h => h.key === 'from');
        assert.ok(fromHeader, 'from header should exist');
        assert.ok(fromHeader.line.includes('From:'), 'from line should contain header name');
        assert.ok(fromHeader.line.includes('sender@example.com'), 'from line should contain value');

        const customHeader = parsed.headerLines.find(h => h.key === 'x-custom-header');
        assert.ok(customHeader, 'custom header should exist');
        assert.ok(customHeader.line.includes('X-Custom-Header:'), 'custom header line should contain header name');
        assert.ok(customHeader.line.includes('custom value'), 'custom header line should contain value');
    });

    await t.test('getHeader retrieves header values', async () => {
        const parsed = await parseEmail(sampleEmail);

        const fromValues = getHeader(parsed.headers, 'from');
        assert.ok(Array.isArray(fromValues), 'getHeader should return array');
        assert.ok(fromValues.length > 0, 'should find from header');

        const toValues = getHeader(parsed.headers, 'to');
        assert.ok(toValues.length > 0, 'should find to header');
    });

    await t.test('getHeader is case-insensitive', async () => {
        const parsed = await parseEmail(sampleEmail);

        const lowerCase = getHeader(parsed.headers, 'from');
        const upperCase = getHeader(parsed.headers, 'FROM');
        const mixedCase = getHeader(parsed.headers, 'From');

        assert.deepStrictEqual(lowerCase, upperCase, 'should match regardless of case');
        assert.deepStrictEqual(lowerCase, mixedCase, 'should match regardless of case');
    });

    await t.test('getHeader handles missing headers', async () => {
        const parsed = await parseEmail(sampleEmail);

        const missing = getHeader(parsed.headers, 'x-nonexistent-header');
        assert.ok(Array.isArray(missing), 'should return array for missing header');
        assert.strictEqual(missing.length, 0, 'should be empty for missing header');
    });

    await t.test('getHeader handles null/undefined headers', async () => {
        const nullResult = getHeader(null, 'from');
        const undefinedResult = getHeader(undefined, 'from');

        assert.ok(Array.isArray(nullResult), 'should return array for null');
        assert.ok(Array.isArray(undefinedResult), 'should return array for undefined');
        assert.strictEqual(nullResult.length, 0, 'should be empty for null');
        assert.strictEqual(undefinedResult.length, 0, 'should be empty for undefined');
    });

    await t.test('hasHeader checks for header existence', async () => {
        const parsed = await parseEmail(sampleEmail);

        assert.strictEqual(hasHeader(parsed.headers, 'from'), true, 'should find from header');
        assert.strictEqual(hasHeader(parsed.headers, 'to'), true, 'should find to header');
        assert.strictEqual(hasHeader(parsed.headers, 'x-nonexistent'), false, 'should not find nonexistent header');
    });

    await t.test('hasHeader is case-insensitive', async () => {
        const parsed = await parseEmail(sampleEmail);

        assert.strictEqual(hasHeader(parsed.headers, 'from'), true);
        assert.strictEqual(hasHeader(parsed.headers, 'FROM'), true);
        assert.strictEqual(hasHeader(parsed.headers, 'From'), true);
    });

    await t.test('hasHeader handles null/undefined headers', async () => {
        assert.strictEqual(hasHeader(null, 'from'), false);
        assert.strictEqual(hasHeader(undefined, 'from'), false);
    });

    await t.test('contentToString converts various content types', async () => {
        const textString = 'Hello World';
        const buffer = Buffer.from('Hello World');
        const uint8Array = new Uint8Array(Buffer.from('Hello World'));
        const arrayBuffer = uint8Array.buffer;

        assert.strictEqual(contentToString(textString), 'Hello World');
        assert.strictEqual(contentToString(buffer), 'Hello World');
        assert.strictEqual(contentToString(uint8Array), 'Hello World');
        assert.strictEqual(contentToString(arrayBuffer), 'Hello World');
    });

    await t.test('contentToString handles empty/null content', async () => {
        assert.strictEqual(contentToString(null), '');
        assert.strictEqual(contentToString(undefined), '');
        assert.strictEqual(contentToString(''), '');
    });

    await t.test('contentToBase64 converts various content types', async () => {
        const expected = Buffer.from('Hello World').toString('base64');

        const textString = 'Hello World';
        const buffer = Buffer.from('Hello World');
        const uint8Array = new Uint8Array(Buffer.from('Hello World'));
        const arrayBuffer = uint8Array.buffer;

        assert.strictEqual(contentToBase64(textString), expected);
        assert.strictEqual(contentToBase64(buffer), expected);
        assert.strictEqual(contentToBase64(uint8Array), expected);
        assert.strictEqual(contentToBase64(arrayBuffer), expected);
    });

    await t.test('contentToBase64 handles empty/null content', async () => {
        assert.strictEqual(contentToBase64(null), '');
        assert.strictEqual(contentToBase64(undefined), '');
    });

    await t.test('parseEmail with real email fixture', async () => {
        const fs = require('fs');
        const Path = require('path');
        const fixturePath = Path.join(__dirname, 'fixtures', 'bounces', 'gmail.eml');
        const content = await fs.promises.readFile(fixturePath);
        const parsed = await parseEmail(content);

        // Verify headerLines works with real email
        assert.ok(Array.isArray(parsed.headerLines), 'headerLines should be array');
        assert.ok(parsed.headerLines.length > 0, 'should have headers from real email');

        // Verify libmime.decodeHeader works with real headers
        const decodedHeaders = parsed.headerLines.map(header => libmime.decodeHeader(header.line));
        assert.ok(decodedHeaders.length > 0, 'should decode real headers');

        // All headers should decode without throwing
        for (let i = 0; i < decodedHeaders.length; i++) {
            assert.ok(decodedHeaders[i] !== undefined, `header ${i} should decode`);
        }
    });

    await t.test('parseEmail with multipart email containing attachments', async () => {
        const multipartEmail = Buffer.from(
            [
                'From: sender@example.com',
                'To: recipient@example.com',
                'Subject: Multipart Test',
                'MIME-Version: 1.0',
                'Content-Type: multipart/mixed; boundary="boundary123"',
                '',
                '--boundary123',
                'Content-Type: text/plain',
                '',
                'Text body',
                '--boundary123',
                'Content-Type: text/html',
                '',
                '<p>HTML body</p>',
                '--boundary123',
                'Content-Type: application/octet-stream',
                'Content-Disposition: attachment; filename="test.bin"',
                '',
                'binary content',
                '--boundary123--'
            ].join('\r\n')
        );

        const parsed = await parseEmail(multipartEmail);

        assert.ok(parsed.text, 'should have text');
        assert.ok(parsed.html, 'should have html');
        assert.ok(Array.isArray(parsed.attachments), 'should have attachments array');

        // Verify headerLines still works
        assert.ok(Array.isArray(parsed.headerLines), 'headerLines should be array');
        const decodedHeaders = parsed.headerLines.map(header => libmime.decodeHeader(header.line));
        assert.ok(decodedHeaders.length > 0, 'should decode headers');
    });

    await t.test('parseEmail with encoded headers', async () => {
        const encodedEmail = Buffer.from(
            [
                'From: =?UTF-8?B?VGVzdCBTZW5kZXI=?= <sender@example.com>',
                'To: recipient@example.com',
                'Subject: =?UTF-8?Q?Test_with_=C3=A9ncoding?=',
                'Content-Type: text/plain',
                '',
                'Body'
            ].join('\r\n')
        );

        const parsed = await parseEmail(encodedEmail);

        assert.ok(Array.isArray(parsed.headerLines), 'headerLines should be array');

        // Verify libmime can decode encoded headers
        const subjectHeader = parsed.headerLines.find(h => h.key === 'subject');
        assert.ok(subjectHeader, 'should find subject header');

        const decoded = libmime.decodeHeader(subjectHeader.line);
        assert.ok(decoded, 'should decode encoded subject');
    });
});
