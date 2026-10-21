'use strict';

// lib/parse-message.js: mailparser hashes every attachment by default (MD5, which an OpenSSL FIPS
// provider refuses) and nothing in EmailEngine reads the checksum, so hashing is switched off.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');

const { parseMessage } = require('../lib/parse-message');

const MESSAGE = [
    'From: a@example.com',
    'To: b@example.com',
    'Subject: with attachment',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/plain',
    '',
    'hello',
    '--b1',
    'Content-Type: application/octet-stream; name="data.bin"',
    'Content-Disposition: attachment; filename="data.bin"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('attachment bytes').toString('base64'),
    '--b1--',
    ''
].join('\r\n');

test('parseMessage() parses attachments without hashing them', async t => {
    const created = [];
    t.mock.method(crypto, 'createHash', function (...args) {
        created.push(args[0]);
        return crypto.createHash.mock.original.apply(this, args);
    });

    const parsed = await parseMessage(MESSAGE);

    assert.strictEqual(parsed.attachments.length, 1);
    assert.strictEqual(parsed.attachments[0].content.toString(), 'attachment bytes');
    assert.strictEqual(parsed.attachments[0].checksum, undefined);
    assert.deepStrictEqual(created, [], 'no hash is created, so no algorithm a FIPS host refuses either');
});
