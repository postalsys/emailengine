'use strict';

// lib/base32.js: RFC 4648 base32 without padding, used for otpauth: secrets and IMAP proxy
// connection ids. Pure, no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { base32Encode } = require('../lib/base32');

// A bit-string reference encoder, written differently from the module on purpose
function referenceEncode(buf) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = [...buf].map(octet => octet.toString(2).padStart(8, '0')).join('');
    if (bits.length % 5) {
        bits = bits.padEnd(bits.length + 5 - (bits.length % 5), '0');
    }
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
        out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
    }
    return out;
}

test('base32Encode', async t => {
    await t.test('matches the RFC 4648 test vectors, padding removed', () => {
        const vectors = [
            ['', ''],
            ['f', 'MY'],
            ['fo', 'MZXQ'],
            ['foo', 'MZXW6'],
            ['foob', 'MZXW6YQ'],
            ['fooba', 'MZXW6YTB'],
            ['foobar', 'MZXW6YTBOI']
        ];
        for (const [input, expected] of vectors) {
            assert.equal(base32Encode(Buffer.from(input)), expected, JSON.stringify(input));
        }
    });

    await t.test('stays correct past 32 bits of accumulated input', () => {
        // The accumulator is shifted with 32-bit operators; long inputs are where an overflow shows
        const input = Buffer.from(Array.from({ length: 257 }, (v, i) => (i * 37 + 11) & 0xff));
        assert.equal(base32Encode(input), referenceEncode(input));
        assert.equal(base32Encode(Buffer.alloc(40, 0xff)), '7'.repeat(64));
    });

    await t.test('encodes a 20-byte TOTP secret to 32 characters of the alphabet', () => {
        const encoded = base32Encode(Buffer.alloc(20, 0xa5));
        assert.equal(encoded.length, 32);
        assert.match(encoded, /^[A-Z2-7]+$/);
    });
});
