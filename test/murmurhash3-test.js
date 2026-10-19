'use strict';

// lib/utils/murmurhash3.js decides which IMAP worker owns an account and which local address it
// connects from (tools.getRendezvousScore), so its output must never change. The vectors below were
// recorded from the `murmurhash` package's v3() before it was replaced; "hello" and the pangram are
// also the published MurmurHash3_x86_32 reference values for seed 0.

const test = require('node:test');
const assert = require('node:assert').strict;

const { murmurhash3 } = require('../lib/utils/murmurhash3');

const VECTORS = [
    ['', 0],
    ['a', 1009084850],
    ['ab', 2613040991],
    ['abc', 3017643002],
    ['abcd', 1139631978],
    ['abcde', 3902511862],
    ['hello', 613153351],
    ['The quick brown fox jumps over the lazy dog', 776992547],
    ['1\x00account-1', 2942472957],
    ['2\x00account-1', 3899279571],
    ['3\x00account-1', 4091153460],
    ['4\x00account-1', 2993243661],
    ['127.0.0.1\x00abc123def456ghi7', 1661168481],
    ['192.168.1.10\x00abc123def456ghi7', 2935908820],
    ['2001:db8::1\x00abc123def456ghi7', 2955891543],
    ['\x00', 1364076727],
    ['\x00key', 1755434456],
    ['õäöü\x00ümlaut', 2831183314],
    ['🙂\x00emoji-account', 180741118],
    ['x'.repeat(257), 905101788]
];

test('murmurhash3', async t => {
    await t.test('matches the recorded vectors, covering every tail length and multi-byte UTF-8', () => {
        for (const [input, expected] of VECTORS) {
            assert.strictEqual(murmurhash3(input), expected, `hash of ${JSON.stringify(input.length > 40 ? input.slice(0, 40) + '...' : input)}`);
        }
    });

    await t.test('hashes a string as its UTF-8 bytes', () => {
        for (const [input, expected] of VECTORS) {
            assert.strictEqual(murmurhash3(Buffer.from(input, 'utf-8')), expected);
        }
    });

    await t.test('treats a missing seed as 0 and applies an explicit one', () => {
        assert.strictEqual(murmurhash3('hello', 0), murmurhash3('hello'));
        // recorded from the murmurhash package's v3('hello', 1)
        assert.strictEqual(murmurhash3('hello', 1), 0xbb4abcad);
    });

    await t.test('always returns an unsigned 32-bit integer', () => {
        for (let i = 0; i < 1000; i++) {
            const hash = murmurhash3(`key-${i}`);
            assert.ok(Number.isInteger(hash) && hash >= 0 && hash <= 0xffffffff, `${hash}`);
        }
    });
});
