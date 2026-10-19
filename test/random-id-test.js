'use strict';

// lib/utils/random-id.js generates account and gateway ids. They have to keep the format of the
// ids already stored (16 characters of [0-9a-z]) and be unpredictable.

const test = require('node:test');
const assert = require('node:assert').strict;

const { randomId, ID_ALPHABET, ID_LENGTH } = require('../lib/utils/random-id');

test('randomId', async t => {
    await t.test('defaults to 16 characters of lowercase base36', () => {
        assert.strictEqual(ID_ALPHABET, '0123456789abcdefghijklmnopqrstuvwxyz');
        assert.strictEqual(ID_LENGTH, 16);
        for (let i = 0; i < 1000; i++) {
            assert.match(randomId(), /^[0-9a-z]{16}$/);
        }
    });

    await t.test('honours a custom alphabet and size', () => {
        assert.match(randomId('ab', 40), /^[ab]{40}$/);
        assert.strictEqual(randomId('x', 5), 'xxxxx');
        assert.strictEqual(randomId(ID_ALPHABET, 0), '');
    });

    await t.test('does not repeat', () => {
        const seen = new Set();
        for (let i = 0; i < 10000; i++) {
            seen.add(randomId());
        }
        assert.strictEqual(seen.size, 10000);
    });

    await t.test('draws every character uniformly', () => {
        // 36 * 16 * 400 = 230400 draws, so each character is expected 6400 times. A modulo-biased
        // generator over a 256-value byte would favour the first 4 characters by about 14%; this
        // bound is far outside random noise (sigma is about 79) and far inside that bias.
        const counts = new Map([...ID_ALPHABET].map(c => [c, 0]));
        for (let i = 0; i < 36 * 400; i++) {
            for (const c of randomId()) {
                counts.set(c, counts.get(c) + 1);
            }
        }
        for (const [c, count] of counts) {
            assert.ok(Math.abs(count - 6400) < 500, `${c} drawn ${count} times`);
        }
    });
});
