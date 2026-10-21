'use strict';

// The unit conversions behind the settings fields shown in days and megabytes. The round trip is
// checked over a seeded sweep of values rather than a handful of picks: whatever a form shows has to
// mean the same thing when it is submitted back unchanged.

const test = require('node:test');
const assert = require('node:assert').strict;

const { secondsToDays, daysToSeconds, bytesToMegabytes, megabytesToBytes } = require('../lib/ui-routes/overridable-fields');

// Small deterministic PRNG (mulberry32), so a failure names a value that reproduces
function prng(seed) {
    return () => {
        seed |= 0;
        seed = (seed + 0x6d2b79f5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

test('blank stays blank in both directions', () => {
    for (const fn of [secondsToDays, daysToSeconds, bytesToMegabytes, megabytesToBytes]) {
        assert.equal(fn(null), null);
        assert.equal(fn(undefined), null);
        assert.equal(fn(NaN), null);
    }
});

test('the defaults convert to round numbers', () => {
    assert.equal(secondsToDays(7 * 24 * 3600), 7);
    assert.equal(daysToSeconds(7), 604800);
    assert.equal(bytesToMegabytes(100 * 1024 * 1024), 100);
    assert.equal(megabytesToBytes(100), 104857600);
});

test('a whole number of days or megabytes survives a round trip exactly', () => {
    const random = prng(20261021);
    for (let i = 0; i < 1000; i++) {
        const days = 1 + Math.floor(random() * 3650);
        assert.equal(secondsToDays(daysToSeconds(days)), days);
        const megabytes = Math.floor(random() * 100000);
        assert.equal(bytesToMegabytes(megabytesToBytes(megabytes)), megabytes);
    }
});

test('a value stored in odd units is shown within the form precision and resubmits close to it', () => {
    const random = prng(1729);
    for (let i = 0; i < 1000; i++) {
        const seconds = 1 + Math.floor(random() * 365 * 24 * 3600);
        const shown = secondsToDays(seconds);
        // two decimals of a day is 864 seconds
        assert.ok(Math.abs(daysToSeconds(shown) - seconds) <= 432, `${seconds}s shown as ${shown} days`);

        const bytes = Math.floor(random() * 10 * 1024 * 1024 * 1024);
        const mb = bytesToMegabytes(bytes);
        assert.ok(Math.abs(megabytesToBytes(mb) - bytes) <= 5243, `${bytes}B shown as ${mb} MB`);
    }
});
