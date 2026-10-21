'use strict';

// The unit conversions behind the settings fields shown in days and megabytes. The round trip is
// checked over a seeded sweep of values rather than a handful of picks: whatever a form shows has to
// mean the same thing when it is submitted back unchanged.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    secondsToDays,
    daysToSeconds,
    bytesToMegabytes,
    megabytesToBytes,
    toFormValue,
    fromFormValue,
    msToSeconds,
    secondsToMs
} = require('../lib/ui-routes/overridable-fields');
const { createRandom: prng } = require('./helpers/property');

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

test('the webhook retry delay is shown in seconds and stored in milliseconds', () => {
    assert.strictEqual(toFormValue('webhooksRetryDelay', 5000), 5);
    assert.strictEqual(fromFormValue('webhooksRetryDelay', 5), 5000);
    assert.strictEqual(fromFormValue('webhooksRetryDelay', 2.5), 2500);
    assert.strictEqual(msToSeconds(null), null);
    assert.strictEqual(secondsToMs(null), null);
    // a whole number of seconds survives the round trip
    for (let seconds = 1; seconds <= 3600; seconds += 37) {
        assert.strictEqual(toFormValue('webhooksRetryDelay', fromFormValue('webhooksRetryDelay', seconds)), seconds);
    }
    // a key without a unit is passed as it is
    assert.strictEqual(toFormValue('notifyText', true), true);
    assert.strictEqual(fromFormValue('notifyText', 'x'), 'x');
});
