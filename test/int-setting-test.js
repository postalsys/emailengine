'use strict';

// lib/utils/int-setting.js, the whole-number readers shared by the overridable settings, the token
// audit log and the webhook retry policy.

const test = require('node:test');
const assert = require('node:assert').strict;

const { asPositiveInt, asNonNegativeInt, boundedInt } = require('../lib/utils/int-setting');
const { forAll, gen } = require('./helpers/property');

// anything a setting or an environment variable could hold
const anyValue = gen.withEdges(
    random => {
        const kind = gen.integer(0, 3)(random);
        if (kind === 0) {
            return gen.integer(-1000, 1000)(random);
        }
        if (kind === 1) {
            return gen.integer(-1000, 1000)(random) / 7;
        }
        if (kind === 2) {
            return String(gen.integer(-50, 5000)(random));
        }
        return gen.string('abc0123456789 .-', 0, 5)(random);
    },
    ['', ' ', null, undefined, NaN, Infinity, -Infinity, '0', 0, -0, '1e3', true, false, [], {}]
);

test('asPositiveInt', async t => {
    await t.test('reads whole numbers of at least 1, floors fractions', () => {
        assert.strictEqual(asPositiveInt('42'), 42);
        assert.strictEqual(asPositiveInt(3.9), 3);
        assert.strictEqual(asPositiveInt('1e3'), 1000);
        for (const value of [0, '0', -1, '', null, undefined, 'abc', 0.5, Infinity]) {
            assert.strictEqual(asPositiveInt(value), undefined, String(value));
        }
    });

    await t.test('property: an answer is always a whole number of at least 1', () => {
        forAll(anyValue, value => {
            const parsed = asPositiveInt(value);
            return parsed === undefined || (Number.isInteger(parsed) && parsed >= 1);
        });
    });
});

test('asNonNegativeInt', async t => {
    await t.test('zero is a value, a blank is not', () => {
        assert.strictEqual(asNonNegativeInt(0), 0);
        assert.strictEqual(asNonNegativeInt('0'), 0);
        for (const value of ['', null, undefined, -1, 'x']) {
            assert.strictEqual(asNonNegativeInt(value), undefined, String(value));
        }
    });

    await t.test('property: an answer is always a whole number of at least 0', () => {
        forAll(anyValue, value => {
            const parsed = asNonNegativeInt(value);
            return parsed === undefined || (Number.isInteger(parsed) && parsed >= 0);
        });
    });
});

test('boundedInt', async t => {
    await t.test('clamps a whole number into the range, defaults anything else', () => {
        assert.strictEqual(boundedInt(5, 10, 1, 20), 5);
        assert.strictEqual(boundedInt(50, 10, 1, 20), 20);
        assert.strictEqual(boundedInt(-5, 10, 1, 20), 1);
        assert.strictEqual(boundedInt('7', 10, 1, 20), 7);
        for (const value of ['', null, undefined, 2.5, 'x']) {
            assert.strictEqual(boundedInt(value, 10, 1, 20), 10, String(value));
        }
    });

    await t.test('property: always inside the range', () => {
        forAll(anyValue, value => {
            const parsed = boundedInt(value, 10, 1, 20);
            return Number.isInteger(parsed) && parsed >= 1 && parsed <= 20;
        });
    });
});
