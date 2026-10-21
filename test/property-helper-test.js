'use strict';

// test/helpers/property.js, the seeded property runner other tests use: it has to be deterministic
// and has to name the seed and the failing case, or a failure could not be repeated.

const test = require('node:test');
const assert = require('node:assert').strict;

const { forAll, gen, createRandom } = require('./helpers/property');

test('property helper', async t => {
    await t.test('the same seed gives the same sequence', () => {
        const a = createRandom(42);
        const b = createRandom(42);
        const c = createRandom(43);
        const first = Array.from({ length: 5 }, a);
        assert.deepStrictEqual(first, Array.from({ length: 5 }, b));
        assert.notDeepStrictEqual(first, Array.from({ length: 5 }, c));
        assert.ok(first.every(value => value >= 0 && value < 1));
    });

    await t.test('integer() stays inside its bounds and reaches both ends', () => {
        const seen = new Set();
        forAll(gen.integer(3, 7), value => {
            seen.add(value);
            return Number.isInteger(value) && value >= 3 && value <= 7;
        });
        assert.deepStrictEqual([...seen].sort(), [3, 4, 5, 6, 7]);
    });

    await t.test('a failing property reports the seed and the case', () => {
        assert.throws(
            () => forAll(gen.integer(0, 100), value => value < 90, { seed: 7 }),
            err => /EE_PROPERTY_SEED=7/.test(err.message) && /Property failed on case \d+\/\d+/.test(err.message)
        );
    });

    await t.test('async properties are awaited in order', async () => {
        const order = [];
        await forAll(
            gen.integer(0, 1000),
            async value => {
                await new Promise(resolve => setImmediate(resolve));
                order.push(value);
            },
            { runs: 20 }
        );
        assert.strictEqual(order.length, 20);
        await assert.rejects(
            forAll(gen.integer(0, 10), async () => false, { runs: 3 }),
            /returned false/
        );
    });
});
