'use strict';

// Property-based testing without a dependency: a seeded generator and a runner that checks an
// invariant over many generated inputs and, when one fails, reports the seed and the case so the run
// can be repeated exactly.
//
//   const { forAll, gen } = require('./helpers/property');
//   forAll(gen.integer(0, 100), value => assert.ok(f(value) >= 0));
//
// Runs are deterministic: the seed is fixed unless EE_PROPERTY_SEED is set, and EE_PROPERTY_RUNS
// raises the number of cases for a longer local hunt (`EE_PROPERTY_RUNS=100000 node --test ...`).

const DEFAULT_SEED = 0x5eed;
const DEFAULT_RUNS = 500;

/**
 * mulberry32: small, fast and good enough to spread test inputs, not for anything else
 * @param {number} seed
 * @returns {Function} Returns a float in [0, 1)
 */
function createRandom(seed) {
    let state = seed >>> 0;
    return () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

// A generator is a function of the random source returning one value
const gen = {
    integer: (min, max) => random => min + Math.floor(random() * (max - min + 1)),
    oneOf: values => random => values[Math.floor(random() * values.length)],
    boolean: () => random => random() < 0.5,
    // Mostly values from the range, sometimes one of the edge cases given
    withEdges: (generator, edges) => random => (random() < 0.2 ? edges[Math.floor(random() * edges.length)] : generator(random)),
    array: (generator, minLength, maxLength) => random => {
        const length = minLength + Math.floor(random() * (maxLength - minLength + 1));
        return Array.from({ length }, () => generator(random));
    },
    record: shape => random => Object.fromEntries(Object.entries(shape).map(([key, generator]) => [key, generator(random)])),
    string: (alphabet, minLength, maxLength) => random => {
        const length = minLength + Math.floor(random() * (maxLength - minLength + 1));
        let out = '';
        for (let i = 0; i < length; i++) {
            out += alphabet[Math.floor(random() * alphabet.length)];
        }
        return out;
    }
};

/**
 * Checks `property` for `runs` generated inputs. A property fails by throwing (an assertion) or by
 * returning false. Async properties are supported: the result is then a promise
 * @param {Function} generator - See `gen`
 * @param {Function} property - Called with each generated value
 * @param {Object} [opts]
 * @param {number} [opts.runs]
 * @param {number} [opts.seed]
 * @returns {void|Promise<void>}
 */
function forAll(generator, property, opts = {}) {
    const seed = Number(process.env.EE_PROPERTY_SEED) || opts.seed || DEFAULT_SEED;
    const runs = Number(process.env.EE_PROPERTY_RUNS) || opts.runs || DEFAULT_RUNS;
    const random = createRandom(seed);

    const fail = (index, value, err) => {
        const error = new Error(
            `Property failed on case ${index + 1}/${runs} (EE_PROPERTY_SEED=${seed}): ${JSON.stringify(value)}\n${err ? err.message : 'returned false'}`
        );
        error.cause = err;
        throw error;
    };

    const values = Array.from({ length: runs }, () => generator(random));

    for (let i = 0; i < values.length; i++) {
        let result;
        try {
            result = property(values[i]);
        } catch (err) {
            fail(i, values[i], err);
        }
        if (result && typeof result.then === 'function') {
            // finish the rest asynchronously, in order
            return (async () => {
                for (let j = i; j < values.length; j++) {
                    let outcome;
                    try {
                        outcome = j === i ? await result : await property(values[j]);
                    } catch (err) {
                        fail(j, values[j], err);
                    }
                    if (outcome === false) {
                        fail(j, values[j]);
                    }
                }
            })();
        }
        if (result === false) {
            fail(i, values[i]);
        }
    }
}

module.exports = { forAll, gen, createRandom };
