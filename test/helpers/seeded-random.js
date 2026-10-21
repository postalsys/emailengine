'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): a small seeded pseudo-random
// generator for property-style tests. A test that draws hundreds of inputs from it covers far more
// of an input space than a handful of hand-picked cases, and the fixed seed keeps every run, and
// every failure, reproducible: a failing case reports the seed and the index it was drawn at.
//
// mulberry32: not cryptographic, fast, and good enough to spread test inputs.

/**
 * @param {number} seed - 32-bit seed
 * @returns {Object} Generator with value-drawing helpers
 */
function seededRandom(seed) {
    let state = seed >>> 0;

    const next = () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };

    const random = {
        seed,
        // a float in [0, 1)
        next,
        // an integer in [min, max]
        int: (min, max) => min + Math.floor(next() * (max - min + 1)),
        // one element of the list
        pick: list => list[Math.floor(next() * list.length)],
        // true with the given probability
        chance: probability => next() < probability,
        // a string of the given length from the alphabet
        string: (length, alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789') => {
            let out = '';
            for (let i = 0; i < length; i++) {
                out += alphabet[Math.floor(next() * alphabet.length)];
            }
            return out;
        }
    };

    return random;
}

/**
 * Runs `check` for `runs` inputs drawn from `generate`, and names the seed and run of the first
 * failure so it can be replayed
 * @param {Object} options
 * @param {number} options.seed - Seed for the generator
 * @param {number} options.runs - How many inputs to try
 * @param {Function} options.generate - (random) => input
 * @param {Function} options.check - (input) => void, throws on a failed property
 */
function forAll({ seed, runs, generate, check }) {
    const random = seededRandom(seed);
    for (let run = 0; run < runs; run++) {
        const input = generate(random);
        try {
            check(input);
        } catch (err) {
            err.message = `property failed for seed ${seed}, run ${run}, input ${JSON.stringify(input)}: ${err.message}`;
            throw err;
        }
    }
}

module.exports = { seededRandom, forAll };
