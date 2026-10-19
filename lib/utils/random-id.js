'use strict';

const { randomInt } = require('crypto');

// The alphabet and length of generated account and gateway ids. Kept identical to the nanoid
// customAlphabet() call this replaced, so new ids look like the ones already stored.
const ID_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
const ID_LENGTH = 16;

/**
 * Generates a random string from a CSPRNG. Every character is drawn uniformly from the alphabet
 * (crypto.randomInt rejects out-of-range values instead of taking a biased modulo).
 *
 * @param {string} [alphabet] Characters to draw from
 * @param {number} [size] Length of the result
 * @returns {string}
 */
function randomId(alphabet = ID_ALPHABET, size = ID_LENGTH) {
    let id = '';
    for (let i = 0; i < size; i++) {
        id += alphabet[randomInt(alphabet.length)];
    }
    return id;
}

module.exports = { randomId, ID_ALPHABET, ID_LENGTH };
