'use strict';

// MurmurHash3, the x86 32-bit variant, over the UTF-8 bytes of a string.
//
// The output is load-bearing: tools.getRendezvousScore() ranks IMAP workers and local addresses
// with it, so the hash decides which worker owns an account and which source address it connects
// from. A different hash would move every account to another worker and another source IP on
// upgrade. The result must stay bit-identical to the `murmurhash` package's v3() this replaced,
// which test/murmurhash3-test.js pins with vectors recorded from that package.

const C1 = 0xcc9e2d51;
const C2 = 0x1b873593;

function rotl32(x, r) {
    return (x << r) | (x >>> (32 - r));
}

function mixK1(k1) {
    k1 = Math.imul(k1, C1);
    k1 = rotl32(k1, 15);
    return Math.imul(k1, C2);
}

/**
 * @param {string|Uint8Array} key Input, strings are hashed as UTF-8
 * @param {number} [seed=0] 32-bit seed
 * @returns {number} Unsigned 32-bit hash
 */
function murmurhash3(key, seed) {
    const bytes = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    const length = bytes.length;
    const tail = length & ~3;

    let h1 = seed >>> 0;

    for (let i = 0; i < tail; i += 4) {
        const k1 = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
        h1 ^= mixK1(k1);
        h1 = rotl32(h1, 13);
        h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
    }

    let k1 = 0;
    switch (length & 3) {
        case 3:
            k1 ^= bytes[tail + 2] << 16;
        // falls through
        case 2:
            k1 ^= bytes[tail + 1] << 8;
        // falls through
        case 1:
            k1 ^= bytes[tail];
            h1 ^= mixK1(k1);
    }

    h1 ^= length;
    h1 ^= h1 >>> 16;
    h1 = Math.imul(h1, 0x85ebca6b);
    h1 ^= h1 >>> 13;
    h1 = Math.imul(h1, 0xc2b2ae35);
    h1 ^= h1 >>> 16;

    return h1 >>> 0;
}

module.exports = { murmurhash3 };
