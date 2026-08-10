'use strict';

// RFC 4648 base32 without padding. Replaces the unmaintained base32.js package; output is
// byte-identical to its encoder for the two uses in this codebase (otpauth: URL secrets and
// IMAP proxy connection ids), which never need padding or decoding.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let octet of buf) {
        value = (value << 8) | octet;
        bits += 8;
        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }

    return output;
}

module.exports = { base32Encode };
