'use strict';

// Admin password hashing in the PHC string format, on Node's own crypto. Replaces @phc/pbkdf2
// (unmaintained since 2018) and stays byte-compatible with every hash that package stored:
//
//     $pbkdf2-<digest>$i=<iterations>$<salt>$<hash>
//
// with the salt and the derived key in standard base64 without padding. A hash written by an
// earlier release, or handed in through EENGINE_PREPARED_PASSWORD, keeps verifying, and a hash
// written here verifies on an earlier release. test/pbkdf2-phc-test.js pins hashes the old
// package produced.

const crypto = require('crypto');
const { promisify } = require('util');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = require('./consts');

const pbkdf2 = promisify(crypto.pbkdf2);

// Derived key length per digest: the digest's own output size, as the old package used
const DIGESTS = { sha1: 20, sha256: 32, sha512: 64 };
const MAX_UINT32 = 2 ** 32 - 1;
const MAX_SALT_SIZE = 1024;

// Only the four-field form pbkdf2 hashes take. A version field, padded base64 or a foreign
// identifier is a malformed string, which the caller treats as a failed check
const PHC_RE = /^\$pbkdf2-([a-z0-9]+)\$i=(0|[1-9][0-9]*)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

function b64(buf) {
    return buf.toString('base64').replace(/=+$/, '');
}

function digestKeyLength(digest) {
    if (!Object.prototype.hasOwnProperty.call(DIGESTS, digest)) {
        throw new TypeError(`Unsupported ${digest} digest function`);
    }
    return DIGESTS[digest];
}

/**
 * Hashes a password into a PHC string. The defaults are the values EmailEngine has always
 * used for the admin password (lib/consts.js).
 *
 * @param {string} password
 * @param {object} [options]
 * @param {number} [options.iterations]
 * @param {number} [options.saltSize] - Salt length in bytes
 * @param {string} [options.digest] - sha1, sha256 or sha512
 * @returns {Promise<string>}
 */
async function hash(password, options) {
    let { iterations = PDKDF2_ITERATIONS, saltSize = PDKDF2_SALT_SIZE, digest = PDKDF2_DIGEST } = options || {};

    if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_UINT32) {
        throw new TypeError(`The 'iterations' option must be an integer in the range (1 <= iterations <= ${MAX_UINT32})`);
    }
    if (!Number.isInteger(saltSize) || saltSize < 1 || saltSize > MAX_SALT_SIZE) {
        throw new TypeError(`The 'saltSize' option must be an integer in the range (1 <= saltSize <= ${MAX_SALT_SIZE})`);
    }
    digest = String(digest).toLowerCase();
    let keyLength = digestKeyLength(digest);

    let salt = crypto.randomBytes(saltSize);
    let key = await pbkdf2(password, salt, iterations, keyLength, digest);

    return `$pbkdf2-${digest}$i=${iterations}$${b64(salt)}$${b64(key)}`;
}

/**
 * Checks a password against a PHC string. Resolves false for a wrong password and rejects for
 * a string that is not a pbkdf2 PHC hash at all, the same contract the old package had.
 *
 * @param {string} phcString
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function verify(phcString, password) {
    let match = typeof phcString === 'string' ? PHC_RE.exec(phcString) : null;
    if (!match) {
        throw new TypeError('Not a pbkdf2 PHC string');
    }

    let [, digest, iterationsValue, saltValue, hashValue] = match;
    digestKeyLength(digest);

    let iterations = Number(iterationsValue);
    if (iterations < 1 || iterations > MAX_UINT32) {
        throw new TypeError(`The 'i' param must be in the range (1 <= i <= ${MAX_UINT32})`);
    }

    let salt = Buffer.from(saltValue, 'base64');
    let expected = Buffer.from(hashValue, 'base64');
    if (!expected.length) {
        // an empty derived key would compare equal to an empty expected key for any password
        throw new TypeError('No hash found in the given string');
    }

    let derived = await pbkdf2(password, salt, iterations, expected.length, digest);
    return crypto.timingSafeEqual(derived, expected);
}

module.exports = { hash, verify };
