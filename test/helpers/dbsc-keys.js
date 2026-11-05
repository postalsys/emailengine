'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): the browser's side of a
// device-bound session for the DBSC tests. A key pair stands in for the one Chrome keeps in the
// device's security hardware, and proofs are signed the way Chrome signs them: a compact JWS with
// `typ: dbsc+jwt`, the public JWK in the header on registration only, and ES256 signatures as raw
// r||s rather than the DER Node produces by default.

const crypto = require('crypto');

const b64 = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

/**
 * @param {'ES256'|'RS256'} [alg]
 * @param {number} [bits] - RSA modulus length
 * @returns {{ alg: string, privateKey: Object, jwk: Object }}
 */
function browserKey(alg = 'ES256', bits = 2048) {
    const pair = alg === 'ES256' ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }) : crypto.generateKeyPairSync('rsa', { modulusLength: bits });
    return { alg, privateKey: pair.privateKey, jwk: pair.publicKey.export({ format: 'jwk' }) };
}

/**
 * Signs a JWS over any header and payload, for building malformed proofs too
 * @param {Object} key - from browserKey()
 * @param {Object} header
 * @param {Object|string} payload
 * @returns {string}
 */
function signJws(key, header, payload) {
    const input = `${b64(header)}.${b64(payload)}`;
    const signature =
        key.alg === 'ES256'
            ? crypto.sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
            : crypto.sign('sha256', Buffer.from(input), key.privateKey);
    return `${input}.${signature.toString('base64url')}`;
}

/**
 * A proof over a challenge, as Chrome sends it
 * @param {Object} key - from browserKey()
 * @param {string} jti - the challenge
 * @param {Object} [opts]
 * @param {boolean} [opts.registration] - carry the public key in the header, as on registration
 * @param {Object} [opts.payload] - extra payload members (authorization)
 * @returns {string}
 */
function signProof(key, jti, { registration = false, payload = {} } = {}) {
    const header = { alg: key.alg, typ: 'dbsc+jwt' };
    if (registration) {
        header.jwk = key.jwk;
    }
    return signJws(key, header, Object.assign({ jti }, payload));
}

module.exports = { browserKey, signJws, signProof, b64 };
