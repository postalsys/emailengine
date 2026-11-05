'use strict';

// Verifies the proofs a browser sends for a device-bound admin session (DBSC, see lib/dbsc/): a
// compact JWS with `typ: dbsc+jwt`, signed by the key pair the browser created for the session.
// Pure, and built on Node's own crypto only (no JOSE dependency, see "Pure JavaScript only").
//
// What Chrome sends, observed against Chrome 156 on 2026-11-05 and matching the spec's normative
// list (§9.10, which drops the `aud` and `iat` of one of its own examples):
//   registration: header { alg, typ: 'dbsc+jwt', jwk }, payload { jti, authorization? }
//   refresh:      header { alg, typ: 'dbsc+jwt' },      payload { jti }
// `jti` is the challenge the server issued. Nothing else in the payload is relied on.

const crypto = require('crypto');

// RS256 and ES256 are what the spec lists besides `none`, which binds the session to nothing and
// is refused outright
const ALGORITHMS = Object.freeze(['ES256', 'RS256']);

// A proof is a few hundred bytes; anything far larger is not one, and is refused before parsing
const MAX_PROOF_LENGTH = 8 * 1024;

const MIN_RSA_BITS = 2048;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

function proofError(message) {
    const err = new Error(message);
    err.code = 'DbscInvalidProof';
    err.statusCode = 400;
    return err;
}

function decodeSegment(segment, what) {
    try {
        const value = BASE64URL.test(segment) && JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            return value;
        }
    } catch (err) {
        // reported below like any other malformed segment
    }
    throw proofError(`Malformed proof ${what}`);
}

/**
 * Splits a compact JWS and decodes its header and payload, without checking the signature
 * @param {string} token
 * @returns {{ header: Object, payload: Object, signingInput: Buffer, signature: Buffer }}
 */
function parseProof(token) {
    if (typeof token !== 'string' || !token || token.length > MAX_PROOF_LENGTH) {
        throw proofError('Missing or oversized proof');
    }
    const parts = token.split('.');
    if (parts.length !== 3 || !BASE64URL.test(parts[2])) {
        throw proofError('Malformed proof');
    }
    const header = decodeSegment(parts[0], 'header');
    const payload = decodeSegment(parts[1], 'payload');

    if (header.typ !== 'dbsc+jwt') {
        throw proofError('Not a DBSC proof');
    }
    if (!ALGORITHMS.includes(header.alg)) {
        throw proofError('Unsupported proof algorithm');
    }
    if (typeof payload.jti !== 'string' || !payload.jti) {
        throw proofError('Proof carries no challenge');
    }

    return {
        header,
        payload,
        signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
        signature: Buffer.from(parts[2], 'base64url')
    };
}

/**
 * Reduces a JWK to the public members of the type the algorithm needs, so a stored key can never
 * carry a private member or an unrelated field from the browser
 * @param {string} alg - ES256 or RS256
 * @param {Object} jwk
 * @returns {Object} the public JWK
 */
function publicJwkFor(alg, jwk) {
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
        throw proofError('Proof carries no key');
    }
    if (alg === 'ES256') {
        if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
            throw proofError('Proof key does not match its algorithm');
        }
        return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    }
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
        throw proofError('Proof key does not match its algorithm');
    }
    return { kty: 'RSA', n: jwk.n, e: jwk.e };
}

function importKey(alg, jwk) {
    let key;
    try {
        key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    } catch (err) {
        throw proofError('Proof key is not usable');
    }
    if (alg === 'RS256' && key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS) {
        throw proofError('Proof key is too short');
    }
    return key;
}

function signatureValid(alg, key, signingInput, signature) {
    if (alg === 'ES256') {
        // JWS carries the raw r||s pair, 32 bytes each, not the DER form Node defaults to
        return signature.length === 64 && crypto.verify('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return crypto.verify('sha256', signingInput, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
}

/**
 * Verifies the proof a browser sends to register a session: signed by the key its own header
 * carries, which becomes the session's key
 * @param {string} token
 * @returns {{ alg: string, jwk: Object, jti: string, authorization: string|undefined }}
 */
function verifyRegistrationProof(token) {
    const { header, payload, signingInput, signature } = parseProof(token);
    const jwk = publicJwkFor(header.alg, header.jwk);
    if (!signatureValid(header.alg, importKey(header.alg, jwk), signingInput, signature)) {
        throw proofError('Proof signature does not verify');
    }
    return { alg: header.alg, jwk, jti: payload.jti, authorization: typeof payload.authorization === 'string' ? payload.authorization : undefined };
}

/**
 * Verifies a refresh proof against the key stored when the session registered. A key in the
 * proof's own header is ignored: the spec forbids one on refresh, and honouring it would let any
 * key sign for the session
 * @param {string} token
 * @param {{ alg: string, jwk: Object }} binding - what registration stored
 * @returns {{ jti: string }}
 */
function verifyRefreshProof(token, binding) {
    const { header, payload, signingInput, signature } = parseProof(token);
    if (header.alg !== binding.alg) {
        throw proofError('Proof algorithm does not match the session');
    }
    if (!signatureValid(binding.alg, importKey(binding.alg, publicJwkFor(binding.alg, binding.jwk)), signingInput, signature)) {
        throw proofError('Proof signature does not verify');
    }
    return { jti: payload.jti };
}

module.exports = { verifyRegistrationProof, verifyRefreshProof, ALGORITHMS, MAX_PROOF_LENGTH };
