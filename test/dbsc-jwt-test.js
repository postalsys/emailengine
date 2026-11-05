'use strict';

// The proofs of a device-bound admin session (lib/dbsc/jwt.js), signed here with real keys the way
// Chrome signs them: ES256 over a P-256 key whose public half rides in the registration header,
// raw r||s signatures, and the payload { jti, authorization? } observed from Chrome 156.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { verifyRegistrationProof, verifyRefreshProof, MAX_PROOF_LENGTH } = require('../lib/dbsc/jwt');
const exitWhenStandalone = require('./helpers/exit-standalone');
const { browserKey, signJws, b64 } = require('./helpers/dbsc-keys');

// Proofs Chrome 156 sent on macOS on 2026-11-05, signed by a Secure Enclave key: a registration over
// the challenge "reg-challenge-1" with authorization "authz-1", and a refresh over a challenge the
// test server issued. Real browser output, so a change to the parsing that only matches what this
// file's own signer produces still fails here
const CHROME_REGISTRATION =
    'eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkFVX0xuQ1YzS1d0ckRyOFB1ZTFyWHlmbTVoRm1PNlpjaDJ5LVFiWG1ONHMiLCJ5IjoiMkM4OHJ3U1ViNnp6cmQ0TjJpMlo1bkhNQjVhcmtiUGU0alUwMHdHdWhxSSJ9LCJ0eXAiOiJkYnNjK2p3dCJ9.eyJhdXRob3JpemF0aW9uIjoiYXV0aHotMSIsImp0aSI6InJlZy1jaGFsbGVuZ2UtMSJ9.iUGASEZ1659GA3Hd_m9pD3KM4ktu3xj0DTwQxarhhIWWtZ49ydN3U0XMQnCx2VgN-vb_69Dtu3Rhox9luL7dqQ';
const CHROME_REFRESH =
    'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRic2Mrand0In0.eyJqdGkiOiJjYmU1NTMyZTg0MmFhOTYxIn0.9e5R7sHD5TkkC7M1l25JXQ4Rw2CrpSArS7ewDiz8QugbcEQ_CkiX1_DOE6IiQ1vTi0GuMotYSSOkx7gBdMMYBg';

const registration = (key, payload = { jti: 'challenge-1' }, extra = {}) =>
    signJws(key, Object.assign({ alg: key.alg, typ: 'dbsc+jwt', jwk: key.jwk }, extra), payload);

test('the proofs Chrome actually sends', () => {
    const binding = verifyRegistrationProof(CHROME_REGISTRATION);
    assert.equal(binding.alg, 'ES256');
    assert.equal(binding.jti, 'reg-challenge-1');
    assert.equal(binding.authorization, 'authz-1');
    assert.deepEqual(verifyRefreshProof(CHROME_REFRESH, binding), { jti: 'cbe5532e842aa961' });
});

for (const alg of ['ES256', 'RS256']) {
    test(`${alg} proofs`, async t => {
        const key = browserKey(alg);

        await t.test('a registration proof yields the public key and the challenge', () => {
            const result = verifyRegistrationProof(registration(key, { jti: 'challenge-1', authorization: 'a1' }));
            assert.equal(result.alg, alg);
            assert.equal(result.jti, 'challenge-1');
            assert.equal(result.authorization, 'a1');
            assert.equal(result.jwk.kty, alg === 'ES256' ? 'EC' : 'RSA');
            assert.equal(result.jwk.d, undefined, 'no private member is ever kept');
        });

        await t.test('a refresh proof is checked against the stored key, not one it carries', () => {
            const binding = verifyRegistrationProof(registration(key));
            const proof = signJws(key, { alg, typ: 'dbsc+jwt' }, { jti: 'challenge-2' });
            assert.deepEqual(verifyRefreshProof(proof, binding), { jti: 'challenge-2' });

            // Another key signing, and naming itself in the header, is still refused
            const other = browserKey(alg);
            const forged = signJws(other, { alg, typ: 'dbsc+jwt', jwk: other.jwk }, { jti: 'challenge-2' });
            assert.throws(() => verifyRefreshProof(forged, binding), { code: 'DbscInvalidProof' });
        });

        await t.test('a tampered payload is refused', () => {
            const [header, , signature] = registration(key).split('.');
            assert.throws(() => verifyRegistrationProof(`${header}.${b64({ jti: 'other' })}.${signature}`), { code: 'DbscInvalidProof' });
        });

        await t.test('a proof signed by a key other than the one it names is refused', () => {
            const other = browserKey(alg);
            const proof = signJws(other, { alg, typ: 'dbsc+jwt', jwk: key.jwk }, { jti: 'c' });
            assert.throws(() => verifyRegistrationProof(proof), { code: 'DbscInvalidProof' });
        });
    });
}

test('what is never a valid proof', async t => {
    const es = browserKey('ES256');

    await t.test('alg none, and an algorithm outside the two', () => {
        const unsigned = `${b64({ alg: 'none', typ: 'dbsc+jwt' })}.${b64({ jti: 'c' })}.`;
        assert.throws(() => verifyRegistrationProof(unsigned), { code: 'DbscInvalidProof' });
        assert.throws(() => verifyRegistrationProof(registration(es, { jti: 'c' }, { alg: 'HS256' })), { code: 'DbscInvalidProof' });
    });

    await t.test('a token of another type', () => {
        assert.throws(() => verifyRegistrationProof(registration(es, { jti: 'c' }, { typ: 'JWT' })), { code: 'DbscInvalidProof' });
    });

    await t.test('a key that does not match the algorithm', () => {
        const rsa = browserKey('RS256');
        assert.throws(() => verifyRegistrationProof(registration(es, { jti: 'c' }, { jwk: rsa.jwk })), { code: 'DbscInvalidProof' });
        assert.throws(() => verifyRegistrationProof(registration(es, { jti: 'c' }, { jwk: undefined })), { code: 'DbscInvalidProof' });
    });

    await t.test('an RSA key shorter than 2048 bits', () => {
        const weak = browserKey('RS256', 1024);
        assert.throws(() => verifyRegistrationProof(registration(weak)), /too short/);
    });

    await t.test('a refresh proof under a different algorithm than the session registered', () => {
        const binding = verifyRegistrationProof(registration(es));
        const rsa = browserKey('RS256');
        const proof = signJws(rsa, { alg: 'RS256', typ: 'dbsc+jwt' }, { jti: 'c' });
        assert.throws(() => verifyRefreshProof(proof, binding), /does not match the session/);
    });

    await t.test('no challenge, malformed segments, absent or oversized input', () => {
        assert.throws(() => verifyRegistrationProof(registration(es, {})), /no challenge/);
        assert.throws(() => verifyRegistrationProof(registration(es, { jti: 42 })), /no challenge/);
        for (const value of [undefined, '', 'a.b', 'a.b.c.d', '!!.e30.sig', `${b64('[1]')}.${b64({ jti: 'c' })}.sig`, 'x'.repeat(MAX_PROOF_LENGTH + 1)]) {
            assert.throws(() => verifyRegistrationProof(value), { code: 'DbscInvalidProof' }, String(value).slice(0, 20));
        }
    });

    await t.test('an ES256 signature in DER form rather than raw r||s', () => {
        const input = `${b64({ alg: 'ES256', typ: 'dbsc+jwt', jwk: es.jwk })}.${b64({ jti: 'c' })}`;
        const der = crypto.sign('sha256', Buffer.from(input), es.privateKey);
        assert.throws(() => verifyRegistrationProof(`${input}.${der.toString('base64url')}`), { code: 'DbscInvalidProof' });
    });
});

exitWhenStandalone();
