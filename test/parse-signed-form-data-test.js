'use strict';

// Unit tests for tools.parseSignedFormData - the sole integrity control on the public hosted
// authentication form (/accounts/new*). Covers the security-critical negative paths that were
// previously untested: signature rejection, TTL expiry, single-use nonce replay, and the
// fail-closed behavior when the service secret is empty (verification must NOT be skipped).

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');

const Joi = require('joi');
const tools = require('../lib/tools');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { signedFormBlobFields } = require('../lib/schemas');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX, MAX_FORM_TTL, NONCE_BYTES } = require('../lib/consts');

const SECRET = 'test-service-secret-parse-signed-form';
const gt = { gettext: s => s };

let prevSecret;
const nonceKeys = [];

const is403 = err => !!(err && err.isBoom && err.output && err.output.statusCode === 403);
const freshNonce = () => crypto.randomBytes(NONCE_BYTES).toString('base64url');
// asIs=true so the test controls the exact signed payload (including n/t).
const sign = (obj, secret = SECRET) => tools.getSignedFormDataSync(secret, obj, true);

test.before(async () => {
    prevSecret = await settings.get('serviceSecret');
    await settings.set('serviceSecret', SECRET);
});

registerRedisTeardown(redis, async () => {
    for (const key of nonceKeys) {
        try {
            await redis.del(key);
        } catch (err) {
            // ignore
        }
    }
    try {
        // Restore the original state. set() refuses to persist a blank serviceSecret, so an absent
        // original must be restored with a direct hdel rather than set('').
        if (prevSecret) {
            await settings.set('serviceSecret', prevSecret);
        } else {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'serviceSecret');
        }
    } catch (err) {
        // ignore
    }
});

test('parseSignedFormData', async t => {
    await t.test('accepts a valid signature with fresh nonce + timestamp', async () => {
        const n = freshNonce();
        const { data, signature } = sign({ account: 'psfd-valid', n, t: Date.now() });
        const parsed = await tools.parseSignedFormData(redis, { data, sig: signature }, gt);
        assert.equal(parsed.account, 'psfd-valid');
        assert.equal(parsed.n, n);
    });

    await t.test('rejects tampered data (signature no longer matches)', async () => {
        const n = freshNonce();
        const good = sign({ account: 'psfd-good', n, t: Date.now() });
        const tampered = sign({ account: 'psfd-EVIL', n, t: Date.now() });
        await assert.rejects(tools.parseSignedFormData(redis, { data: tampered.data, sig: good.signature }, gt), is403);
    });

    await t.test('rejects a missing signature', async () => {
        const n = freshNonce();
        const { data } = sign({ account: 'psfd-nosig', n, t: Date.now() });
        await assert.rejects(tools.parseSignedFormData(redis, { data }, gt), is403);
    });

    await t.test('rejects a wrong signature', async () => {
        const n = freshNonce();
        const { data } = sign({ account: 'psfd-wrongsig', n, t: Date.now() });
        await assert.rejects(tools.parseSignedFormData(redis, { data, sig: 'not-the-right-signature' }, gt), is403);
    });

    await t.test('rejects an expired timestamp', async () => {
        const n = freshNonce();
        const expiredT = Date.now() - MAX_FORM_TTL; // older than MAX_FORM_TTL - 60s
        const { data, signature } = sign({ account: 'psfd-expired', n, t: expiredT });
        await assert.rejects(tools.parseSignedFormData(redis, { data, sig: signature }, gt), is403);
    });

    await t.test('rejects a replayed (already consumed) nonce', async () => {
        const n = freshNonce();
        const { data, signature } = sign({ account: 'psfd-replay', n, t: Date.now() });
        const key = `${REDIS_PREFIX}account:form:${n}`;
        nonceKeys.push(key);
        await redis.set(key, '1');
        await assert.rejects(tools.parseSignedFormData(redis, { data, sig: signature }, gt), is403);
    });

    await t.test('requireNonce rejects a blob missing n or t, accepts a complete one', async () => {
        // The connection/create endpoints pass { requireNonce: true } so a signature-only blob (no
        // single-use nonce) cannot be replayed. A blob missing n (or t) is rejected even though its
        // signature is valid; a full n+t blob is accepted.
        const noNonce = sign({ account: 'psfd-no-nonce', t: Date.now() });
        await assert.rejects(tools.parseSignedFormData(redis, { data: noNonce.data, sig: noNonce.signature }, gt, { requireNonce: true }), is403);

        const noTs = sign({ account: 'psfd-no-ts', n: freshNonce() });
        await assert.rejects(tools.parseSignedFormData(redis, { data: noTs.data, sig: noTs.signature }, gt, { requireNonce: true }), is403);

        const full = sign({ account: 'psfd-require-ok', n: freshNonce(), t: Date.now() });
        const parsed = await tools.parseSignedFormData(redis, { data: full.data, sig: full.signature }, gt, { requireNonce: true });
        assert.equal(parsed.account, 'psfd-require-ok');
    });

    await t.test('verifyServiceSignature returns true only for a matching signature', async () => {
        const { data, signature } = sign({ account: 'psfd-vss', n: freshNonce(), t: Date.now() });
        const decoded = Buffer.from(data, 'base64url').toString();
        assert.equal(await tools.verifyServiceSignature(decoded, signature), true);
        assert.equal(await tools.verifyServiceSignature(decoded, 'wrong-signature'), false);
        assert.equal(await tools.verifyServiceSignature(decoded, undefined), false);
    });

    await t.test('fails closed when the service secret is empty (regenerates, does not skip)', async () => {
        // Force the stored secret absent (a direct hdel - set() now refuses to blank serviceSecret, which
        // is the guard exercised by settings-coupling-test.js). getServiceSecret() must regenerate a fresh
        // secret, so a blob signed with the empty secret is rejected rather than silently accepted.
        await redis.hdel(`${REDIS_PREFIX}settings`, 'serviceSecret');
        const n = freshNonce();
        const forged = sign({ account: 'psfd-forged', n, t: Date.now() }, '');
        await assert.rejects(tools.parseSignedFormData(redis, { data: forged.data, sig: forged.signature }, gt), is403);

        const healed = await settings.get('serviceSecret');
        assert.ok(healed && healed.length > 0, 'getServiceSecret should have persisted a fresh secret');

        // Restore the known secret for any later runs in this process.
        await settings.set('serviceSecret', SECRET);
    });
});

test('signedFormBlobFields (shared hosted-form data/sig fragment)', async t => {
    // The shared fragment (lib/schemas.js) is what stops the hosted-form endpoints from drifting on
    // their security-relevant data/sig validation. Guard the contract: both are required base64url.
    const schema = Joi.object(signedFormBlobFields);

    await t.test('accepts a well-formed data + sig pair', () => {
        const { error } = schema.validate({ data: 'AAAA', sig: 'BBBB' });
        assert.ok(!error, error && error.message);
    });

    await t.test('rejects a missing sig (required, not optional)', () => {
        const { error } = schema.validate({ data: 'AAAA' });
        assert.ok(error, 'sig must be required so it cannot silently drift back to optional');
    });

    await t.test('rejects a missing data', () => {
        const { error } = schema.validate({ sig: 'BBBB' });
        assert.ok(error, 'data must be required');
    });
});
