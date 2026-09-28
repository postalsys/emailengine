'use strict';

// lib/pbkdf2-phc.js replaced @phc/pbkdf2 for the admin password. The hashes below were produced
// by @phc/pbkdf2 1.1.14 itself (the last version EmailEngine shipped) through the exact call the
// admin password used, plus the other digests it supports, so every hash already stored in
// `authData`, and every EENGINE_PREPARED_PASSWORD minted before the swap, keeps verifying.

const test = require('node:test');
const assert = require('node:assert').strict;

const { hash, verify } = require('../lib/pbkdf2-phc');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = require('../lib/consts');

const PASSWORD = 'correct horse battery staple';

const PHC_VECTORS = [
    {
        label: 'the admin password parameters (sha256, 600000 iterations, 16 byte salt)',
        password: PASSWORD,
        hash: '$pbkdf2-sha256$i=600000$lidz+ZXVGW9XT/45uzI0hg$3FyfEVfLShV+oS/ZYUFvFh2g7hSWF3fLxAL1DVdrEFQ'
    },
    {
        label: 'sha512, 1000 iterations',
        password: PASSWORD,
        hash: '$pbkdf2-sha512$i=1000$ZGD/1HyoFlTyK0CkELawlA$pYb5sTUhONicCmolfvT5FusXsMVcDPE+LfeeDgUhMMWKpz8Rlj1UijPRXaoeoN3JaJx3SiH08digmSKTET2YIw'
    },
    {
        label: 'sha1, 2000 iterations',
        password: PASSWORD,
        hash: '$pbkdf2-sha1$i=2000$AdpAAR+fSY3HPsbK9hJRIw$2MQU+Xk3mrRdQ4b51FDFJNBy894'
    },
    {
        label: 'sha256, 1000 iterations, 8 byte salt',
        password: PASSWORD,
        hash: '$pbkdf2-sha256$i=1000$jKf9fEPUMa8$uuZWXI3go36YvbaohlIqdSzsgmdfV2cSizuY8R3IC1Q'
    },
    {
        label: 'sha256, 1000 iterations, a password outside ASCII',
        password: 'pässwörd ✓',
        hash: '$pbkdf2-sha256$i=1000$OiHwSK5djOvEP7NV4qV68Q$eeFUXd+rR7cIoA4y3pefE+gTeUnE/t2dior17TorJuo'
    },
    {
        label: 'the old package defaults (sha512, 25000 iterations)',
        password: PASSWORD,
        hash: '$pbkdf2-sha512$i=25000$PRMe3YCZipCx64/9/YlzbA$MhlpAFQ2aq4Z6XQUqHPxaqKJMgv5YvhaxGhJsyJzZIoCGy+hmuzcrAvoutnD2r13iTHkpIVccrQPEg0Vxmj4VA'
    }
];

// The PHC string form: identifier, iteration count, then salt and hash in unpadded base64
const PHC_FORMAT = /^\$pbkdf2-(sha1|sha256|sha512)\$i=[1-9][0-9]*\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/;

test('verify() accepts every hash @phc/pbkdf2 stored and refuses the wrong password', async t => {
    for (const vector of PHC_VECTORS) {
        await t.test(vector.label, async () => {
            assert.equal(await verify(vector.hash, vector.password), true);
            assert.equal(await verify(vector.hash, vector.password + 'x'), false);
            assert.equal(await verify(vector.hash, ''), false);
        });
    }
});

test('hash() writes the pinned format with the admin password parameters by default', async () => {
    const phc = await hash(PASSWORD);

    assert.match(phc, PHC_FORMAT);
    assert.ok(phc.startsWith(`$pbkdf2-${PDKDF2_DIGEST}$i=${PDKDF2_ITERATIONS}$`), phc);

    const [, , , salt, key] = phc.split('$');
    assert.equal(Buffer.from(salt, 'base64').length, PDKDF2_SALT_SIZE);
    assert.equal(Buffer.from(key, 'base64').length, 32, 'a sha256 key is 32 bytes');
    assert.equal(salt.includes('='), false, 'unpadded base64');
    assert.equal(key.includes('='), false, 'unpadded base64');

    assert.equal(await verify(phc, PASSWORD), true);
    assert.equal(await verify(phc, 'not the password'), false);
});

test('hash() honours explicit parameters and two hashes of one password differ by salt', async () => {
    const a = await hash(PASSWORD, { iterations: 1000, saltSize: 8, digest: 'sha512' });
    const b = await hash(PASSWORD, { iterations: 1000, saltSize: 8, digest: 'SHA512' });

    assert.match(a, PHC_FORMAT);
    assert.ok(a.startsWith('$pbkdf2-sha512$i=1000$'), a);
    assert.ok(b.startsWith('$pbkdf2-sha512$i=1000$'), b);
    assert.notEqual(a, b);
    assert.equal(Buffer.from(a.split('$')[3], 'base64').length, 8);
    assert.equal(Buffer.from(a.split('$')[4], 'base64').length, 64, 'a sha512 key is 64 bytes');

    assert.equal(await verify(a, PASSWORD), true);
    assert.equal(await verify(b, PASSWORD), true);

    const sha1 = await hash(PASSWORD, { iterations: 1000, digest: 'sha1' });
    assert.ok(sha1.startsWith('$pbkdf2-sha1$i=1000$'), sha1);
    assert.equal(await verify(sha1, PASSWORD), true);
});

test('hash() rejects parameters the format cannot carry', async () => {
    await assert.rejects(hash(PASSWORD, { iterations: 0 }), TypeError);
    await assert.rejects(hash(PASSWORD, { iterations: 1.5 }), TypeError);
    await assert.rejects(hash(PASSWORD, { iterations: 2 ** 32 }), TypeError);
    await assert.rejects(hash(PASSWORD, { saltSize: 0 }), TypeError);
    await assert.rejects(hash(PASSWORD, { saltSize: 2048 }), TypeError);
    await assert.rejects(hash(PASSWORD, { digest: 'md5' }), TypeError);
});

test('verify() rejects a string that is not a pbkdf2 PHC hash rather than answering false', async () => {
    // The caller treats a rejection as a failed check, so a malformed stored hash can never pass;
    // it is still kept apart from a wrong password, which the old package also answered with false
    for (const malformed of [
        '',
        'plain',
        undefined,
        null,
        '$pbkdf2-sha256$i=1000$abc',
        '$pbkdf2-md5$i=1000$abc$def',
        '$pbkdf2-sha256$i=0$YWJj$ZGVm',
        '$pbkdf2-sha256$i=1000$YWJj=$ZGVm',
        '$pbkdf2-sha256$v=1$i=1000$YWJj$ZGVm',
        '$argon2id$v=19$m=1,t=1,p=1$YWJj$ZGVm'
    ]) {
        await assert.rejects(verify(malformed, PASSWORD), TypeError, JSON.stringify(malformed));
    }

    // an empty derived key would equal an empty expected key for any password
    await assert.rejects(verify('$pbkdf2-sha256$i=1000$YWJj$A', PASSWORD), TypeError);

    // well formed, but the stored key is simply not this password's: false, like the old package
    assert.equal(await verify('$pbkdf2-sha256$i=1000$YWJj$ZGVm', PASSWORD), false);
});
