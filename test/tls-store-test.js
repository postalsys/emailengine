'use strict';

// The TLS material store (lib/tls/store.js): what a listener may serve, and in what order.
//
// The precedence this module states is the fix for a bug that had no symptom: the SMTP server and
// the IMAP proxy loaded their environment certificate and then overwrote it with whatever Let's
// Encrypt had provisioned, so an operator who pinned a certificate through the environment was
// silently served a different one. The resolution order is asserted here and in
// test/tls-context-test.js, which exercises it through the object a listener is actually handed.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

// Set the test Redis prefix before anything opens a connection. The secret is what makes the
// at-rest encryption assertions meaningful: with none configured, encrypt() is a passthrough.
process.env.EENGINE_REDIS_PREFIX = 'test_tls_store';
process.env.EENGINE_SECRET = 'tls-store-test-secret';

const store = require('../lib/tls/store');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');

/**
 * A certificate and key pair to feed the upload path, generated with the same builder the fallback
 * uses so the test needs no fixtures on disk.
 *
 * @param {string[]} hostnames Names to cover
 * @returns {Promise<Object>} `{ cert, privateKey }`
 */
async function pair(hostnames) {
    return await createSelfSignedCertificate({ hostnames });
}

test('TLS material store', async t => {
    t.after(async () => {
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length) {
            await redis.del(keys);
        }
        redis.quit();
        // Requiring lib/settings opens connections that outlive the tests; see tools-test.js
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(async () => {
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length) {
            await redis.del(keys);
        }
    });

    await t.test('splitPemChain() takes a bundle apart', async () => {
        const first = await pair(['a.example.com']);
        const second = await pair(['b.example.com']);

        // Operators paste leaf and chain into one field about as often as they use separate ones.
        const chain = store.splitPemChain(`${first.cert}\n${second.cert}`);
        assert.equal(chain.length, 2);
        assert.ok(chain[0].includes('BEGIN CERTIFICATE'));
        assert.deepEqual(store.splitPemChain('not a certificate'), []);
        assert.deepEqual(store.splitPemChain(null), []);
    });

    await t.test('certificateCovers() answers for names, addresses and nothing else', async () => {
        const material = await pair(['mail.example.com', '192.0.2.10']);

        assert.equal(store.certificateCovers(material.cert, 'mail.example.com'), true);
        assert.equal(store.certificateCovers(material.cert, '192.0.2.10'), true);
        assert.equal(store.certificateCovers(material.cert, 'other.example.com'), false);
        assert.equal(store.certificateCovers('garbage', 'mail.example.com'), false);
        assert.equal(store.certificateCovers(material.cert, ''), false);
    });

    await t.test('describeCertificate() reports the fields the UI renders', async () => {
        const material = await pair(['mail.example.com', 'smtp.example.com']);
        const described = store.describeCertificate(material.cert);

        assert.deepEqual(described.altNames, ['mail.example.com', 'smtp.example.com']);
        assert.equal(described.selfSigned, true);
        assert.equal(described.fingerprint, material.fingerprint);
        assert.ok(described.validTo instanceof Date);
        assert.equal(store.describeCertificate('garbage'), false);
    });

    await t.test('getCertificateHostnames() puts the service hostname first', async () => {
        await settings.set('serviceUrl', 'https://mail.example.com');
        await settings.set('tlsHostnames', ['smtp.example.com', 'mail.example.com', 'imap.example.com']);

        // The service hostname is implicit and must not appear twice when it is also listed.
        assert.deepEqual(await store.getCertificateHostnames(), ['mail.example.com', 'smtp.example.com', 'imap.example.com']);
    });

    await t.test('getCertificateHostnames() survives a missing or unparseable service URL', async () => {
        // Reachable through the API and through EENGINE_SETTINGS, and it used to crash both the
        // SMTP worker and the IMAP proxy with "Invalid URL" before either could report anything.
        await settings.set('serviceUrl', null);
        await settings.set('tlsHostnames', ['smtp.example.com']);
        assert.deepEqual(await store.getCertificateHostnames(), ['smtp.example.com']);

        await settings.set('tlsHostnames', null);
        assert.deepEqual(await store.getCertificateHostnames(), []);
    });

    await t.test('getCertificateHostnames() unwraps an IPv6 literal', async () => {
        await settings.set('serviceUrl', 'https://[2001:db8::1]');
        await settings.set('tlsHostnames', null);

        // A URL keeps the brackets; a certificate name does not.
        assert.deepEqual(await store.getCertificateHostnames(), ['2001:db8::1']);
    });

    await t.test('acmeEligibleHostnames() keeps only names a CA could validate', () => {
        assert.deepEqual(
            store.acmeEligibleHostnames([
                'mail.example.com',
                '192.0.2.10',
                '2001:db8::1',
                'localhost',
                'mailserver',
                'mail.local',
                'mail.lan',
                'mail.internal',
                'mail.home.arpa'
            ]),
            ['mail.example.com']
        );
    });

    await t.test('setManualCertificate() stores a valid pair and reports it back', async () => {
        const material = await pair(['mail.example.com']);

        const stored = await store.setManualCertificate({ cert: material.cert, privateKey: material.privateKey });
        assert.equal(stored.source, 'manual');
        assert.deepEqual(stored.altNames, ['mail.example.com']);

        const loaded = await store.getManualCertificate();
        assert.equal(loaded.cert, material.cert);
        assert.equal(loaded.source, 'manual');
        assert.ok(loaded.privateKey.includes('PRIVATE KEY'));
    });

    await t.test('an uploaded private key is encrypted at rest', async () => {
        const material = await pair(['mail.example.com']);
        await store.setManualCertificate({ cert: material.cert, privateKey: material.privateKey });

        const raw = JSON.parse(await redis.hget(store.TLS_KEY, store.MANUAL_FIELD));
        assert.ok(!raw.privateKey.includes('PRIVATE KEY'), 'the stored value is not the PEM');
        assert.match(raw.privateKey, /^\$/, 'and carries the encryption marker');
        assert.ok(raw.cert.includes('BEGIN CERTIFICATE'), 'the certificate itself is public, so it is stored as-is');
    });

    await t.test('setManualCertificate() takes the chain from either field', async () => {
        const leaf = await pair(['mail.example.com']);
        const intermediate = await pair(['ca.example.com']);

        await store.setManualCertificate({ cert: `${leaf.cert}${intermediate.cert}`, privateKey: leaf.privateKey });
        assert.equal((await store.getManualCertificate()).ca.length, 1);

        await store.setManualCertificate({ cert: leaf.cert, ca: intermediate.cert, privateKey: leaf.privateKey });
        assert.equal((await store.getManualCertificate()).ca.length, 1);
    });

    await t.test('setManualCertificate() refuses a key that does not match the certificate', async () => {
        const material = await pair(['mail.example.com']);
        const other = await pair(['mail.example.com']);

        // Stored and then discovered at the next restart is the wrong time to find this out: the
        // listener would be down and the page would still show a certificate as installed.
        await assert.rejects(() => store.setManualCertificate({ cert: material.cert, privateKey: other.privateKey }), /does not belong/);
        assert.equal(await store.getManualCertificate(), false, 'and nothing is stored');
    });

    await t.test('setManualCertificate() refuses input that is not PEM', async () => {
        const material = await pair(['mail.example.com']);

        await assert.rejects(() => store.setManualCertificate({ cert: 'hello', privateKey: material.privateKey }), /PEM encoded/);
        await assert.rejects(() => store.setManualCertificate({ cert: material.cert, privateKey: 'hello' }), /private key/i);
    });

    await t.test('setManualCertificate() reads a passphrase protected key and stores it without one', async () => {
        const material = await pair(['mail.example.com']);
        const encryptedKey = crypto
            .createPrivateKey(material.privateKey)
            .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'hunter2' })
            .toString();

        // Keeping the passphrase would mean storing it next to what it protects; the value is
        // encrypted at rest with the instance secret instead.
        await assert.rejects(() => store.setManualCertificate({ cert: material.cert, privateKey: encryptedKey }), /passphrase/i);

        await store.setManualCertificate({ cert: material.cert, privateKey: encryptedKey, passphrase: 'hunter2' });
        const loaded = await store.getManualCertificate();
        assert.ok(loaded.privateKey.includes('BEGIN PRIVATE KEY'), 'stored unencrypted at the PEM level');
        assert.ok(!loaded.privateKey.includes('ENCRYPTED'));
    });

    await t.test('deleteManualCertificate() removes it', async () => {
        const material = await pair(['mail.example.com']);
        await store.setManualCertificate({ cert: material.cert, privateKey: material.privateKey });

        await store.deleteManualCertificate();
        assert.equal(await store.getManualCertificate(), false);
    });

    await t.test('getSelfSignedCertificate() generates once and reuses what it stored', async () => {
        const first = await store.getSelfSignedCertificate(['mail.example.com']);
        const second = await store.getSelfSignedCertificate(['mail.example.com']);

        // Regenerating on every call would break whoever pinned the fingerprint.
        assert.equal(second.fingerprint, first.fingerprint);
        assert.equal(first.source, 'self-signed');
        assert.ok(store.certificateCovers(first.cert, 'mail.example.com'));
    });

    await t.test('getSelfSignedCertificate() replaces one that no longer covers the configured names', async () => {
        const first = await store.getSelfSignedCertificate(['mail.example.com']);
        const second = await store.getSelfSignedCertificate(['mail.example.com', 'smtp.example.com']);

        assert.notEqual(second.fingerprint, first.fingerprint);
        assert.ok(store.certificateCovers(second.cert, 'smtp.example.com'));
    });

    await t.test('getSelfSignedCertificate() falls back to localhost when nothing is configured', async () => {
        const material = await store.getSelfSignedCertificate([]);

        // A listener with TLS switched on and no service URL still has to start.
        assert.ok(store.certificateCovers(material.cert, store.FALLBACK_HOSTNAME));
    });

    await t.test('the self-signed private key is encrypted at rest', async () => {
        await store.getSelfSignedCertificate(['mail.example.com']);

        const raw = JSON.parse(await redis.hget(store.TLS_KEY, store.SELF_SIGNED_FIELD));
        assert.match(raw.privateKey, /^\$/);
    });

    await t.test('two workers generating at once agree on one certificate', async () => {
        // Whoever loses the race reads back the winner's rather than serving a second certificate
        // that nobody pinned.
        const results = await Promise.all([
            store.getSelfSignedCertificate(['mail.example.com']),
            store.getSelfSignedCertificate(['mail.example.com']),
            store.getSelfSignedCertificate(['mail.example.com'])
        ]);

        assert.equal(new Set(results.map(entry => entry.fingerprint)).size, 1);
    });

    await t.test('two workers replacing a stale certificate at once agree on one', async () => {
        // HSETNX converged concurrent first creation, and replacement looked like the same thing:
        // delete the stale record, then create. It is not. Between the delete and the create every
        // other worker sees an empty field and wins its own create, so a hostname change - which
        // fans a certificate reload out to the API, SMTP and IMAP proxy workers at once - could
        // leave each of them serving a certificate of its own while the admin page showed whichever
        // one wrote last, and a client pinning that fingerprint reached a worker with another.
        await store.getSelfSignedCertificate(['old.example.com']);

        const names = ['mail.example.com'];

        // The interleaving that produced two live certificates: both workers read the same stale
        // record, and the second is suspended between its read and its write for as long as the
        // first takes to finish. Modelled on the read, so it holds whatever the write is.
        let firstDone;
        const firstFinished = new Promise(resolve => (firstDone = resolve));
        let reads = 0;

        const originalHget = redis.hget.bind(redis);
        redis.hget = async (key, field) => {
            const index = key === store.TLS_KEY && field === store.SELF_SIGNED_FIELD ? reads++ : -1;
            const value = await originalHget(key, field);
            if (index === 1) {
                await firstFinished;
            }
            return value;
        };

        let results;
        try {
            const first = store.getSelfSignedCertificate(names).then(result => {
                firstDone();
                return result;
            });
            const second = store.getSelfSignedCertificate(names);

            results = await Promise.all([first, second]);
        } finally {
            redis.hget = originalHget;
        }

        assert.equal(new Set(results.map(entry => entry.fingerprint)).size, 1, 'both workers serve the same certificate');

        // And it is the one that was stored, not one the loser kept to itself
        const stored = await store.peekSelfSignedCertificate();
        assert.equal(stored.fingerprint, results[0].fingerprint);
        assert.ok(store.certificateCovers(stored.cert, 'mail.example.com'));
    });

    await t.test('coversHostname() does not throw on the SNI path', async () => {
        // checkIP() throws on anything that is not an address, and this is called for every servername
        // a client sends. An exception here fails the handshake rather than falling through to the
        // default context, so the routing by name type is load bearing.
        const material = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const x509 = store.parseCertificate(material.cert);

        assert.equal(store.coversHostname(x509, 'mail.example.com'), true);
        assert.doesNotThrow(() => store.coversHostname(x509, 'not-an-address'));
        assert.doesNotThrow(() => store.coversHostname(x509, '192.0.2.10'));
        assert.doesNotThrow(() => store.coversHostname(x509, 'a b c'));
        assert.equal(store.coversHostname(false, 'mail.example.com'), false);
    });

    await t.test('getAcmeCertificate() only reports a usable record and never orders one', async () => {
        const material = await pair(['mail.example.com']);
        const calls = [];

        const certs = {
            async getCertificate(hostname, skipAcquire) {
                calls.push({ hostname, skipAcquire });
                return { status: 'valid', cert: material.cert, privateKey: material.privateKey, ca: ['chain'] };
            }
        };

        const resolved = await store.getAcmeCertificate(certs, 'mail.example.com');
        assert.equal(resolved.source, 'acme');
        assert.deepEqual(resolved.ca, ['chain']);

        // A listener starting up must not block on a certificate authority.
        assert.deepEqual(calls, [{ hostname: 'mail.example.com', skipAcquire: true }]);
    });

    await t.test('getAcmeCertificate() ignores a pending, failed or missing record', async () => {
        const pending = {
            async getCertificate() {
                return { status: 'pending' };
            }
        };
        const failing = {
            async getCertificate() {
                throw new Error('redis is down');
            }
        };
        const missing = {
            async getCertificate() {
                return false;
            }
        };

        assert.equal(await store.getAcmeCertificate(pending, 'mail.example.com'), false);
        assert.equal(await store.getAcmeCertificate(failing, 'mail.example.com'), false);
        assert.equal(await store.getAcmeCertificate(missing, 'mail.example.com'), false);
        assert.equal(await store.getAcmeCertificate(null, 'mail.example.com'), false);
    });
});
