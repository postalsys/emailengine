'use strict';

// The self-signed certificate builder (lib/tls/self-signed.js and its DER writer).
//
// EmailEngine mints one X.509 certificate itself, so that a listener with TLS switched on always
// has something to serve. A certificate that parses is not the same thing as a certificate that
// works, so these tests do both: the structure is asserted field by field, and then a real TLS
// handshake is completed against a real Node client. The handshake is the one that would have
// caught every encoding mistake this module could make.
//
// Pure: no Redis, no server.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const tls = require('tls');
const net = require('net');

const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
const der = require('../lib/tls/der');

/**
 * Completes a TLS handshake against a listener serving `material`, with the client trusting only
 * that certificate.
 *
 * @param {Object} material `{ cert, privateKey }`
 * @param {string} servername SNI name to request and verify against
 * @returns {Promise<Object>} `{ authorized, authorizationError, protocol }`
 */
async function handshake(material, servername) {
    const server = tls.createServer({ cert: material.cert, key: material.privateKey }, socket => socket.end('ok'));

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
        return await new Promise((resolve, reject) => {
            const socket = tls.connect({ port, host: '127.0.0.1', servername, ca: [material.cert] }, () => {
                const result = {
                    authorized: socket.authorized,
                    authorizationError: socket.authorizationError,
                    protocol: socket.getProtocol()
                };
                socket.end();
                resolve(result);
            });
            socket.on('error', reject);
        });
    } finally {
        server.close();
    }
}

test('DER length octets use the short form below 128 and the long form above it', () => {
    assert.deepEqual([...der.encodeLength(0)], [0]);
    assert.deepEqual([...der.encodeLength(127)], [127]);
    assert.deepEqual([...der.encodeLength(128)], [0x81, 128]);
    assert.deepEqual([...der.encodeLength(256)], [0x82, 1, 0]);
    assert.deepEqual([...der.encodeLength(65536)], [0x83, 1, 0, 0]);
});

test('DER integers stay non-negative', () => {
    // A value whose top bit is set gains a leading zero, or it would decode as negative.
    assert.deepEqual([...der.integer(Buffer.from([0x80]))], [0x02, 0x02, 0x00, 0x80]);
    // Redundant leading zeros are stripped: DER admits exactly one encoding.
    assert.deepEqual([...der.integer(Buffer.from([0x00, 0x00, 0x01]))], [0x02, 0x01, 0x01]);
    assert.deepEqual([...der.integer(2)], [0x02, 0x01, 0x02]);
});

test('object identifiers encode their arcs in base 128', () => {
    // 2.5.29.17 (subjectAltName): first two arcs share an octet, 29 and 17 fit in one each.
    assert.deepEqual([...der.oid('2.5.29.17')], [0x06, 0x03, 0x55, 0x1d, 0x11]);
    // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption) exercises multi-octet arcs.
    assert.deepEqual([...der.oid('1.2.840.113549.1.1.11')], [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
});

test('times use UTCTime through 2049 and GeneralizedTime after it', () => {
    // RFC 5280 4.1.2.5: the representation depends on the year, and a certificate that outlives
    // 2049 encoded as UTCTime would read as 1950.
    assert.equal(der.time(new Date('2026-09-08T12:00:00Z')).subarray(0, 1)[0], 0x17);
    assert.equal(der.time(new Date('2026-09-08T12:00:00Z')).subarray(2).toString('latin1'), '260908120000Z');
    assert.equal(der.time(new Date('2051-01-02T03:04:05Z')).subarray(0, 1)[0], 0x18);
    assert.equal(der.time(new Date('2051-01-02T03:04:05Z')).subarray(2).toString('latin1'), '20510102030405Z');
});

test('named bit strings drop their trailing zero bits', () => {
    // KeyUsage digitalSignature (0) + keyEncipherment (2): one octet, five unused bits.
    assert.deepEqual([...der.namedBits([0, 2])], [0x03, 0x02, 5, 0xa0]);
    // digitalSignature alone: seven unused bits.
    assert.deepEqual([...der.namedBits([0])], [0x03, 0x02, 7, 0x80]);
});

test('IP addresses encode to four or sixteen octets', () => {
    assert.deepEqual([...der.ipToBuffer('192.0.2.10')], [192, 0, 2, 10]);

    const v6 = der.ipToBuffer('2001:db8::1');
    assert.equal(v6.length, 16);
    assert.equal(v6.toString('hex'), '20010db8000000000000000000000001');

    // A compressed middle and an IPv4-mapped tail both have to expand to the same sixteen octets.
    assert.equal(der.ipToBuffer('::1').toString('hex'), '00000000000000000000000000000001');
    assert.equal(der.ipToBuffer('::ffff:192.0.2.1').toString('hex'), '00000000000000000000ffffc0000201');
    assert.equal(der.ipToBuffer('not an address'), false);
});

test('a generated certificate carries the fields RFC 5280 requires of a server certificate', async () => {
    const result = await createSelfSignedCertificate({ hostnames: ['mail.example.com', 'smtp.example.com'] });
    const x509 = new crypto.X509Certificate(result.cert);

    assert.equal(x509.subject, 'O=EmailEngine self-signed\nCN=mail.example.com');
    assert.equal(x509.issuer, x509.subject, 'self-signed: issuer and subject are the same name');
    assert.equal(x509.subjectAltName, 'DNS:mail.example.com, DNS:smtp.example.com');

    // Deliberately a leaf, not an authority. A key that sits on a mail server must not be one that
    // is allowed to sign other certificates.
    assert.equal(x509.ca, false);

    assert.ok(x509.verify(x509.publicKey), 'the signature verifies against its own public key');
    assert.ok(x509.checkHost('smtp.example.com'), 'every listed name is matched');
    assert.equal(x509.checkHost('other.example.com'), undefined, 'and no other name is');
});

test('the certificate is valid from before it was generated', async () => {
    // A certificate that is not valid yet fails a handshake exactly like an expired one, and the
    // machine that generates this is often the one whose clock is wrong.
    const now = new Date('2026-09-08T12:00:00Z');
    const result = await createSelfSignedCertificate({ hostnames: ['mail.example.com'], now });

    assert.ok(result.validFrom.getTime() < now.getTime(), 'backdated');
    assert.ok(result.validTo.getTime() > now.getTime() + 300 * 24 * 3600 * 1000, 'and lives about a year');
});

test('IP addresses are covered as iPAddress names, not as text', async () => {
    // An IP-only deployment is exactly the case the self-signed fallback exists for, and a client
    // matches an address against the iPAddress entry, never against a dNSName that looks like one.
    const result = await createSelfSignedCertificate({ hostnames: ['192.0.2.10', '2001:db8::1'] });
    const x509 = new crypto.X509Certificate(result.cert);

    assert.ok(x509.checkIP('192.0.2.10'));
    assert.ok(x509.checkIP('2001:db8::1'));
    assert.equal(x509.checkIP('198.51.100.1'), undefined, 'and no other address is');
});

test('an RSA certificate completes a real TLS handshake', async () => {
    const result = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
    const outcome = await handshake(result, 'mail.example.com');

    assert.equal(outcome.authorized, true, outcome.authorizationError && outcome.authorizationError.message);
    assert.equal(result.keyType, 'rsa');
});

test('an EC certificate completes a real TLS handshake', async () => {
    const result = await createSelfSignedCertificate({ hostnames: ['mail.example.com'], keyType: 'ec' });
    const outcome = await handshake(result, 'mail.example.com');

    assert.equal(outcome.authorized, true, outcome.authorizationError && outcome.authorizationError.message);
    assert.equal(result.keyType, 'ec');
    assert.equal(new crypto.X509Certificate(result.cert).publicKey.asymmetricKeyType, 'ec');
});

test('a handshake against the wrong name fails verification', async () => {
    const result = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

    await assert.rejects(
        () => handshake(result, 'other.example.com'),
        err => /altnames|Hostname/i.test(err.message),
        'a certificate that matched any name would be worse than no certificate'
    );
});

test('an existing private key is reused rather than replaced', async () => {
    // Regenerating the certificate for a new hostname must not invalidate a pinned key when the
    // caller has one to keep.
    const first = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
    const second = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'], privateKey: first.privateKey });

    assert.equal(second.privateKey, first.privateKey);
    assert.notEqual(second.fingerprint, first.fingerprint, 'but it is a different certificate');
});

test('serial numbers are unique per certificate', async () => {
    const first = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
    const second = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

    assert.notEqual(first.serialNumber, second.serialNumber);
});

test('a certificate cannot be generated without a hostname', async () => {
    await assert.rejects(() => createSelfSignedCertificate({ hostnames: [] }), /without a hostname/);
    await assert.rejects(() => createSelfSignedCertificate({}), /without a hostname/);
});

test('hostnames are normalized', async () => {
    const result = await createSelfSignedCertificate({ hostnames: ['  MAIL.Example.COM  ', '', null] });

    assert.deepEqual(result.altNames, ['mail.example.com']);
    assert.ok(new crypto.X509Certificate(result.cert).checkHost('mail.example.com'));
});

test('an internationalized hostname is encoded as its A-label', async () => {
    // A dNSName is an IA5String. Writing the Unicode bytes produces a certificate that parses and
    // then matches nothing, because a TLS client compares against the A-label the DNS uses.
    const result = await createSelfSignedCertificate({ hostnames: ['põdra.example.com', 'mail.example.com'] });
    const x509 = new crypto.X509Certificate(result.cert);

    assert.equal(x509.subjectAltName, 'DNS:xn--pdra-0qa.example.com, DNS:mail.example.com');
    assert.ok(x509.checkHost('xn--pdra-0qa.example.com'));
    assert.match(x509.subject, /CN=xn--pdra-0qa\.example\.com/);
});

test('a very long hostname still produces a usable certificate', async () => {
    // The Common Name is capped at 64 characters; the name that is actually matched lives in the
    // subjectAltName, which has no such bound.
    const long = `${'a'.repeat(60)}.${'b'.repeat(60)}.example.com`;
    const result = await createSelfSignedCertificate({ hostnames: [long] });
    const x509 = new crypto.X509Certificate(result.cert);

    assert.ok(x509.checkHost(long), 'the full name is matched through the SAN');
    assert.ok(net.isIP(long) === 0);
});
