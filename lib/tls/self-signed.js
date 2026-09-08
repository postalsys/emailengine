'use strict';

// Builds the self-signed certificate a TLS listener falls back to.
//
// EmailEngine used to promise this and not do it: the admin UI showed a "Self-signed" badge and
// said one would be used, while nothing anywhere generated one. What actually happened once the
// built-in key pairs were removed from smtp-server and imap-core (they shipped in every copy of
// those libraries, so a listener "secured" by one was readable by anyone) is that a TLS listener
// with no certificate refused to start, and the worker crash-looped. The promise is kept here
// instead of withdrawn, because the alternative to a warning badge is an outage.
//
// This certificate is generated on the instance, is unique to it, and its key is encrypted at rest
// like every other secret. That is the whole difference from the shipped key pairs, and it is the
// difference that matters: nobody else has this key. It is still self-signed, so a client either
// pins the fingerprint the admin UI shows or accepts an unverified certificate. Nothing here
// claims otherwise.

const crypto = require('crypto');
const net = require('net');
const punycode = require('punycode.js');
const { promisify } = require('util');

const generateKeyPair = promisify(crypto.generateKeyPair);

const {
    sequence,
    set,
    octetString,
    bitString,
    boolean,
    nullValue,
    utf8String,
    explicit,
    implicit,
    integer,
    oid,
    time,
    namedBits,
    ipToBuffer,
    readTlv
} = require('./der');

// RFC 5280 object identifiers, named so the structure below reads like the specification.
const OID_COMMON_NAME = '2.5.4.3';
const OID_ORGANIZATION = '2.5.4.10';
const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
const OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const OID_EXT_SUBJECT_ALT_NAME = '2.5.29.17';
const OID_EXT_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_EXT_KEY_USAGE = '2.5.29.15';
const OID_EXT_EXT_KEY_USAGE = '2.5.29.37';
const OID_EXT_SUBJECT_KEY_ID = '2.5.29.14';
const OID_KP_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

// KeyUsage bit positions.
const KEY_USAGE_DIGITAL_SIGNATURE = 0;
const KEY_USAGE_KEY_ENCIPHERMENT = 2;

// A year, less than the 398 days the CA/Browser Forum allows a public certificate to live. The
// value only matters to whoever pinned the fingerprint: a shorter life means more re-pinning, a
// longer one means a listener that quietly stops working years from now.
const DEFAULT_VALIDITY_DAYS = 365;

// Clock skew allowance. A certificate that is not valid yet fails a handshake exactly like an
// expired one, and the machine that generates this is often the one with the wrong clock.
const BACKDATE_MS = 60 * 60 * 1000;

const ORGANIZATION = 'EmailEngine self-signed';

/**
 * Certificate name with a single Common Name attribute, plus a fixed organization so the origin of
 * the certificate is legible in any inspection tool.
 *
 * The Common Name is vestigial for verification (no TLS client may match on it any more), but an
 * empty subject renders as blank in every UI, so it carries the primary hostname. Its upper bound
 * is 64 characters, which a long hostname can exceed; the name that is actually matched lives in
 * the subjectAltName extension, so truncating here loses nothing.
 *
 * @param {string} commonName Primary hostname
 * @returns {Buffer} Encoded Name
 */
function encodeName(commonName) {
    return sequence([
        set([sequence([oid(OID_ORGANIZATION), utf8String(ORGANIZATION)])]),
        set([sequence([oid(OID_COMMON_NAME), utf8String(commonName.slice(0, 64))])])
    ]);
}

/**
 * The A-label form of a hostname, which is what goes on the wire. Unchanged for an all-ASCII name.
 *
 * @param {string} hostname Name, possibly internationalized
 * @returns {string} ASCII-compatible encoding
 */
function toAsciiHostname(hostname) {
    try {
        return punycode.toASCII(hostname);
    } catch (err) {
        return hostname;
    }
}

/**
 * subjectAltName, the extension a TLS client actually matches the hostname against.
 *
 * @param {string[]} hostnames Names and IP addresses to cover
 * @returns {Buffer} Encoded GeneralNames
 */
function encodeSubjectAltName(hostnames) {
    const entries = [];

    for (const hostname of hostnames) {
        if (net.isIP(hostname)) {
            const address = ipToBuffer(hostname);
            if (address) {
                entries.push(implicit(7, address));
            }
            continue;
        }

        // A dNSName is an IA5String, so an internationalized name has to go in as its A-label.
        // Writing the Unicode bytes produces a certificate that parses and matches nothing.
        entries.push(implicit(2, Buffer.from(toAsciiHostname(hostname), 'latin1')));
    }

    return sequence(entries);
}

/**
 * One Extension of the extensions list.
 *
 * @param {string} extnId Extension OID
 * @param {boolean} critical Whether a client that does not understand it must reject the certificate
 * @param {Buffer} value The extension's own DER
 * @returns {Buffer} Encoded Extension
 */
function extension(extnId, critical, value) {
    const parts = [oid(extnId)];
    if (critical) {
        parts.push(boolean(true));
    }
    parts.push(octetString(value));
    return sequence(parts);
}

/**
 * The public key bits out of a SubjectPublicKeyInfo, which is what a subject key identifier is the
 * SHA-1 of. SPKI is `SEQUENCE { AlgorithmIdentifier, BIT STRING }`, so this steps over the first
 * element and drops the BIT STRING's unused-bit count.
 *
 * @param {Buffer} spki DER SubjectPublicKeyInfo
 * @returns {Buffer} The public key bit string contents
 */
function publicKeyBits(spki) {
    const outer = readTlv(spki);
    const algorithm = readTlv(spki, outer.contentStart);
    const keyBits = readTlv(spki, algorithm.end);
    return spki.subarray(keyBits.contentStart + 1, keyBits.end);
}

function toPem(der, label) {
    const body = der.toString('base64').replace(/.{1,64}/g, line => `${line}\n`);
    return `-----BEGIN ${label}-----\n${body}-----END ${label}-----\n`;
}

/**
 * Generates the private key the certificate is signed with.
 *
 * RSA by default, matching the choice @postalsys/certs makes for ACME keys and for the same reason:
 * this key terminates TLS for IMAP and SMTP clients as well as browsers, and RSA is the safer
 * assumption there. Nothing downstream depends on the two being byte-identical - both are read back
 * with crypto.createPrivateKey().
 *
 * @param {string} keyType 'rsa' (default) or 'ec'
 * @returns {Promise<string>} PEM private key
 */
async function generatePrivateKey(keyType) {
    if (keyType === 'ec') {
        const { privateKey } = await generateKeyPair('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'sec1', format: 'pem' }
        });
        return privateKey;
    }

    const { privateKey } = await generateKeyPair('rsa', {
        modulusLength: 2048,
        publicExponent: 65537,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });

    return privateKey;
}

/**
 * Mints a self-signed server certificate.
 *
 * Deliberately a leaf and not a certificate authority: `basicConstraints` says CA:FALSE and there
 * is no keyCertSign. `openssl req -x509` defaults the other way, which makes a certificate that can
 * be dropped into a trust store more readily, but it also mints a certificate that is allowed to
 * sign others - and this key sits on a mail server, not in a safe. Whoever wants to trust it pins
 * the fingerprint.
 *
 * @param {Object} opts
 * @param {string[]} opts.hostnames Names and IP addresses the certificate covers; the first is the subject
 * @param {string} [opts.keyType] 'rsa' (default) or 'ec'
 * @param {number} [opts.validityDays] Lifetime in days
 * @param {string} [opts.privateKey] Reuse an existing PEM key instead of generating one
 * @param {Date} [opts.now] Clock, for tests
 * @returns {Promise<Object>} `{ cert, privateKey, fingerprint, serialNumber, altNames, validFrom, validTo }`
 */
async function createSelfSignedCertificate(opts) {
    const options = opts || {};

    const hostnames = []
        .concat(options.hostnames || [])
        .map(hostname => (hostname || '').toString().trim().toLowerCase())
        .filter(hostname => hostname);

    if (!hostnames.length) {
        throw new Error('Can not generate a certificate without a hostname');
    }

    const keyType = options.keyType === 'ec' ? 'ec' : 'rsa';
    const privateKeyPem = options.privateKey || (await generatePrivateKey(keyType));
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

    const now = options.now || new Date();
    const validFrom = new Date(now.getTime() - BACKDATE_MS);
    const validTo = new Date(now.getTime() + (options.validityDays || DEFAULT_VALIDITY_DAYS) * 24 * 3600 * 1000);

    const signatureAlgorithm = keyType === 'ec' ? sequence([oid(OID_ECDSA_WITH_SHA256)]) : sequence([oid(OID_SHA256_WITH_RSA), nullValue()]);

    // An EC key signs; it never encrypts a key exchange, so keyEncipherment would be a usage the
    // certificate cannot honour.
    const keyUsageBits = keyType === 'ec' ? [KEY_USAGE_DIGITAL_SIGNATURE] : [KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_KEY_ENCIPHERMENT];

    const name = encodeName(net.isIP(hostnames[0]) ? hostnames[0] : toAsciiHostname(hostnames[0]));

    const tbsCertificate = sequence([
        // [0] EXPLICIT version, 2 meaning v3. Extensions do not exist before v3.
        explicit(0, integer(2)),
        integer(crypto.randomBytes(16)),
        signatureAlgorithm,
        name,
        sequence([time(validFrom), time(validTo)]),
        name,
        spki,
        explicit(
            3,
            sequence([
                extension(OID_EXT_BASIC_CONSTRAINTS, true, sequence([])),
                extension(OID_EXT_KEY_USAGE, true, namedBits(keyUsageBits)),
                extension(OID_EXT_EXT_KEY_USAGE, false, sequence([oid(OID_KP_SERVER_AUTH)])),
                extension(OID_EXT_SUBJECT_ALT_NAME, false, encodeSubjectAltName(hostnames)),
                extension(OID_EXT_SUBJECT_KEY_ID, false, octetString(crypto.createHash('sha1').update(publicKeyBits(spki)).digest()))
            ])
        )
    ]);

    const signature = crypto.sign('sha256', tbsCertificate, privateKey);
    const der = sequence([tbsCertificate, signatureAlgorithm, bitString(signature)]);

    const cert = toPem(der, 'CERTIFICATE');
    const x509 = new crypto.X509Certificate(cert);

    return {
        cert,
        privateKey: privateKeyPem,
        keyType,
        serialNumber: x509.serialNumber,
        fingerprint: x509.fingerprint,
        altNames: hostnames,
        validFrom: new Date(x509.validFrom),
        validTo: new Date(x509.validTo)
    };
}

module.exports = { createSelfSignedCertificate, DEFAULT_VALIDITY_DAYS };
