'use strict';

// Where a TLS listener's certificate comes from, and in what order.
//
// EmailEngine has four possible sources and, until this module existed, no agreement between them.
// The SMTP server and the IMAP proxy each loaded their environment certificate and then overwrote
// it with whatever Let's Encrypt had provisioned, so an operator who pinned a certificate through
// the environment was silently overridden by an automatic one. The admin UI, meanwhile, described a
// self-signed fallback that did not exist.
//
// The order is now stated once, here, and every listener asks this module:
//
//   1. environment or config file, per listener (EENGINE_SMTP_TLS_*, [api.tls], ...). An explicit
//      instruction from the operator outranks anything EmailEngine decided on its own.
//   2. a certificate uploaded through the admin UI, when it covers the name being served.
//   3. the Let's Encrypt certificate for that name.
//   4. a self-signed certificate covering every configured name.
//
// Only 2 and 4 are stored here, in EmailEngine's own `tls` hash. Let's Encrypt records stay in the
// @postalsys/certs store, which owns their lifecycle. Private keys in both places are encrypted
// with the instance secret and are re-encrypted by the rotation pass in encrypt.js.

const crypto = require('crypto');
const net = require('net');
const { isDeepStrictEqual } = require('node:util');

const { redis } = require('../db');
const settings = require('../settings');
const getSecret = require('../get-secret');
const { encrypt, decrypt } = require('../encrypt');
const { REDIS_PREFIX } = require('../consts');
const { createSelfSignedCertificate } = require('./self-signed');

const TLS_KEY = `${REDIS_PREFIX}tls`;

const MANUAL_FIELD = 'manual';
const SELF_SIGNED_FIELD = 'selfSigned';

// A self-signed certificate is replaced this long before it expires. Generous, because replacing
// one invalidates whatever pinned its fingerprint and there is no reason to cut it fine.
const SELF_SIGNED_RENEW_BEFORE = 30 * 24 * 3600 * 1000;

// The name a self-signed certificate is issued to when nothing better is known. A listener with no
// service URL still has to start, and "localhost" is at least true for the loopback case that
// configuration usually means.
const FALLBACK_HOSTNAME = 'localhost';

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/**
 * Splits a PEM bundle into its certificates. Operators paste leaf and chain into one field about as
 * often as they use separate ones, so both have to work.
 *
 * @param {string} pem One or more concatenated PEM certificates
 * @returns {string[]} Normalized PEM blocks
 */
function splitPemChain(pem) {
    return ((pem || '').toString().match(PEM_BLOCK) || []).map(block => `${block.replace(/\r\n/g, '\n').trim()}\n`);
}

/**
 * Parses a PEM certificate, or reports that it does not parse.
 *
 * Callers that ask about a certificate more than once parse it here and keep the result: the SNI
 * callback is on the accept path of three listeners, so a parse per handshake is a parse per
 * client connection.
 *
 * @param {string} cert PEM certificate
 * @returns {Object|false} An X509Certificate, or false
 */
function parseCertificate(cert) {
    if (!cert) {
        return false;
    }

    try {
        return new crypto.X509Certificate(cert);
    } catch (err) {
        return false;
    }
}

/**
 * Does this certificate cover this name? Wildcards and IP addresses included, which is why it asks
 * Node rather than comparing the subjectAltName strings itself.
 *
 * @param {Object|false} x509 Parsed certificate
 * @param {string} hostname Name to check
 * @returns {boolean} True when the certificate may be served for that name
 */
function coversHostname(x509, hostname) {
    if (!x509 || !hostname) {
        return false;
    }

    // Routed by what the name is, not tried in turn: checkIP() throws on anything that is not an
    // address, and this runs inside the SNI callback, where a throw would fail the handshake of
    // every client connecting by hostname.
    return !!(net.isIP(hostname) ? x509.checkIP(hostname) : x509.checkHost(hostname));
}

/**
 * Certificate metadata in the shape the admin UI and the listener status use.
 *
 * @param {string} cert PEM certificate
 * @returns {Object|false} Parsed fields, or false when the PEM does not parse
 */
function describeCertificate(cert) {
    return describeX509(parseCertificate(cert));
}

/**
 * The same metadata from a certificate that is already parsed. Split out for the callers that hold
 * one: the SNI path parses every certificate it serves, and describing it from the PEM again means
 * a second parse of the same bytes.
 *
 * @param {Object|false} x509 Parsed certificate
 * @returns {Object|false} Parsed fields, or false when there was no certificate
 */
function describeX509(x509) {
    if (!x509) {
        return false;
    }

    // subjectAltName is a display string. Node quotes an entry containing a comma or a quote, so
    // the quotes come back off after the split - this list is what the admin UI shows as "Covers",
    // and a crafted certificate should not be able to make it read as something else. Nothing
    // decides coverage from this: that is coversHostname(), which asks OpenSSL.
    const altNames = String(x509.subjectAltName || '')
        .split(',')
        .map(entry => entry.trim())
        .filter(entry => /^(DNS|IP Address):/i.test(entry))
        .map(entry =>
            entry
                .replace(/^(DNS|IP Address):/i, '')
                .trim()
                .replace(/^"|"$/g, '')
                .toLowerCase()
        );

    return {
        subject: x509.subject,
        issuer: x509.issuer,
        serialNumber: x509.serialNumber,
        fingerprint: x509.fingerprint,
        fingerprint256: x509.fingerprint256,
        altNames,
        validFrom: new Date(x509.validFrom),
        validTo: new Date(x509.validTo),
        selfSigned: x509.issuer === x509.subject
    };
}

async function decodeRecord(value) {
    if (!value) {
        return false;
    }

    let record;
    try {
        record = JSON.parse(value);
    } catch (err) {
        return false;
    }

    if (record && record.privateKey) {
        const encryptSecret = await getSecret();
        record.privateKey = await decrypt(record.privateKey, encryptSecret);
    }

    return record;
}

async function readRecord(field) {
    return await decodeRecord(await redis.hget(TLS_KEY, field));
}

async function serializeRecord(record) {
    const stored = Object.assign({}, record);
    if (stored.privateKey) {
        const encryptSecret = await getSecret();
        stored.privateKey = await encrypt(stored.privateKey, encryptSecret);
    }
    return JSON.stringify(stored);
}

/**
 * The names EmailEngine serves TLS for: the service URL's hostname first, then whatever else the
 * operator listed. The first one is the subject of a self-signed certificate and the name a
 * Let's Encrypt certificate is ordered for; the rest are ordered separately and served over SNI.
 *
 * IP addresses and unqualified names are kept, unlike the ACME path which cannot use them: a
 * self-signed certificate for an IP-only deployment is exactly the case this fallback exists for.
 *
 * @returns {Promise<string[]>} Lower-cased hostnames, deduplicated, in priority order
 */
async function getCertificateHostnames() {
    return hostnamesFrom(await settings.getMulti('serviceUrl', 'tlsHostnames'));
}

/**
 * The one spelling of a hostname. Settings, certificate names and the server name a client sends
 * are all compared folded, so every caller has to fold the same way.
 *
 * @param {string} hostname Name from a setting, a URL or a handshake
 * @returns {string} Folded name, empty when there was none
 */
function normalizeHostname(hostname) {
    return (hostname || '').toString().toLowerCase().trim();
}

/**
 * The same derivation, from values the caller already has. Split out so a page that reads several
 * settings at once does not issue a second round trip for the two this needs.
 *
 * @param {Object} values `{ serviceUrl, tlsHostnames }`
 * @returns {string[]} Lower-cased hostnames, deduplicated, in priority order
 */
function hostnamesFrom(values) {
    const hostnames = [];

    try {
        const hostname = normalizeHostname(new URL(values && values.serviceUrl).hostname);
        if (hostname) {
            // A URL keeps an IPv6 literal in brackets; a certificate name does not.
            hostnames.push(hostname.replace(/^\[|\]$/g, ''));
        }
    } catch (err) {
        // no service URL, or not a URL at all
    }

    for (const entry of [].concat((values && values.tlsHostnames) || [])) {
        const hostname = normalizeHostname(entry);
        if (hostname && !hostnames.includes(hostname)) {
            hostnames.push(hostname);
        }
    }

    return hostnames;
}

/**
 * The names the operator listed on top of the Service URL's own, folded the way every reader of
 * the list compares them. Separate from hostnamesFrom() because the admin page treats the two
 * differently: the Service URL's name is set on the General page, these are rows of its own.
 *
 * @param {Object} values `{ tlsHostnames }`
 * @returns {string[]} Lower-cased hostnames, empty entries dropped
 */
function extraHostnamesFrom(values) {
    return []
        .concat((values && values.tlsHostnames) || [])
        .map(normalizeHostname)
        .filter(name => name);
}

/**
 * Whether writing `value` over the stored value actually changes what the TLS listeners serve.
 *
 * A write is not a change: settings.set() is an unconditional hset, and a read-modify-write API
 * client posts the whole settings object back on every call. Reloading on the write alone handed
 * three listeners a new certificate every time somebody changed the timezone. tlsHostnames is a
 * set of names, so a reordered list is the same list.
 *
 * @param {string} key Settings key
 * @param {*} storedValue What the store holds now
 * @param {*} value What is about to be written
 * @returns {boolean} True when the listeners should reload
 */
function tlsSettingChanged(key, storedValue, value) {
    if (key === 'tlsHostnames') {
        const normalize = list => extraHostnamesFrom({ tlsHostnames: list }).sort();
        return !isDeepStrictEqual(normalize(storedValue), normalize(value));
    }

    // Against what settings.set() will store rather than against what was posted: serviceUrl is
    // reduced to its origin, so the stored value posted back with a trailing slash is the same value.
    return (storedValue ?? '') !== (settings.formatSettingValue(key, value) ?? '');
}

/**
 * The hostnames a Let's Encrypt certificate can be ordered for. The ACME http-01 challenge needs a
 * name the CA can resolve and reach, so an address literal, a single label or a private-use suffix
 * is not one of them.
 *
 * @param {string[]} hostnames Candidate names
 * @returns {string[]} The subset that can be validated
 */
function acmeEligibleHostnames(hostnames) {
    return [].concat(hostnames || []).filter(hostname => {
        if (!hostname || net.isIP(hostname)) {
            return false;
        }
        if (!/\./.test(hostname) || /(\.local|\.lan|\.internal|\.home\.arpa|\.localhost)$/i.test(hostname)) {
            return false;
        }
        return true;
    });
}

/**
 * The certificate an operator uploaded, if any.
 *
 * @returns {Promise<Object|false>} `{ cert, ca, privateKey, ...metadata }`
 */
async function getManualCertificate() {
    const record = await readRecord(MANUAL_FIELD);
    if (!record || !record.cert || !record.privateKey) {
        return false;
    }
    return Object.assign({ source: 'manual' }, describeCertificate(record.cert) || {}, record);
}

/**
 * The uploaded certificate's metadata, for a page that only names it. Unlike getManualCertificate()
 * this never decrypts the private key: a form that says "a certificate for X is installed" has no
 * business pulling key material into memory.
 *
 * @returns {Promise<Object|false>} `{ source, subject, altNames, validTo, ... }`
 */
async function peekManualCertificate() {
    const raw = await redis.hget(TLS_KEY, MANUAL_FIELD);

    let record;
    try {
        record = raw ? JSON.parse(raw) : null;
    } catch (err) {
        return false;
    }

    if (!record || !record.cert) {
        return false;
    }

    return Object.assign({ source: 'manual' }, describeCertificate(record.cert) || {}, { updated: record.updated });
}

/**
 * Validates and stores an uploaded certificate.
 *
 * Everything is checked before anything is written: a certificate that does not parse, a key that
 * does not parse, or a pair that does not match is refused rather than stored and discovered at the
 * next restart, when the listener would be down and the admin UI would still show it as installed.
 *
 * @param {Object} input
 * @param {string} input.cert PEM certificate, optionally with the chain appended
 * @param {string} [input.ca] PEM chain, when supplied separately
 * @param {string} input.privateKey PEM private key
 * @param {string} [input.passphrase] Passphrase, when the key is encrypted
 * @returns {Promise<Object>} The stored record's metadata
 */
async function setManualCertificate(input) {
    const chain = splitPemChain(input && input.cert).concat(splitPemChain(input && input.ca));

    if (!chain.length) {
        throw certificateError('The certificate must be PEM encoded and start with "-----BEGIN CERTIFICATE-----"', 'cert');
    }

    let x509;
    try {
        x509 = new crypto.X509Certificate(chain[0]);
    } catch (err) {
        throw certificateError(`Could not read the certificate: ${err.message}`, 'cert');
    }

    const keyPem = (input.privateKey || '').toString().replace(/\r\n/g, '\n').trim();

    // Read from the PEM, not from the error: OpenSSL reports a missing passphrase as "interrupted
    // or cancelled" (it wanted to prompt for one), which tells the operator nothing at all.
    const keyIsEncrypted = /BEGIN ENCRYPTED PRIVATE KEY|Proc-Type:\s*4,ENCRYPTED/i.test(keyPem);

    if (keyIsEncrypted && !input.passphrase) {
        throw certificateError('This private key is passphrase protected. Enter the passphrase to install it.', 'privateKey');
    }

    let privateKey;
    try {
        privateKey = crypto.createPrivateKey({ key: keyPem, passphrase: input.passphrase || undefined });
    } catch (err) {
        throw certificateError(
            keyIsEncrypted ? 'Could not read the private key. Check the passphrase.' : `Could not read the private key: ${err.message}`,
            'privateKey'
        );
    }

    if (!x509.checkPrivateKey(privateKey)) {
        throw certificateError('The private key does not belong to this certificate', 'privateKey');
    }

    const record = {
        cert: chain[0],
        ca: chain.slice(1),
        // Stored without its passphrase: the value is encrypted at rest with the instance secret,
        // and keeping the passphrase would mean storing it next to what it protects.
        privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        updated: new Date().toISOString()
    };

    await redis.hset(TLS_KEY, MANUAL_FIELD, await serializeRecord(record));

    return Object.assign({ source: 'manual' }, describeCertificate(record.cert) || {});
}

function certificateError(message, field) {
    const err = new Error(message);
    err.code = 'InvalidCertificate';
    if (field) {
        err.details = { [field]: message };
    }
    return err;
}

async function deleteManualCertificate() {
    return await redis.hdel(TLS_KEY, MANUAL_FIELD);
}

/**
 * The instance's self-signed certificate, generated on first use and replaced when it no longer
 * covers the configured names or is close to expiring.
 *
 * Written conditionally on the record that was read, so that two workers reaching this at the same
 * moment agree on one certificate: whoever loses the race reads back the winner's rather than
 * serving a second one that nobody pinned.
 *
 * @param {string[]} hostnames Names the certificate has to cover
 * @param {Object} [logger] Logger for the generation notice
 * @returns {Promise<Object>} `{ cert, privateKey, ...metadata }`
 */
async function peekSelfSignedCertificate() {
    const record = await readRecord(SELF_SIGNED_FIELD);
    if (!record || !record.cert) {
        return false;
    }

    return Object.assign({ source: 'self-signed' }, describeCertificate(record.cert) || {}, record);
}

async function getSelfSignedCertificate(hostnames, logger) {
    const names = []
        .concat(hostnames || [])
        .map(normalizeHostname)
        .filter(name => name);
    if (!names.length) {
        names.push(FALLBACK_HOSTNAME);
    }

    const asMaterial = record => Object.assign({ source: 'self-signed' }, describeCertificate(record.cert) || {}, record);

    // The stored bytes are kept, not just the record: they are what the replacement below is made
    // conditional on, and re-serializing cannot produce them again - the private key is encrypted
    // with a fresh IV every time, so the same certificate serializes to a different string.
    const stale = await redis.hget(TLS_KEY, SELF_SIGNED_FIELD);
    const existing = await decodeRecord(stale);
    if (existing && existing.cert && existing.privateKey && !selfSignedIsStale(existing, names)) {
        return asMaterial(existing);
    }

    // Whatever is there covers the wrong names or is about to expire, and both make a handshake
    // fail, so it is replaced rather than kept.
    const generated = await createSelfSignedCertificate({ hostnames: names });

    const record = {
        cert: generated.cert,
        privateKey: generated.privateKey,
        hostnames: names,
        updated: new Date().toISOString()
    };

    // Conditional on the record that was read, so concurrent replacement converges the way
    // concurrent creation already did. Deleting the stale record and then HSETNX looked equivalent
    // and was not: a certificate reload fans out to the API, SMTP and IMAP proxy workers at once,
    // so after a hostname change all three find the same stale record, and the delete let each of
    // them win an HSETNX in turn - every worker then served its own certificate while the page
    // showed whichever wrote last.
    const stored = await redis.hSetIfEquals(TLS_KEY, SELF_SIGNED_FIELD, await serializeRecord(record), stale || '');

    if (!stored) {
        const winner = await readRecord(SELF_SIGNED_FIELD);
        if (winner && winner.cert && winner.privateKey) {
            return asMaterial(winner);
        }
    } else if (logger) {
        logger.warn({
            msg: 'Generated a self-signed TLS certificate. Clients can not verify it; pin the fingerprint or install a real certificate',
            hostnames: names,
            fingerprint: generated.fingerprint,
            validTo: generated.validTo
        });
    }

    return asMaterial(record);
}

// The names the record was generated for, not the names its certificate reports. They are the same
// list, but a certificate normalizes what it holds - Node reads an IPv6 SAN back as
// "2001:db8:0:0:0:0:0:1" where the setting said "2001:db8::1" - and comparing against that would
// find a mismatch on every pass and regenerate the certificate forever.
function selfSignedIsStale(record, hostnames) {
    const covered = [].concat(record.hostnames || []);
    if (covered.length !== hostnames.length || hostnames.some(hostname => !covered.includes(hostname))) {
        return true;
    }

    const parsed = describeCertificate(record.cert);
    if (!parsed) {
        return true;
    }

    return parsed.validTo.getTime() - Date.now() < SELF_SIGNED_RENEW_BEFORE;
}

async function deleteSelfSignedCertificate() {
    return await redis.hdel(TLS_KEY, SELF_SIGNED_FIELD);
}

/**
 * Reads the Let's Encrypt record for a name, without ever ordering one. Provisioning is the
 * reconciler's job (lib/tls/provision.js); a listener starting up must not block on a CA.
 *
 * @param {Object} certs @postalsys/certs handler
 * @param {string} hostname Name to look up
 * @param {Object} [logger] Logger for a store that could not be read
 * @returns {Promise<Object|false>} `{ cert, ca, privateKey, ...metadata }`
 */
async function getAcmeCertificate(certs, hostname, logger) {
    if (!certs || !hostname) {
        return false;
    }

    let record;
    try {
        record = await certs.getCertificate(hostname, true);
    } catch (err) {
        // The listener still starts on whatever is left, but silently: a rotated EENGINE_SECRET
        // fails the key decrypt and Redis can be down, and both looked like "no certificate here"
        // with nothing in the log to say the stored one exists.
        if (logger) {
            logger.error({ msg: 'Failed to read the stored TLS certificate', hostname, err });
        }
        return false;
    }

    if (!record || record.status !== 'valid' || !record.cert || !record.privateKey) {
        return false;
    }

    return Object.assign({ source: 'acme' }, describeCertificate(record.cert) || {}, {
        cert: record.cert,
        ca: [].concat(record.ca || []).flatMap(entry => entry),
        privateKey: record.privateKey
    });
}

module.exports = {
    TLS_KEY,
    MANUAL_FIELD,
    SELF_SIGNED_FIELD,
    FALLBACK_HOSTNAME,
    splitPemChain,
    parseCertificate,
    coversHostname,
    describeCertificate,
    describeX509,
    getCertificateHostnames,
    normalizeHostname,
    hostnamesFrom,
    extraHostnamesFrom,
    tlsSettingChanged,
    acmeEligibleHostnames,
    getManualCertificate,
    peekManualCertificate,
    setManualCertificate,
    deleteManualCertificate,
    getSelfSignedCertificate,
    peekSelfSignedCertificate,
    deleteSelfSignedCertificate,
    getAcmeCertificate
};
