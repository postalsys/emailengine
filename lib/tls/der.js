'use strict';

// Minimal DER writer for the self-signed certificate builder in lib/tls/self-signed.js.
//
// EmailEngine needs to mint one X.509 certificate: a short-lived, self-signed leaf that lets a TLS
// listener start when no real certificate is available. Node's crypto can generate the key pair and
// produce the signature but cannot assemble a certificate, and every library that can is either
// unmaintained or several megabytes of ASN.1 machinery for the one structure we emit. This is the
// subset that structure needs, written so each function maps to a line of RFC 5280.
//
// Encoding only. Nothing here parses attacker-controlled input; the one reader (readTlv) walks a
// SubjectPublicKeyInfo that Node itself produced a moment earlier.

const net = require('net');
const ipaddr = require('ipaddr.js');

/**
 * DER length octets: short form below 128, long form above it.
 *
 * @param {number} length Content length in bytes
 * @returns {Buffer} Encoded length
 */
function encodeLength(length) {
    if (length < 0x80) {
        return Buffer.from([length]);
    }

    const bytes = [];
    let value = length;
    while (value > 0) {
        bytes.unshift(value & 0xff);
        value = Math.floor(value / 256);
    }

    return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/**
 * Tag-length-value, the shape every DER element has.
 *
 * @param {number} tag Identifier octet
 * @param {Buffer|Buffer[]} content Content octets, concatenated when an array
 * @returns {Buffer} Encoded element
 */
function tlv(tag, content) {
    const body = Buffer.isBuffer(content) ? content : Buffer.concat(content);
    return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

const sequence = content => tlv(0x30, content);
const set = content => tlv(0x31, content);
const octetString = content => tlv(0x04, content);
const bitString = content => tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.isBuffer(content) ? content : Buffer.concat(content)]));
const boolean = value => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
const nullValue = () => tlv(0x05, Buffer.alloc(0));
const utf8String = value => tlv(0x0c, Buffer.from(value, 'utf-8'));

// Constructed context-specific tag, the [n] EXPLICIT of the ASN.1 modules.
const explicit = (tagNumber, content) => tlv(0xa0 | tagNumber, content);

// Primitive context-specific tag, the [n] IMPLICIT that GeneralName uses for its choices.
const implicit = (tagNumber, content) => tlv(0x80 | tagNumber, content);

/**
 * A non-negative INTEGER. DER integers are signed, so a value whose top bit is set gains a leading
 * zero octet, and leading zero octets that are not needed are stripped.
 *
 * @param {Buffer|number} value Magnitude, big-endian when a Buffer
 * @returns {Buffer} Encoded INTEGER
 */
function integer(value) {
    let bytes;

    if (typeof value === 'number') {
        bytes = [];
        let remaining = value;
        do {
            bytes.unshift(remaining & 0xff);
            remaining = Math.floor(remaining / 256);
        } while (remaining > 0);
        bytes = Buffer.from(bytes);
    } else {
        bytes = Buffer.from(value);
    }

    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0 && !(bytes[start + 1] & 0x80)) {
        start++;
    }
    bytes = bytes.subarray(start);

    if (bytes[0] & 0x80) {
        bytes = Buffer.concat([Buffer.from([0]), bytes]);
    }

    return tlv(0x02, bytes);
}

/**
 * An OBJECT IDENTIFIER from its dotted form. The first two arcs share one octet; every later arc is
 * base-128 with the continuation bit set on all but its last octet.
 *
 * @param {string} dotted e.g. "2.5.29.17"
 * @returns {Buffer} Encoded OID
 */
function oid(dotted) {
    const arcs = dotted.split('.').map(Number);
    const bytes = [40 * arcs[0] + arcs[1]];

    for (let i = 2; i < arcs.length; i++) {
        const chunk = [arcs[i] & 0x7f];
        let remaining = Math.floor(arcs[i] / 128);
        while (remaining > 0) {
            chunk.unshift((remaining & 0x7f) | 0x80);
            remaining = Math.floor(remaining / 128);
        }
        bytes.push(...chunk);
    }

    return tlv(0x06, Buffer.from(bytes));
}

/**
 * A Time, in the representation RFC 5280 requires for the year: UTCTime through 2049,
 * GeneralizedTime from 2050.
 *
 * @param {Date} date The instant to encode
 * @returns {Buffer} Encoded Time
 */
function time(date) {
    const pad = value => String(value).padStart(2, '0');
    const year = date.getUTCFullYear();
    const rest = `${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;

    if (year >= 1950 && year < 2050) {
        return tlv(0x17, Buffer.from(`${pad(year % 100)}${rest}`, 'latin1'));
    }

    return tlv(0x18, Buffer.from(`${year}${rest}`, 'latin1'));
}

/**
 * A BIT STRING carrying named bits, as KeyUsage does. Trailing unused bits are counted, and DER
 * requires the trailing zero bits to be dropped.
 *
 * @param {number[]} bits Bit numbers to set, counted from the most significant bit of the first octet
 * @returns {Buffer} Encoded BIT STRING
 */
function namedBits(bits) {
    const highest = Math.max(...bits);
    const octets = Buffer.alloc(Math.floor(highest / 8) + 1);

    for (const bit of bits) {
        octets[Math.floor(bit / 8)] |= 0x80 >> (bit % 8);
    }

    const unused = 7 - (highest % 8);
    return tlv(0x03, Buffer.concat([Buffer.from([unused]), octets]));
}

/**
 * An IP address as the octet string an iPAddress GeneralName carries: four octets for IPv4, sixteen
 * for IPv6. `::` expansion and IPv4-mapped tails are ipaddr.js's problem, not ours - it is already
 * a dependency and already the address parser everywhere else in the tree.
 *
 * @param {string} address Textual address
 * @returns {Buffer|false} Address octets, or false when the address does not parse
 */
function ipToBuffer(address) {
    if (!net.isIP(address)) {
        return false;
    }

    try {
        return Buffer.from(ipaddr.parse(address).toByteArray());
    } catch (err) {
        return false;
    }
}

/**
 * Reads one DER element. Used on a SubjectPublicKeyInfo that Node produced, to reach the public key
 * bits the subject key identifier is computed over.
 *
 * @param {Buffer} buf Buffer to read from
 * @param {number} [offset] Where the element starts
 * @returns {Object} `{ tag, contentStart, contentLength, end }`
 */
function readTlv(buf, offset = 0) {
    const tag = buf[offset];
    let pos = offset + 1;
    let length = buf[pos++];

    if (length & 0x80) {
        const count = length & 0x7f;
        length = 0;
        for (let i = 0; i < count; i++) {
            length = length * 256 + buf[pos++];
        }
    }

    return { tag, contentStart: pos, contentLength: length, end: pos + length };
}

module.exports = {
    encodeLength,
    tlv,
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
};
