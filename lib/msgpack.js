'use strict';

// Wrapper around @msgpack/msgpack that keeps the call-site contract of the deprecated
// msgpack5 package this codebase used before:
// - encode() returns a Buffer (call sites chain .toString('base64url'), Buffer.concat and
//   hsetBuffer on it) and omits undefined object properties instead of encoding nil
// - decode() reads the first value and ignores trailing bytes - graceful-degradation guards
//   for corrupt stored blobs rely on a parseable prefix decoding instead of throwing
// - decode() returns Buffers for bin values where @msgpack/msgpack yields Uint8Array -
//   call sites use .toString('hex')/.toString('base64') which are Buffer-only
// The wire format is plain spec msgpack in both directions, so blobs persisted by earlier
// msgpack5-based releases stay readable and vice versa.

const { Encoder, Decoder } = require('@msgpack/msgpack');

// shared instances so the per-call codec setup (internal 2KB encode buffer, decoder stack pool)
// amortizes across calls - decode runs on every API token check and mailbox listing entry.
// The library guards re-entrancy itself by cloning when an instance is already in use.
const encoder = new Encoder({ ignoreUndefined: true });
const decoder = new Decoder();

function bufferize(value) {
    if (value instanceof Uint8Array) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }

    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            value[i] = bufferize(value[i]);
        }
        return value;
    }

    if (value && typeof value === 'object' && !(value instanceof Date)) {
        for (let key of Object.keys(value)) {
            value[key] = bufferize(value[key]);
        }
        return value;
    }

    return value;
}

function encode(value) {
    // copy into a standalone Buffer - encodeSharedRef() returns a view over the reused internal buffer
    return Buffer.from(encoder.encodeSharedRef(value));
}

function decode(buf) {
    for (let value of decoder.decodeMulti(buf)) {
        return bufferize(value);
    }
    // empty input yields no values instead of throwing
    throw new Error('Unable to decode msgpack value');
}

// Decodes a byte stream of concatenated msgpack values (append-list hash fields)
function decodeMulti(buf) {
    return Array.from(decoder.decodeMulti(buf), bufferize);
}

module.exports = { encode, decode, decodeMulti };
