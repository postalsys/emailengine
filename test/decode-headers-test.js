'use strict';

// Unit coverage for decodeHeaders() (lib/utils/decode-headers.js), the libmime wrapper every
// parsed header block goes through.
//
// libmime returns "__proto__" and "constructor" field names as real own properties, and
// lib/email-client/imap/mailbox.js and lib/bounce-detect.js hand these maps back to callers
// verbatim. See lib/utils/decode-headers.js for why each name is dropped.

const test = require('node:test');
const assert = require('node:assert').strict;

const libmime = require('libmime');
const msgpack = require('../lib/msgpack');
const { decodeHeaders } = require('../lib/utils/decode-headers');

test('decodeHeaders', async t => {
    await t.test('libmime really does produce the own __proto__ key this wrapper exists to drop', () => {
        // Pins the upstream behavior the wrapper compensates for: libmime defines the key rather
        // than letting it reach the prototype setter. If it ever stops, the wrapper becomes dead
        // code rather than silently load-bearing. There is no equivalent to pin for "constructor",
        // where a plain assignment always produces an own key
        const raw = libmime.decodeHeaders('Subject: hi\r\n__proto__: injected\r\n');

        assert.ok(Object.hasOwn(raw, '__proto__'));
    });

    await t.test('drops names that collide with Object.prototype and keeps everything else', () => {
        const headers = decodeHeaders('Subject: hi\r\n__proto__: injected\r\nConstructor: c\r\nX-Custom: value\r\n');

        assert.deepEqual(Object.keys(headers), ['subject', 'x-custom']);
        assert.ok(!Object.hasOwn(headers, '__proto__'));
        assert.ok(!Object.hasOwn(headers, 'constructor'));
        assert.equal(Object.getPrototypeOf(headers), Object.prototype);
    });

    await t.test('drops exactly the names the clients cannot represent, and no more', () => {
        // libmime lowercases, so these are the only two collisions - anything else that merely
        // looks dangerous must survive
        const headers = decodeHeaders(['toString: a', 'hasOwnProperty: b', 'prototype: c', 'valueOf: d', '__proto__: e', 'constructor: f'].join('\r\n'));

        assert.deepEqual(Object.keys(headers).sort(), ['hasownproperty', 'prototype', 'tostring', 'valueof']);
    });

    await t.test('result round-trips through msgpack and JSON', () => {
        const headers = decodeHeaders('Subject: hi\r\n__proto__: injected\r\nconstructor: c\r\n');

        assert.deepEqual(msgpack.decode(msgpack.encode(headers)), headers);
        assert.deepEqual(JSON.parse(JSON.stringify(headers)), headers);
    });

    await t.test('leaves ordinary header blocks untouched, including repeats', () => {
        const headers = decodeHeaders('Received: one\r\nReceived: two\r\nSubject: hi\r\n');

        assert.deepEqual(headers, { received: ['one', 'two'], subject: ['hi'] });
    });

    await t.test('leaves the global prototype untouched', () => {
        decodeHeaders('__proto__: injected\r\n');

        assert.deepEqual(Object.keys(Object.prototype), []);
        assert.equal({}.injected, undefined);
    });
});
