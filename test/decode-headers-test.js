'use strict';

// Unit coverage for decodeHeaders() (lib/utils/decode-headers.js), the libmime wrapper every
// parsed header block goes through.
//
// libmime returns a "__proto__" field name as a real OWN property rather than letting it reach
// the prototype setter. Both lib/email-client/imap/mailbox.js and lib/bounce-detect.js hand these
// maps back to callers verbatim, and an own "__proto__" key is the one thing lib/msgpack.js
// refuses to decode - so a map carrying it produces webhook logs and message payloads that encode
// but can never be read back.

const test = require('node:test');
const assert = require('node:assert').strict;

const libmime = require('libmime');
const msgpack = require('../lib/msgpack');
const { decodeHeaders } = require('../lib/utils/decode-headers');

test('decodeHeaders', async t => {
    await t.test('libmime really does produce the own key this wrapper exists to drop', () => {
        // Pins the upstream behavior the wrapper compensates for; if libmime ever stops doing
        // this, the wrapper becomes dead code rather than silently load-bearing
        const raw = libmime.decodeHeaders('Subject: hi\r\n__proto__: injected\r\n');

        assert.ok(Object.hasOwn(raw, '__proto__'));
    });

    await t.test('drops a __proto__ field name and keeps everything else', () => {
        const headers = decodeHeaders('Subject: hi\r\n__proto__: injected\r\nX-Custom: value\r\n');

        assert.deepEqual(Object.keys(headers), ['subject', 'x-custom']);
        assert.ok(!Object.hasOwn(headers, '__proto__'));
        assert.equal(Object.getPrototypeOf(headers), Object.prototype);
    });

    await t.test('result round-trips through msgpack and JSON', () => {
        const headers = decodeHeaders('Subject: hi\r\n__proto__: injected\r\n');

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
