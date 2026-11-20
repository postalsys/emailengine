'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { decodedAttachmentSize } = require('../lib/attachment-size');
const exitWhenStandalone = require('./helpers/exit-standalone');

// The base64 body of a file as a mail client writes it: 76 characters per line, CRLF after each
function encodedLength(bytes) {
    return Buffer.alloc(bytes).toString('base64').replace(/.{76}/g, '$&\r\n').replace(/\r\n$/, '').length;
}

test('decodedAttachmentSize', async t => {
    await t.test('undoes base64, line breaks included, to at most the 2 bytes of padding over', () => {
        for (const bytes of [0, 1, 2, 3, 56, 57, 58, 1000, 4096, 123457, 2 * 1024 * 1024]) {
            const size = decodedAttachmentSize(encodedLength(bytes), 'base64');
            assert.ok(size >= bytes && size - bytes <= 2, `${bytes} bytes came out as ${size}`);
        }
    });

    await t.test('reads the encoding name in any case', () => {
        assert.equal(decodedAttachmentSize(4, 'BASE64'), 3);
    });

    await t.test('keeps the encoded size for encodings that do not grow the file, or can not be undone', () => {
        for (const encoding of ['7bit', '8bit', 'binary', 'quoted-printable', undefined, null, '']) {
            assert.equal(decodedAttachmentSize(1234, encoding), 1234, String(encoding));
        }
    });

    await t.test('reports nothing for a size the server did not give', () => {
        for (const value of [undefined, null, NaN, -1, '100']) {
            assert.equal(decodedAttachmentSize(value, 'base64'), undefined, String(value));
        }
    });
});

exitWhenStandalone();
