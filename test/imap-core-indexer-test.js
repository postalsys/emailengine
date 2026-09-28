'use strict';

// Regression tests for two defects in the vendored imap-core indexer
// (lib/imapproxy/imap-core/lib/indexer/indexer.js):
//  - rebuild() waited for backpressure with `once('drain', resolve())`, which resolves at once (the
//    throw from registering undefined as a listener is swallowed by the settled promise), so the
//    whole message was buffered regardless of the reader.
//  - getMaildata() UTF-8-decoded the raw quoted-printable bytes before handing them to libqp, which
//    mangled every 8-bit byte in the body.

const test = require('node:test');
const assert = require('node:assert').strict;

const Indexer = require('../lib/imapproxy/imap-core/lib/indexer/indexer');

test('rebuild() waits for the reader instead of buffering the whole message', async () => {
    const indexer = new Indexer();
    const part = ('x'.repeat(76) + '\r\n').repeat(260); // about 20 KB, above the stream buffer
    const lines = ['From: a@example.com', 'Subject: big', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="bb"', ''];
    for (let i = 0; i < 20; i++) {
        lines.push('--bb', 'Content-Type: text/plain', '', part);
    }
    lines.push('--bb--', '');
    const raw = Buffer.from(lines.join('\r\n'));
    const tree = indexer.parseMimeTree(raw);

    const { value: output } = indexer.rebuild(tree);

    // Nothing reads yet. Honouring backpressure means the producer stops after the first part
    // or so; ignoring it (the old `resolve()` bug) buffers all ~400 KB in memory.
    await new Promise(r => setTimeout(r, 50));
    const buffered = output.readableLength + output.writableLength;
    assert.ok(buffered < 250 * 1024, `buffered ${buffered} bytes without a reader`);

    const rebuilt = await new Promise((resolve, reject) => {
        const chunks = [];
        output.on('error', reject);
        output.on('data', chunk => chunks.push(chunk));
        output.on('end', () => resolve(Buffer.concat(chunks)));
    });
    assert.ok(rebuilt.length > 390 * 1024);
    assert.equal(rebuilt.toString().split('--bb').length - 1, 21);
});

test('getMaildata() decodes 8-bit bytes in a quoted-printable body', () => {
    const indexer = new Indexer();
    const raw = Buffer.concat([
        Buffer.from(['From: a@example.com', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', ''].join('\r\n')),
        // raw UTF-8 bytes next to an encoded sequence
        Buffer.from('caf\u00e9 \u20ac =C3=A9\r\n', 'utf-8')
    ]);
    const maildata = indexer.getMaildata(indexer.parseMimeTree(raw));
    assert.equal(maildata.text, 'caf\u00e9 \u20ac \u00e9');
});
