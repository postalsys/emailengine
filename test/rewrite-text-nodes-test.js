'use strict';

// Unit tests for lib/rewrite-text-nodes.js. This is the MIME transform behind
// open/click tracking and other body rewriting: it walks an RFC822 message and
// feeds each eligible text/plain or text/html node through a caller-supplied
// rewriter. The safety-relevant behaviors are WHICH nodes get rewritten -
// attachments and parts inside an embedded message/rfc822 must be left alone -
// plus charset decoding to UTF-8 before the rewriter runs and graceful handling
// of a rewriter that returns a non-string.

const test = require('node:test');
const assert = require('node:assert').strict;

const iconv = require('iconv-lite');
const libmime = require('libmime');
const { forAll, gen } = require('./helpers/property');
const MimeNode = require('@zone-eu/mailsplit/lib/mime-node');

const { rewriteTextNodes } = require('../lib/rewrite-text-nodes');

function msg(lines) {
    return lines.join('\r\n');
}

// A rewriter that tags every body it is given, so the number of tags in the
// output equals the number of nodes that were actually rewritten.
const TAG = 'XREWRITEX';
const tagging = async body => `${body}\n${TAG}`;
function countTag(buf) {
    return buf.toString().split(TAG).length - 1;
}

test('rewriteTextNodes', async t => {
    await t.test('rejects when the source is missing', async () => {
        await assert.rejects(() => rewriteTextNodes(null, { htmlRewriter: async h => h }), /Missing input source/);
    });

    await t.test('rewrites a text/html node and passes the decoded html to the rewriter', async () => {
        let received;
        const source = msg(['From: a@example.com', 'Subject: t', 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', '<p>Hello world</p>']);
        const out = await rewriteTextNodes(source, {
            htmlRewriter: async html => {
                received = html;
                return html.replace('Hello world', 'Hello [tracked]');
            }
        });
        assert.match(received, /<p>Hello world<\/p>/);
        assert.match(out.toString(), /Hello \[tracked\]/);
        assert.doesNotMatch(out.toString(), /Hello world/);
    });

    await t.test('rewrites a text/plain node', async () => {
        const source = msg(['Subject: t', 'Content-Type: text/plain; charset=utf-8', '', 'plain body']);
        const out = await rewriteTextNodes(source, { textRewriter: async text => text.replace('plain body', 'rewritten body') });
        assert.match(out.toString(), /rewritten body/);
    });

    await t.test('accepts a Buffer source', async () => {
        const source = Buffer.from(msg(['Content-Type: text/plain; charset=utf-8', '', 'buffer body']));
        const out = await rewriteTextNodes(source, { textRewriter: async () => 'replaced' });
        assert.ok(Buffer.isBuffer(out));
        assert.match(out.toString(), /replaced/);
    });

    await t.test('rewrites both alternatives in multipart/alternative', async () => {
        const source = msg([
            'Content-Type: multipart/alternative; boundary="B"',
            '',
            '--B',
            'Content-Type: text/plain; charset=utf-8',
            '',
            'plain part',
            '--B',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<p>html part</p>',
            '--B--'
        ]);
        const out = await rewriteTextNodes(source, {
            textRewriter: async text => `${text} TXT`,
            htmlRewriter: async html => `${html} HTML`
        });
        assert.match(out.toString(), /plain part TXT/);
        assert.match(out.toString(), /<p>html part<\/p> HTML/);
    });

    await t.test('only the provided rewriter type is applied', async () => {
        const source = msg([
            'Content-Type: multipart/alternative; boundary="B"',
            '',
            '--B',
            'Content-Type: text/plain; charset=utf-8',
            '',
            'plain part',
            '--B',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<p>html part</p>',
            '--B--'
        ]);
        // html rewriter only -> the text/plain node must be untouched.
        const out = await rewriteTextNodes(source, { htmlRewriter: tagging });
        assert.strictEqual(countTag(out), 1);
        assert.match(out.toString(), /<p>html part<\/p>/);
    });

    await t.test('does not rewrite an attachment part', async () => {
        const source = msg([
            'Content-Type: multipart/mixed; boundary="B"',
            '',
            '--B',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<p>body</p>',
            '--B',
            'Content-Type: text/html; charset=utf-8; name="a.html"',
            'Content-Disposition: attachment; filename="a.html"',
            '',
            '<p>attachment</p>',
            '--B--'
        ]);
        const out = await rewriteTextNodes(source, { htmlRewriter: tagging });
        // Only the inline body is tagged; the attachment is left intact.
        assert.strictEqual(countTag(out), 1);
        assert.match(out.toString(), /<p>attachment<\/p>/);
    });

    await t.test('does not rewrite parts inside an embedded message/rfc822', async () => {
        const source = msg([
            'Content-Type: multipart/mixed; boundary="B"',
            '',
            '--B',
            'Content-Type: text/plain; charset=utf-8',
            '',
            'outer text',
            '--B',
            'Content-Type: message/rfc822',
            '',
            'From: inner@example.com',
            'Subject: inner',
            'Content-Type: text/plain; charset=utf-8',
            '',
            'inner text',
            '--B--'
        ]);
        const out = await rewriteTextNodes(source, { textRewriter: tagging });
        // Only the outer text/plain is rewritten; the embedded message is skipped.
        assert.strictEqual(countTag(out), 1);
        assert.match(out.toString(), /inner text/);
    });

    await t.test('keeps the original body when the rewriter returns a non-string', async () => {
        const source = msg(['Content-Type: text/html; charset=utf-8', '', '<p>keep me</p>']);
        const out = await rewriteTextNodes(source, { htmlRewriter: async () => undefined });
        assert.match(out.toString(), /<p>keep me<\/p>/);
    });

    await t.test('decodes a non-UTF-8 charset before invoking the rewriter and enforces UTF-8 output', async () => {
        // Body is the Latin-1 bytes for "café", base64-encoded.
        const latin1Body = Buffer.from('café', 'latin1').toString('base64');
        const source = msg(['Content-Type: text/plain; charset=iso-8859-1', 'Content-Transfer-Encoding: base64', '', latin1Body]);

        let received;
        const out = await rewriteTextNodes(source, {
            textRewriter: async text => {
                received = text;
                return text;
            }
        });

        // The rewriter sees properly decoded UTF-8 text, not raw Latin-1 bytes.
        assert.strictEqual(received, 'café');
        // Output is re-labelled as UTF-8...
        assert.match(out.toString().toLowerCase(), /charset=utf-8/);
        // ...and its (base64) body round-trips to the UTF-8 encoding of the character.
        const b64 = out
            .toString()
            .split(/\r?\n\r?\n/)[1]
            .trim();
        assert.strictEqual(Buffer.from(b64, 'base64').toString('utf-8'), 'café');
        assert.strictEqual(b64, Buffer.from('café', 'utf-8').toString('base64'));
    });

    // The node decoder had no error listener, so a decoder failing mid-body was an
    // uncaughtException that took the worker with it. No decoder used here fails on input
    // today, so the failure is injected: a Transform whose first chunk errors, in each of the
    // two positions the decoder slot can hold.
    const failing = stream => {
        stream._transform = (chunk, encoding, done) => done(new Error('injected decoder failure'));
        return stream;
    };

    await t.test('rejects instead of crashing when the charset decoder fails mid-body', async () => {
        const realDecodeStream = libmime.createDecodeStream;
        libmime.createDecodeStream = charset => failing(realDecodeStream.call(libmime, charset));
        try {
            const source = msg(['Content-Type: text/plain; charset=iso-8859-1', 'Content-Transfer-Encoding: quoted-printable', '', 'body text']);
            await assert.rejects(() => rewriteTextNodes(source, { textRewriter: tagging }), /injected decoder failure/);
        } finally {
            libmime.createDecodeStream = realDecodeStream;
        }
    });

    await t.test('rejects instead of crashing when the transfer-encoding decoder fails mid-body', async () => {
        const realGetDecoder = MimeNode.prototype.getDecoder;
        MimeNode.prototype.getDecoder = function () {
            return failing(realGetDecoder.call(this));
        };
        try {
            const source = msg(['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'body text']);
            await assert.rejects(() => rewriteTextNodes(source, { textRewriter: tagging }), /injected decoder failure/);
        } finally {
            MimeNode.prototype.getDecoder = realGetDecoder;
        }
    });

    await t.test('rejects instead of crashing when the message has more MIME nodes than the splitter allows', async () => {
        const lines = ['From: a@example.com', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="xx"', ''];
        for (let i = 0; i < 1100; i++) {
            lines.push('--xx', 'Content-Type: text/html', '', `<p>part${i}</p>`);
        }
        lines.push('--xx--', '');
        for (const source of [msg(lines), Buffer.from(msg(lines))]) {
            await assert.rejects(
                () => rewriteTextNodes(source, { htmlRewriter: tagging }),
                err => err.code === 'EMAXLEN' && err.responseCode === 552
            );
        }
    });

    await t.test('rejects instead of crashing on an oversized header block', async () => {
        const source = msg(['From: a@example.com', `X-Big: ${'a'.repeat(1100 * 1024)}`, 'Content-Type: text/html', '', '<p>x</p>']);
        await assert.rejects(
            () => rewriteTextNodes(source, { htmlRewriter: tagging }),
            err => err.code === 'EMAXLEN'
        );
    });

    // Regression: the charset name went to iconv-lite without being normalized, so a label as
    // common as x-cp1251 failed to decode, and the part was then relabelled utf-8 with its
    // windows-1251 bytes kept, which garbled it in the sent message
    await t.test('decodes a charset alias iconv-lite does not know by that name', async () => {
        const source = msg([
            'Content-Type: text/plain; charset=x-cp1251',
            'Content-Transfer-Encoding: base64',
            '',
            iconv.encode('Привет, мир', 'windows-1251').toString('base64')
        ]);
        let received;
        const out = await rewriteTextNodes(source, {
            textRewriter: async text => {
                received = text;
                return text;
            }
        });
        assert.strictEqual(received, 'Привет, мир');
        const b64 = out
            .toString()
            .split(/\r?\n\r?\n/)[1]
            .trim();
        assert.strictEqual(Buffer.from(b64, 'base64').toString('utf-8'), 'Привет, мир');
    });

    await t.test('leaves a part in a charset it can not decode untouched, label included', async () => {
        for (const charset of ['utf-7', 'x-unknown-charset']) {
            const raw = '+ADw-script+AD4-alert(1)+ADw-/script+AD4-';
            const source = msg([`Content-Type: text/html; charset=${charset}`, 'Content-Transfer-Encoding: 7bit', '', raw]);
            let called = false;
            const out = await rewriteTextNodes(source, {
                htmlRewriter: async html => {
                    called = true;
                    return html + TAG;
                }
            });
            assert.strictEqual(called, false, `${charset} is not handed to the rewriter`);
            assert.match(out.toString(), new RegExp(`charset=${charset.replace(/[-]/g, '[-]')}`, 'i'), `${charset} label kept`);
            assert.ok(out.toString().includes(raw), `${charset} body kept`);
            assert.ok(!out.toString().includes('<script>'));
        }
    });

    await t.test('property: multibyte text decodes the same whatever the line breaks fall on', async () => {
        const alphabet = ['a', ' ', '中', '文', '字', '€', '\u00e9', '\u{1f600}', '\u3042'];
        await forAll(
            gen.record({ text: gen.string(alphabet, 1, 200), charset: gen.oneOf(['gb18030', 'big5', 'shift_jis', 'euc-kr', 'utf-16be']) }),
            async ({ text, charset }) => {
                // keep only characters the charset can encode, so the comparison is exact
                const encodable = [...text].filter(ch => iconv.decode(iconv.encode(ch, charset), charset) === ch).join('') || 'a';
                const encoded = iconv
                    .encode(encodable, charset)
                    .toString('base64')
                    .replace(/.{1,8}/g, '$&\r\n');
                const source = msg([`Content-Type: text/plain; charset=${charset}`, 'Content-Transfer-Encoding: base64', '', encoded]);
                let received;
                await rewriteTextNodes(source, {
                    textRewriter: async value => {
                        received = value;
                        return value;
                    }
                });
                assert.strictEqual(received, encodable);
            },
            { runs: 150 }
        );
    });
});
