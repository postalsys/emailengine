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
});
