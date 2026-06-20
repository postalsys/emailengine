'use strict';

// Unit tests for lib/get-raw-email.js, the send-pipeline helper that turns an
// API submission (`data`) into a ready-to-send RFC822 message. Two distinct code
// paths are covered:
//
//   1. The "raw" path (data.raw provided): processMessage() streams the message
//      through a HeadersRewriter that injects Date/MIME-Version/Message-ID,
//      strips and interprets the X-EE-* control headers, applies from/to/cc/bcc
//      overrides, and computes the SMTP envelope.
//   2. The "composed" path (structured html/text/address fields): MailComposer
//      builds the MIME, with preview-text injection and message/rfc822
//      "as is" attachment embedding handled before the build.
//
// Both paths also have a returnObject variant, plus the removeBcc() helper.
// This module is pure (no network, no Redis writes) but pulls in lib/tools which
// transitively opens a Redis client, so the standard teardown helper is used.

const test = require('node:test');
const assert = require('node:assert').strict;

const { getRawEmail, removeBcc } = require('../lib/get-raw-email');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

// Build a minimal RFC822 message for the data.raw path.
function rawMessage(headerLines, body) {
    return Buffer.from([...headerLines, '', body].join('\r\n'));
}

test('getRawEmail - raw path (processMessage)', async t => {
    await t.test('injects Date, MIME-Version and a generated Message-ID', async () => {
        const raw = rawMessage(['From: Alice <alice@example.com>', 'To: bob@example.org', 'Subject: Hello'], 'Body text');
        const res = await getRawEmail({ raw }, null);

        const out = res.raw.toString();
        assert.ok(Buffer.isBuffer(res.raw));
        assert.match(out, /^Date:/m);
        assert.match(out, /^MIME-Version: 1\.0/m);
        assert.match(out, /^Message-ID:/m);

        // Message-ID domain is taken from the envelope From address.
        assert.match(res.messageId, /@example\.com>$/);
        assert.strictEqual(res.subject, 'Hello');
        assert.strictEqual(res.hasBcc, false);
        assert.strictEqual(res.envelope.from, 'alice@example.com');
        assert.deepStrictEqual(res.envelope.to, ['bob@example.org']);
    });

    await t.test('accepts data.raw as a base64 string', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Subject: B64'], 'hi');
        const res = await getRawEmail({ raw: raw.toString('base64') }, null);
        assert.match(res.raw.toString(), /^Subject: B64/m);
        assert.strictEqual(res.subject, 'B64');
    });

    await t.test('does not regenerate an existing Message-ID', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Message-ID: <keep-me@local>', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw }, null);
        assert.strictEqual(res.messageId, '<keep-me@local>');
        assert.strictEqual(res.raw.toString().match(/^Message-ID:/gim).length, 1);
    });

    await t.test('normalizes a caller-supplied messageId and replaces the header', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Message-ID: <old@local>', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, messageId: 'new@local' }, null);
        assert.strictEqual(res.messageId, '<new@local>');
        assert.match(res.raw.toString(), /^Message-ID: <new@local>/m);
        assert.doesNotMatch(res.raw.toString(), /old@local/);
    });

    await t.test('strips angle brackets correctly when normalizing messageId', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, messageId: '<<weird@local>>' }, null);
        assert.strictEqual(res.messageId, '<weird@local>');
    });

    await t.test('overrides the To header from data.to and adds Bcc', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: original@example.com', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, to: [{ address: 'new@example.com' }], bcc: [{ address: 'secret@example.com' }] }, null);

        const out = res.raw.toString();
        assert.match(out, /^To: .*new@example\.com/m);
        assert.doesNotMatch(out, /original@example\.com/);
        assert.strictEqual(res.hasBcc, true);
        // The envelope collects to + cc + bcc recipients.
        assert.ok(res.envelope.to.includes('new@example.com'));
        assert.ok(res.envelope.to.includes('secret@example.com'));
    });

    await t.test('does not replace an existing header with a default-only address', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: original@example.com', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, to: [{ address: 'fallback@example.com', _default: true }] }, null);
        assert.match(res.raw.toString(), /^To: original@example\.com/m);
    });

    await t.test('removes an address header when data provides an empty array', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: original@example.com', 'Cc: cc@example.com', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, cc: [] }, null);
        assert.doesNotMatch(res.raw.toString(), /^Cc:/m);
    });

    await t.test('honors a caller-provided envelope', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Subject: x'], 'hi');
        const res = await getRawEmail({ raw, envelope: { from: 'envfrom@example.com', to: ['env-to@example.com'] } }, null);
        assert.strictEqual(res.envelope.from, 'envfrom@example.com');
        assert.deepStrictEqual(res.envelope.to, ['env-to@example.com']);
    });

    await t.test('extracts and strips the X-EE-* control headers', async () => {
        const future = new Date(Date.now() + 24 * 3600 * 1000);
        const raw = rawMessage(
            [
                'From: a@example.com',
                'To: b@example.com',
                'Subject: x',
                `X-EE-Send-At: ${future.toISOString()}`,
                'X-EE-Delivery-Attempts: 7',
                'X-EE-Gateway: gw-123',
                'X-EE-Tracking-Enabled: true'
            ],
            'hi'
        );
        const res = await getRawEmail({ raw }, null);

        const out = res.raw.toString();
        // Control headers are consumed and removed from the outgoing message.
        assert.doesNotMatch(out, /^X-EE-Send-At:/im);
        assert.doesNotMatch(out, /^X-EE-Delivery-Attempts:/im);
        assert.doesNotMatch(out, /^X-EE-Gateway:/im);
        assert.doesNotMatch(out, /^X-EE-Tracking-Enabled:/im);

        assert.ok(res.sendAt instanceof Date);
        assert.strictEqual(res.sendAt.getTime(), future.getTime());
        assert.strictEqual(res.deliveryAttempts, 7);
        assert.strictEqual(res.gateway, 'gw-123');
        assert.strictEqual(res.trackingEnabled, true);
        // A future sendAt rewrites the Date header to match.
        assert.match(out, new RegExp(`^Date: ${future.toUTCString().replace('GMT', '\\+0000')}`, 'm'));
    });

    await t.test('adds the X-Ee-Sid header from licenseInfo', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Subject: x'], 'hi');
        const licensed = await getRawEmail({ raw }, { details: { key: 'abcdef0123456789' } });
        assert.match(licensed.raw.toString(), /^X-Ee-Sid: \S+/m);

        const unlicensed = await getRawEmail({ raw }, {});
        assert.match(unlicensed.raw.toString(), /^X-Ee-Sid: UNLICENSED_COPY/m);

        const none = await getRawEmail({ raw }, null);
        assert.doesNotMatch(none.raw.toString(), /^X-Ee-Sid:/m);
    });

    await t.test('returnObject parses the message into a structured object', async () => {
        const raw = rawMessage(
            ['From: Alice <alice@example.com>', 'To: bob@example.org', 'Subject: Parsed', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="BB"'],
            [
                '--BB',
                'Content-Type: text/plain',
                '',
                'body here',
                '--BB',
                'Content-Type: text/plain; name="note.txt"',
                'Content-Disposition: attachment; filename="note.txt"',
                '',
                'attached text',
                '--BB--'
            ].join('\r\n')
        );

        const res = await getRawEmail({ raw }, null, { returnObject: true });
        const parsed = res.emailObject;

        assert.ok(parsed);
        assert.strictEqual(parsed.subject, 'Parsed');
        // from is collapsed to a single address object, to/cc/bcc to value arrays.
        assert.strictEqual(parsed.from.address, 'alice@example.com');
        assert.strictEqual(parsed.to[0].address, 'bob@example.org');
        // headers Map is deleted to avoid conflicts.
        assert.strictEqual(parsed.headers, undefined);

        assert.strictEqual(parsed.attachments.length, 1);
        const att = parsed.attachments[0];
        assert.strictEqual(att.encoding, 'base64');
        assert.strictEqual(att.isInline, false);
        assert.strictEqual(Buffer.from(att.content, 'base64').toString(), 'attached text');
    });
});

test('getRawEmail - composed path (MailComposer)', async t => {
    await t.test('builds a MIME message from structured fields', async () => {
        const res = await getRawEmail(
            {
                from: { name: 'Alice', address: 'alice@example.com' },
                to: [{ address: 'bob@example.org' }],
                subject: 'Composed',
                text: 'plain body',
                html: '<p>html body</p>'
            },
            null
        );

        const out = res.raw.toString();
        assert.ok(Buffer.isBuffer(res.raw));
        assert.match(out, /^From: Alice <alice@example\.com>/m);
        assert.match(out, /^Subject: Composed/m);
        assert.ok(res.messageId && /^<.+>$/.test(res.messageId));
        assert.strictEqual(res.subject, 'Composed');
        assert.strictEqual(res.hasBcc, false);
        assert.strictEqual(res.envelope.from, 'alice@example.com');
        assert.deepStrictEqual(res.envelope.to, ['bob@example.org']);
    });

    await t.test('reports hasBcc and keeps the Bcc header in the built message', async () => {
        const res = await getRawEmail(
            {
                from: { address: 'alice@example.com' },
                to: [{ address: 'bob@example.org' }],
                bcc: [{ address: 'secret@example.com' }],
                text: 'x'
            },
            null
        );
        assert.strictEqual(res.hasBcc, true);
        // getRawEmail builds with keepBcc=true; removeBcc strips it later in the pipeline.
        assert.match(res.raw.toString(), /^Bcc: .*secret@example\.com/m);
        assert.ok(res.envelope.to.includes('secret@example.com'));
    });

    await t.test('adds the X-Ee-Sid header from licenseInfo', async () => {
        const res = await getRawEmail(
            { from: { address: 'a@example.com' }, to: [{ address: 'b@example.com' }], text: 'x' },
            { details: { key: 'abcdef0123456789' } }
        );
        assert.match(res.raw.toString(), /^X-Ee-Sid: \S+/m);
    });

    await t.test('injects preview text after the <body> tag', async () => {
        const res = await getRawEmail(
            {
                from: { address: 'a@example.com' },
                to: [{ address: 'b@example.com' }],
                html: '<html><body class="x">Hi</body></html>',
                previewText: 'Sneak peek'
            },
            null,
            { returnObject: true }
        );
        // returnObject (composed) exposes the processed mailComposer options directly.
        const html = res.emailObject.html;
        assert.match(html, /Sneak peek/);
        assert.match(html, /display:none/);
        // Preview block is inserted right after the body open tag.
        assert.match(html, /<body class="x">\s*\n?<!--\[if !gte mso 9\]>/);
        // previewText is consumed.
        assert.strictEqual(res.emailObject.previewText, null);
    });

    await t.test('prepends preview text when there is no <body> tag', async () => {
        const res = await getRawEmail(
            {
                from: { address: 'a@example.com' },
                to: [{ address: 'b@example.com' }],
                html: '<p>No body tag</p>',
                previewText: 'Preview first'
            },
            null,
            { returnObject: true }
        );
        const html = res.emailObject.html;
        assert.ok(html.indexOf('Preview first') < html.indexOf('<p>No body tag</p>'));
    });

    await t.test('embeds a message/rfc822 attachment as-is and detects 8bit content', async () => {
        // Inner message contains a non-ASCII byte, so the wrapper must use 8bit.
        const inner = Buffer.from('From: inner@example.com\r\nSubject: Iñner\r\n\r\nbody', 'utf-8');
        const res = await getRawEmail(
            {
                from: { address: 'a@example.com' },
                to: [{ address: 'b@example.com' }],
                text: 'see attached',
                attachments: [
                    {
                        filename: 'forwarded.eml',
                        contentType: 'message/rfc822',
                        encoding: 'base64',
                        content: inner.toString('base64')
                    }
                ]
            },
            null
        );

        const out = res.raw.toString();
        assert.match(out, /Content-Type: message\/rfc822/i);
        assert.match(out, /Content-Transfer-Encoding: 8bit/i);
        // The inner message is embedded unencoded, so its raw headers/body survive verbatim.
        assert.match(out, /^From: inner@example\.com/m);
        assert.match(out, /^body$/m);
    });

    await t.test('uses 7bit for a pure-ASCII message/rfc822 attachment', async () => {
        const inner = Buffer.from('From: inner@example.com\r\nSubject: Plain inner\r\n\r\nbody', 'ascii');
        const res = await getRawEmail(
            {
                from: { address: 'a@example.com' },
                to: [{ address: 'b@example.com' }],
                text: 'see attached',
                attachments: [{ filename: 'fwd.eml', contentType: 'message/rfc822', encoding: 'base64', content: inner.toString('base64') }]
            },
            null
        );
        assert.match(res.raw.toString(), /Content-Transfer-Encoding: 7bit/i);
    });

    await t.test('returnObject returns the composer options and a computed envelope', async () => {
        const res = await getRawEmail(
            {
                messageId: '<fixed@local>',
                from: { address: 'alice@example.com' },
                to: [{ address: 'bob@example.org' }],
                cc: [{ address: 'carol@example.org' }],
                bcc: [{ address: 'secret@example.com' }],
                subject: 'Obj',
                text: 'x'
            },
            null,
            { returnObject: true }
        );

        assert.strictEqual(res.raw, undefined);
        assert.ok(res.emailObject);
        assert.strictEqual(res.emailObject.subject, 'Obj');
        assert.strictEqual(res.messageId, '<fixed@local>');
        assert.strictEqual(res.envelope.from, 'alice@example.com');
        // Envelope recipients are the de-duplicated union of to/cc/bcc.
        assert.deepStrictEqual(res.envelope.to.sort(), ['bob@example.org', 'carol@example.org', 'secret@example.com'].sort());
        assert.strictEqual(res.hasBcc, true);
    });
});

test('removeBcc', async t => {
    await t.test('strips the Bcc header but keeps everything else', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Bcc: secret@example.com', 'Subject: keep'], 'body stays');
        const out = (await removeBcc(raw)).toString();

        assert.doesNotMatch(out, /^Bcc:/im);
        assert.match(out, /^From: a@example\.com/m);
        assert.match(out, /^To: b@example\.com/m);
        assert.match(out, /^Subject: keep/m);
        assert.match(out, /body stays/);
    });

    await t.test('is a no-op for a message without a Bcc header', async () => {
        const raw = rawMessage(['From: a@example.com', 'To: b@example.com', 'Subject: no bcc'], 'body');
        const out = (await removeBcc(raw)).toString();
        assert.match(out, /^Subject: no bcc/m);
        assert.match(out, /body/);
    });
});
