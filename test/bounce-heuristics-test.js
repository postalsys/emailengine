'use strict';

// Unit tests for the text-heuristic fallback in lib/bounce-detect.js. The
// existing bounce-test.js covers structured RFC 3464 delivery-status parsing;
// this covers the regex-based body heuristics used when a bounce has no
// machine-readable delivery-status attachment (Postfix/Exim, Google's old
// format, X-Failed-Recipients, non-standard "<addr>:" blocks). These matchers
// are the most format-fragile part of bounce detection and had no coverage.

const test = require('node:test');
const assert = require('node:assert').strict;

const { bounceDetect } = require('../lib/bounce-detect');

// Build a minimal RFC822 plaintext message so the body lands in parsed.text and
// no delivery-status attachment exists (forcing the text-heuristic path).
function buildBounce(headers, body) {
    const lines = [
        'From: Mail Delivery System <mailer-daemon@mta.example.com>',
        'To: sender@example.com',
        'Subject: Mail delivery failed',
        'Date: Wed, 01 Jan 2025 00:00:00 +0000',
        'MIME-Version: 1.0'
    ];
    for (const [key, value] of Object.entries(headers || {})) {
        lines.push(`${key}: ${value}`);
    }
    lines.push('Content-Type: text/plain; charset=utf-8');
    lines.push('');
    lines.push(body);
    return Buffer.from(lines.join('\r\n'));
}

test('bounce-detect text heuristics', async t => {
    await t.test('returns empty object for empty input', async () => {
        assert.deepStrictEqual(await bounceDetect(null), {});
    });

    await t.test('parses Postfix "host ... said:" format', async () => {
        const body = ['<bob@example.com>: host mx.example.com[203.0.113.4] said: 550 5.1.1 No such user here', '(in reply to RCPT TO command)', ''].join(
            '\r\n'
        );
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'bob@example.com');
        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.mta, 'mx.example.com');
        assert.strictEqual(bounce.response.status, '5.1.1');
        assert.match(bounce.response.message, /No such user here/);
    });

    await t.test('extracts recipient from the X-Failed-Recipients header', async () => {
        const bounce = await bounceDetect(buildBounce({ 'X-Failed-Recipients': 'carol@example.com' }, 'Your message could not be delivered.'));
        assert.strictEqual(bounce.recipient, 'carol@example.com');
    });

    await t.test('uses the first address when X-Failed-Recipients lists several', async () => {
        const bounce = await bounceDetect(buildBounce({ 'X-Failed-Recipients': 'first@example.com, second@example.com' }, 'Delivery problem.'));
        assert.strictEqual(bounce.recipient, 'first@example.com');
    });

    await t.test('parses Google old-style permanent failure', async () => {
        const body = [
            'Delivery to the following recipient failed permanently:',
            '',
            '     dave@example.com',
            '',
            'Technical details of permanent failure:',
            'Google tried to deliver your message, but it was rejected by the recipient domain.',
            ''
        ].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'dave@example.com');
        assert.strictEqual(bounce.action, 'failed');
    });

    await t.test('parses a non-standard "<addr>:" rejection block', async () => {
        const body = [
            'Sorry, we were unable to deliver your message to the following address.',
            '',
            '<erin@example.com>:',
            '550: 5.1.1 <erin@example.com>: Recipient address rejected: User unknown in relay recipient table',
            ''
        ].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'erin@example.com');
        assert.strictEqual(bounce.action, 'failed');
        assert.match(bounce.response.message, /Recipient address rejected/);
    });

    await t.test('parses a bare SMTP status line ("550 5.7.1 ...")', async () => {
        const body = ['Technical details of permanent failure:', '', '550 5.7.1 Message rejected due to content policy', ''].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.action, 'failed');
        assert.strictEqual(bounce.response.status, '5.7.1');
        assert.match(bounce.response.message, /Message rejected/);
    });

    // A delay notice is not a bounce. mightBeABounce() admits any MAILER-DAEMON sender, and these
    // notices carry the same recipient block or quoted reply the heuristics read a bounce off, so
    // the action they set is what keeps a still-retrying message out of the bounce store and the
    // emailBounce webhook
    await t.test('does not report a "WARNING MESSAGE ONLY" delay notice as a bounce', async () => {
        const body = [
            'Hi. This is the mail delivery program at mail.example.com.',
            "I'm afraid I wasn't able to deliver your message to the following addresses yet.",
            'THIS IS A WARNING MESSAGE ONLY.',
            'YOU DO NOT NEED TO RESEND YOUR MESSAGE.',
            '',
            '<frank@example.com>:',
            "Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)",
            "I'll keep trying for a while longer.",
            ''
        ].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'frank@example.com');
        assert.strictEqual(bounce.response.status, '4.4.1');
        assert.strictEqual(bounce.action, undefined);
    });

    await t.test('does not report a quoted 4xx "said:" reply as a bounce', async () => {
        const body = [
            '<grace@example.com>: host mx.example.com[203.0.113.4] said: 450 4.2.1 Mailbox temporarily unavailable',
            '(in reply to RCPT TO command)',
            ''
        ].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'grace@example.com');
        assert.strictEqual(bounce.response.status, '4.2.1');
        assert.strictEqual(bounce.action, undefined);
    });

    await t.test('keeps a final bounce that quotes the last temporary reply', async () => {
        // qmail gives up after the queue lifetime and reports the 4.x.x it kept getting
        const body = [
            'Hi. This is the qmail-send program at mail.example.com.',
            "I'm afraid I wasn't able to deliver your message to the following addresses.",
            "This is a permanent error; I've given up. Sorry it didn't work out.",
            '',
            '<heidi@example.com>:',
            "Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)",
            "I'm not going to try again; this message has been in the queue too long.",
            ''
        ].join('\r\n');
        const bounce = await bounceDetect(buildBounce({}, body));

        assert.strictEqual(bounce.recipient, 'heidi@example.com');
        assert.strictEqual(bounce.response.status, '4.4.1');
        assert.strictEqual(bounce.action, 'failed');
    });
});
