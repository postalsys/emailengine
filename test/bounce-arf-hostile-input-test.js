'use strict';

// Hostile-input tests for lib/bounce-detect.js and lib/arf-detect.js. Both run inside the IMAP
// worker on messages any outside sender can deliver, so a pattern that goes quadratic stalls every
// account on that worker. The inputs here are the ones that used to take seconds at the 50 KB
// heuristic window (bounce) or minutes on a large feedback report (ARF).

const test = require('node:test');
const assert = require('node:assert').strict;

// Record the options every simpleParser() call in bounce-detect receives. bounce-detect captures
// the function when it loads, so the wrapper has to be installed before it is required.
const mailparser = require('mailparser');
const realSimpleParser = mailparser.simpleParser;
const parserCalls = [];
mailparser.simpleParser = (input, options, ...rest) => {
    parserCalls.push(options);
    return realSimpleParser(input, options, ...rest);
};

const { bounceDetect, MAX_HEADER_BLOCK_SIZE } = require('../lib/bounce-detect');
const { arfDetect } = require('../lib/arf-detect');

mailparser.simpleParser = realSimpleParser;

async function timeIt(fn) {
    const start = process.hrtime.bigint();
    await fn();
    return Number(process.hrtime.bigint() - start) / 1e6;
}

// Linear work: doubling the input must not more than roughly triple the time. The floor keeps
// timer noise on sub-millisecond runs from failing the ratio.
async function assertScalesLinearly(label, build, size) {
    const small = await timeIt(() => build(size / 2));
    const large = await timeIt(() => build(size));
    assert.ok(large < 500, `${label}: ${large.toFixed(1)} ms at full size`);
    assert.ok(large <= Math.max(small * 3, 50), `${label}: ${small.toFixed(1)} ms -> ${large.toFixed(1)} ms when doubled`);
}

const heuristicInput = parsedText => bounceDetect({ parsed: { text: parsedText, attachments: [], headers: new Map() } });

test('bounce heuristics stay linear on hostile text at the 50 KB window', async t => {
    const SIZE = 50000;

    await t.test('a run of blank lines (SMTP reply at line start)', () => assertScalesLinearly('newlines', n => heuristicInput('\n'.repeat(n)), SIZE));

    await t.test('a run of "<" (Postfix "host ... said:")', () => assertScalesLinearly('angle brackets', n => heuristicInput('<'.repeat(n)), SIZE));

    await t.test('a newline then a run of "<" ("<addr>:" block)', () =>
        assertScalesLinearly('newline angle', n => heuristicInput('\n<' + '<'.repeat(n)), SIZE)
    );

    await t.test('unterminated addresses', () => assertScalesLinearly('open addresses', n => heuristicInput('<a@'.repeat(Math.floor(n / 3))), SIZE));

    await t.test('a line of repeated "Error:" (mobile carrier style)', () =>
        assertScalesLinearly('Error:', n => heuristicInput('Error:'.repeat(Math.floor(n / 6))), SIZE)
    );

    await t.test('"host" without a colon inside the Postfix recipient block', () => {
        // Reaching this branch needs a recipient and a response without a message, which a
        // delivery-status part with a Status but no Diagnostic-Code provides
        const build = n =>
            bounceDetect({
                parsed: {
                    text: 'A message that you sent could not be delivered\n' + ' host a'.repeat(Math.floor(n / 7)) + ' x@example.com',
                    attachments: [
                        {
                            contentType: 'message/delivery-status',
                            content: Buffer.from(
                                'Reporting-MTA: dns; mta.example.com\n\nFinal-Recipient: rfc822; x@example.com\nAction: failed\nStatus: 5.1.1\n'
                            )
                        }
                    ],
                    headers: new Map()
                }
            });
        return assertScalesLinearly('host block', build, SIZE);
    });

    await t.test('ordinary formats are still recognised', async () => {
        let result = await heuristicInput('<bob@example.com>: host mx.example.com[203.0.113.4] said: 550 5.1.1 No such user here\n');
        assert.equal(result.recipient, 'bob@example.com');
        assert.equal(result.mta, 'mx.example.com');

        result = await heuristicInput('Technical details:\n\n550-5.7.1 [1.2.3.4 11] Message rejected\n');
        assert.equal(result.response.status, '5.7.1');

        result = await heuristicInput('Sorry\n<carol@example.com>:\n550: 5.1.1 <carol@example.com>: Recipient address rejected\n');
        assert.equal(result.recipient, 'carol@example.com');

        result = await heuristicInput('Status: failed\nError: No valid recipients for this MM\n');
        assert.equal(result.response.message, 'Error: No valid recipients for this MM');
    });
});

test('a huge delivery-status part is cut before its headers are unfolded', async () => {
    // One folded header of a few hundred thousand continuation lines: libmime's unfolding is
    // quadratic in the line count, so the body is capped at MAX_HEADER_BLOCK_SIZE first
    const build = n =>
        bounceDetect({
            parsed: {
                text: '',
                html: false,
                attachments: [
                    {
                        contentType: 'message/delivery-status',
                        content: Buffer.from('Final-Recipient: rfc822; x@example.com\nAction: failed\nStatus: 5.1.1\nX-Fold: a\n' + ' b\n'.repeat(n))
                    }
                ],
                headers: new Map()
            }
        });
    const full = await timeIt(() => build(400000));
    assert.ok(full < 1000, `delivery-status with 400k folded lines took ${full.toFixed(1)} ms`);
    assert.equal(MAX_HEADER_BLOCK_SIZE, 64 * 1024);

    const result = await build(400000);
    assert.equal(result.recipient, 'x@example.com');
    assert.equal(result.action, 'failed');
});

test('every simpleParser call in bounce-detect keeps cid links', async () => {
    // Without keepCidLinks mailparser replaces every cid: reference in the HTML with the whole
    // image as a data URL, once per reference, which a small DSN can grow past the maximum
    // string length in a callback no caller can catch
    const image = Buffer.alloc(2048, 1).toString('base64');
    const html = '<p>' + '<img src="cid:img1">'.repeat(50) + '</p>';
    const original = ['From: a@example.com', 'Message-ID: <orig@example.com>', 'Content-Type: text/plain', '', 'hello'].join('\r\n');
    const zoho = ['Received: from x', 'Message-ID: <zoho@example.com>'].join('\r\n');
    const raw = [
        'From: Mail Delivery System <mailer-daemon@zoho.example.com>',
        'X-Mailer: Zoho Mail',
        'MIME-Version: 1.0',
        'Content-Type: multipart/report; report-type=delivery-status; boundary="r"',
        '',
        '--r',
        'Content-Type: multipart/related; boundary="h"',
        '',
        '--h',
        'Content-Type: text/html',
        '',
        html,
        '--h',
        'Content-Type: image/png',
        'Content-ID: <img1>',
        'Content-Transfer-Encoding: base64',
        '',
        image,
        '--h--',
        '--r',
        'Content-Type: message/delivery-status',
        '',
        'Final-Recipient: rfc822; x@example.com',
        'Action: failed',
        'Status: 5.1.1',
        '',
        '--r',
        'Content-Type: message/rfc822',
        '',
        original,
        '--r',
        'Content-Type: text/rfc822',
        '',
        zoho,
        '--r--',
        ''
    ].join('\r\n');

    parserCalls.length = 0;
    const result = await bounceDetect(Buffer.from(raw));
    assert.equal(result.recipient, 'x@example.com');

    // the top-level parse, the message/rfc822 part and the Zoho text/rfc822 part
    assert.equal(parserCalls.length, 3);
    for (const options of parserCalls) {
        assert.equal(options.keepCidLinks, true);
        assert.equal(options.skipImageLinks, true);
        assert.equal(options.keepDeliveryStatus, true);
    }
});

test('ARF: a long whitespace run in Original-Mail-From stays linear', async () => {
    const build = n =>
        arfDetect({
            attachments: [
                {
                    contentType: 'message/feedback-report',
                    content: Buffer.from(`Feedback-Type: abuse\r\nOriginal-Mail-From: <a${' '.repeat(n)}b>\r\n`)
                }
            ]
        });
    await assertScalesLinearly('Original-Mail-From', build, 40000);

    const report = await arfDetect({
        attachments: [
            { contentType: 'message/feedback-report', content: Buffer.from('Feedback-Type: abuse\r\nOriginal-Mail-From: < sender@example.com >\r\n') }
        ]
    });
    assert.equal(report.arf['original-mail-from'], 'sender@example.com');
    assert.equal(report.arf['feedback-type'], 'abuse');
});

test('ARF: fields are capped in length', async () => {
    const report = await arfDetect({
        attachments: [
            {
                contentType: 'message/feedback-report',
                content: Buffer.from(`Feedback-Type: abuse\r\nUser-Agent: ${'x'.repeat(10000)}\r\nReported-Domain: ${'d'.repeat(10000)}\r\n`)
            }
        ]
    });
    assert.equal(report.arf['feedback-type'], 'abuse');
    assert.equal(report.arf['user-agent'].length, 2048);
    assert.ok(report.arf['reported-domain'].every(value => value.length <= 2048));
});

test('ARF: huge folded report and original headers are cut before decoding', async () => {
    const build = n =>
        arfDetect({
            attachments: [
                { contentType: 'message/feedback-report', content: Buffer.from('Feedback-Type: abuse\r\nX-Fold: a\r\n' + ' b\r\n'.repeat(n)) },
                { contentType: 'text/rfc822-headers', content: Buffer.from('Message-ID: <m@example.com>\r\nX-Fold: a\r\n' + ' b\r\n'.repeat(n)) }
            ]
        });
    const elapsed = await timeIt(() => build(400000));
    assert.ok(elapsed < 1000, `ARF with 400k folded lines took ${elapsed.toFixed(1)} ms`);

    const report = await build(400000);
    assert.equal(report.arf['feedback-type'], 'abuse');
    assert.equal(report.headers['message-id'], '<m@example.com>');
});
