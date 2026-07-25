'use strict';

// Control-header handling for the built-in SMTP submission server (lib/smtp-message-processor.js).
//
// These headers are the documented way a legacy client picks the sending account and dedupes a
// retry over plain SMTP. Two properties matter and neither had any coverage:
//
//   1. The value is captured, so onData() can route the message to the right account and pass
//      the idempotency key on to queueMessage().
//   2. The header is REMOVED. Whatever survives here is delivered to the recipient, so a leaked
//      X-EE-Account discloses the internal account id of the sender.
//
// The module is stream-only (mailsplit + the headers rewriter), with no Redis or worker
// dependency, so these are plain unit tests.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable } = require('node:stream');

const { processMessage, collectMessage, ACCOUNT_HEADER, IDEMPOTENCY_HEADER } = require('../lib/smtp-message-processor');

function buildMessage(headerLines, body = 'Message body here.') {
    return [...headerLines, '', body].join('\r\n');
}

// Stands in for the raw DATA stream smtp-server hands to onData: a stream that also carries the
// running size accounting as properties (node_modules/smtp-server/lib/smtp-stream.js sets
// byteLength/sizeExceeded on the stream object itself).
function rawDataStream(source, { sizeExceeded = false } = {}) {
    const stream = Readable.from([Buffer.from(source)]);
    stream.sizeExceeded = sizeExceeded;
    return stream;
}

// A header block over the splitter's 1MB per-MIME-node cap. Any client that can reach the
// submission port can send one.
function oversizedHeaderMessage() {
    return buildMessage(['From: sender@example.com', `X-Padding: ${'a'.repeat(1024 * 1024 + 16)}`]);
}

// Runs a raw message through processMessage() and returns the rewritten message plus the meta
// the worker would then act on.
async function run(source) {
    const meta = {};
    const stream = processMessage(Readable.from([Buffer.from(source)]), meta);

    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(chunk);
    }

    return { output: Buffer.concat(chunks).toString(), meta };
}

test('SMTP submission message processing', async t => {
    await t.test('the control header names are the documented ones', async () => {
        // Every other case below builds its fixture from these constants, so a renamed VALUE
        // would keep the suite green while breaking every client that sets the documented
        // header. These are a public wire contract, so they are pinned literally here.
        assert.strictEqual(ACCOUNT_HEADER, 'x-ee-account');
        assert.strictEqual(IDEMPOTENCY_HEADER, 'x-ee-idempotency-key');
    });

    await t.test('X-EE-Account is captured and stripped from the delivered message', async () => {
        const { output, meta } = await run(
            buildMessage(['From: sender@example.com', 'To: recipient@example.com', 'Subject: Routed', `${ACCOUNT_HEADER}: my-account`])
        );

        assert.strictEqual(meta.requestedAccount, 'my-account');
        assert.doesNotMatch(output, /x-ee-account/i, 'the routing header must never reach the recipient');
        assert.match(output, /Subject: Routed/, 'the rest of the headers survive');
        assert.match(output, /Message body here\./, 'the body survives');
    });

    await t.test('X-EE-Idempotency-Key is captured and stripped', async () => {
        const { output, meta } = await run(
            buildMessage(['From: sender@example.com', 'Subject: Deduped', `${IDEMPOTENCY_HEADER}: 550e8400-e29b-41d4-a716-446655440000`])
        );

        assert.strictEqual(meta.idempotencyKey, '550e8400-e29b-41d4-a716-446655440000');
        assert.doesNotMatch(output, /x-ee-idempotency-key/i);
    });

    await t.test('both control headers are handled in one pass', async () => {
        const { output, meta } = await run(
            buildMessage([
                'From: sender@example.com',
                `${ACCOUNT_HEADER}: acct-1`,
                'Subject: Both',
                `${IDEMPOTENCY_HEADER}: key-1`,
                'To: recipient@example.com'
            ])
        );

        assert.deepStrictEqual(meta, { requestedAccount: 'acct-1', idempotencyKey: 'key-1' });
        assert.doesNotMatch(output, /x-ee-/i);
        assert.match(output, /Subject: Both/);
        assert.match(output, /To: recipient@example\.com/);
    });

    await t.test('header names are matched case-insensitively', async () => {
        // SMTP clients spell headers however they like; a case-sensitive match would both miss
        // the routing value AND leave the header in the delivered message.
        const { output, meta } = await run(buildMessage(['From: sender@example.com', 'X-Ee-Account: mixed-case', 'X-EE-IDEMPOTENCY-KEY: SHOUTED']));

        assert.strictEqual(meta.requestedAccount, 'mixed-case');
        assert.strictEqual(meta.idempotencyKey, 'SHOUTED');
        assert.doesNotMatch(output, /x-ee-/i);
    });

    await t.test('a message with no control headers leaves meta empty and the message intact', async () => {
        const source = buildMessage(['From: sender@example.com', 'To: recipient@example.com', 'Subject: Plain']);
        const { output, meta } = await run(source);

        assert.deepStrictEqual(meta, {});
        assert.match(output, /Subject: Plain/);
        assert.match(output, /Message body here\./);
    });

    await t.test('an empty control header value is stripped without setting meta', async () => {
        // getFirst() returns '' - falsy, so no routing is requested, but the header still has to go
        const { output, meta } = await run(buildMessage(['From: sender@example.com', `${ACCOUNT_HEADER}:`, 'Subject: Empty']));

        assert.strictEqual(meta.requestedAccount, undefined);
        assert.doesNotMatch(output, /x-ee-account/i);
    });

    await t.test('every occurrence of a repeated control header is removed', async () => {
        // A client (or an intermediary) that sets the header twice must not have the second copy
        // delivered just because only the first was read.
        const { output, meta } = await run(
            buildMessage(['From: sender@example.com', `${ACCOUNT_HEADER}: first`, `${ACCOUNT_HEADER}: second`, 'Subject: Repeated'])
        );

        assert.strictEqual(meta.requestedAccount, 'first', 'the first occurrence wins');
        assert.doesNotMatch(output, /x-ee-account/i, 'no copy of the header may survive');
    });

    await t.test('control headers inside an attached message/rfc822 are left alone', async () => {
        // Only the top level node is rewritten. A forwarded message that happens to carry the
        // header is content, not a routing instruction, and rewriting it would corrupt the
        // attachment (and change the outer message's meaning).
        const source = [
            'From: sender@example.com',
            'Subject: Forwarded',
            'MIME-Version: 1.0',
            'Content-Type: multipart/mixed; boundary=BOUND',
            '',
            '--BOUND',
            'Content-Type: text/plain',
            '',
            'See attached.',
            '--BOUND',
            'Content-Type: message/rfc822',
            '',
            'From: original@example.com',
            `${ACCOUNT_HEADER}: inner-account`,
            'Subject: Original',
            '',
            'Original body.',
            '--BOUND--',
            ''
        ].join('\r\n');

        const { output, meta } = await run(source);

        assert.strictEqual(meta.requestedAccount, undefined, 'an embedded header must not redirect the submission');
        assert.match(output, /inner-account/, 'the attached message must be delivered unmodified');
    });

    await t.test('the message body is byte-preserved through the rewrite', async () => {
        const body = ['Line one', 'Line two with trailing spaces   ', '', 'Unicode: äöü 日本語 emoji-free', 'Final line'].join('\r\n');
        const source = buildMessage(['From: sender@example.com', 'Content-Type: text/plain; charset=utf-8', `${ACCOUNT_HEADER}: acct`], body);

        const { output } = await run(source);

        assert.ok(output.includes(body), 'the body must survive the split/rejoin unchanged');
    });

    await t.test('a source stream error surfaces on the returned stream instead of going unhandled', async () => {
        // An aborted SMTP DATA transfer must reject the onData callback, not crash the worker
        // through an unhandled error event.
        const failing = new Readable({
            read() {
                this.destroy(new Error('connection reset mid-DATA'));
            }
        });

        const stream = processMessage(failing, {});

        await assert.rejects(
            (async () => {
                for await (const chunk of stream) {
                    void chunk;
                }
            })(),
            /connection reset mid-DATA/
        );
    });

    await t.test('a MIME parse error surfaces on the returned stream instead of going unhandled', async () => {
        // The splitter enforces its own limits (1MB of headers per MIME node, 1000 child nodes).
        // Those errors are raised on the splitter, which is an INTERMEDIATE stage: pipe() only
        // attaches an error listener to the destination, so nothing the caller does can catch
        // them unless they are forwarded. Unforwarded, one oversized header block from any
        // client that reaches the submission port kills the whole SMTP worker thread.
        const stream = processMessage(Readable.from([Buffer.from(oversizedHeaderMessage())]), {});

        await assert.rejects(
            (async () => {
                for await (const chunk of stream) {
                    void chunk;
                }
            })(),
            /Max header size/
        );
    });
});

test('SMTP submission message collection', async t => {
    await t.test('a submitted message is buffered with the control headers already stripped', async () => {
        const meta = {};
        const { message, sizeExceeded } = await collectMessage(
            rawDataStream(buildMessage(['From: sender@example.com', `${ACCOUNT_HEADER}: acct-1`, 'Subject: Collected'])),
            meta
        );

        assert.strictEqual(sizeExceeded, false);
        assert.strictEqual(meta.requestedAccount, 'acct-1');
        assert.doesNotMatch(message.toString(), /x-ee-account/i);
        assert.match(message.toString(), /Subject: Collected/);
    });

    await t.test('the size verdict is read from the raw stream, where smtp-server keeps it', async () => {
        // smtp-server sets sizeExceeded on the DATA stream it hands to onData, never on the
        // rewritten stream. Reading it off the rewritten stream made the flag permanently
        // undefined, so the 552 rejection was dead code and truncated messages were queued and
        // delivered as if they were complete.
        const { message, sizeExceeded } = await collectMessage(
            rawDataStream(buildMessage(['From: sender@example.com', 'Subject: Too big']), { sizeExceeded: true }),
            {}
        );

        assert.strictEqual(sizeExceeded, true, 'an oversized message must be reported so onData can answer 552');
        assert.strictEqual(message.length, 0, 'no reason to buffer a message that is going to be rejected');
    });

    await t.test('a source stream error rejects instead of resolving with a partial message', async () => {
        const failing = new Readable({
            read() {
                this.destroy(new Error('connection reset mid-DATA'));
            }
        });
        failing.sizeExceeded = false;

        await assert.rejects(collectMessage(failing, {}), /connection reset mid-DATA/);
    });

    await t.test('a MIME parse error rejects instead of killing the worker', async () => {
        await assert.rejects(collectMessage(rawDataStream(oversizedHeaderMessage()), {}), /Max header size/);
    });
});
