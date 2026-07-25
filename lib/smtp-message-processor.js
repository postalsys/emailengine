'use strict';

// Inbound message processing for the built-in SMTP submission server (workers/smtp.js).
//
// Lives here rather than inline in the worker for the same reason the auth handler does
// (lib/smtp-auth.js): the worker requires worker_threads and boots an SMTPServer on load, so
// nothing inside it can be unit tested. This piece is worth testing on its own because it is
// the only place the EmailEngine-specific control headers are consumed, and every one of them
// MUST be stripped before the message goes out - a leaked X-EE-Account header discloses the
// internal account id to the recipient.

const { Splitter, Joiner } = require('@zone-eu/mailsplit');
const { HeadersRewriter } = require('./headers-rewriter');

// Control headers a client may set on a submitted message. Each is read into `meta` and then
// removed from the message. Header lookups are case-insensitive (mailsplit lowercases keys).
const ACCOUNT_HEADER = 'x-ee-account';
const IDEMPOTENCY_HEADER = 'x-ee-idempotency-key';

/**
 * Pipes a submitted message through the MIME splitter, strips the EmailEngine control headers
 * into `meta`, and rejoins it.
 *
 * @param {Stream} stream - Raw message stream from the SMTP server
 * @param {Object} [meta] - Collector object; receives requestedAccount / idempotencyKey
 * @returns {Stream} Stream of the rewritten message
 */
function processMessage(stream, meta) {
    meta = meta || {};
    const splitter = new Splitter();
    const joiner = new Joiner();

    const headersRewriter = new HeadersRewriter(async headers => {
        let requestedAccount = headers.getFirst(ACCOUNT_HEADER);
        headers.remove(ACCOUNT_HEADER);
        if (requestedAccount) {
            meta.requestedAccount = requestedAccount;
        }

        let idempotencyKey = headers.getFirst(IDEMPOTENCY_HEADER);
        headers.remove(IDEMPOTENCY_HEADER);
        if (idempotencyKey) {
            meta.idempotencyKey = idempotencyKey;
        }
    });

    // Forward the errors of every stage to the joiner, which is the only stream the caller ever
    // sees. Readable.pipe() attaches an 'error' listener to the destination only, so an error
    // raised anywhere upstream has no listener at all and takes the worker down as an uncaught
    // exception. The splitter must be on this list too: it enforces a 1MB per-MIME-node header
    // cap and a child-node limit (both 'EMAXLEN'), so any client that can reach the submission
    // port can trigger one with a single oversized message.
    for (let source of [stream, splitter, headersRewriter]) {
        source.once('error', err => joiner.emit('error', err));
    }

    return stream.pipe(splitter).pipe(headersRewriter).pipe(joiner);
}

/**
 * Buffers a submitted message: runs it through processMessage() and collects the result.
 *
 * The size verdict is read from the RAW stream. smtp-server keeps byteLength/sizeExceeded on the
 * DATA stream it hands to onData, not on the rewritten stream returned by processMessage(), and
 * it only refuses an oversized message on its own when the client volunteered a SIZE= parameter
 * with MAIL FROM. Without a SIZE= it truncates the DATA stream and leaves the rejection to the
 * application, so reading the flag off the wrong object means truncated messages get queued and
 * delivered instead of being answered with a 552.
 *
 * @param {Stream} rawStream - Raw DATA stream from the SMTP server
 * @param {Object} [meta] - Collector object; receives requestedAccount / idempotencyKey
 * @returns {Promise<{message: Buffer, sizeExceeded: Boolean}>} Rewritten message and size verdict
 */
function collectMessage(rawStream, meta) {
    return new Promise((resolve, reject) => {
        const stream = processMessage(rawStream, meta);

        let chunks = [];
        let chunklen = 0;

        // Covers the source stream, the MIME splitter and the headers rewriter - processMessage()
        // forwards all three here. A promise settles once, so a stream error arriving after the
        // message was already collected can not produce a second SMTP response.
        stream.on('error', reject);

        stream.on('readable', () => {
            let chunk;
            while ((chunk = stream.read()) !== null) {
                // Stop buffering once the limit is blown; the message is rejected either way and
                // there is no reason to hold the rest of it in memory.
                if (!rawStream.sizeExceeded) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            }
        });

        stream.on('end', () => {
            const message = Buffer.concat(chunks, chunklen);
            // Release the per-chunk copies right away. The listeners above close over `chunks`
            // and stay attached to the joiner until the submission finishes, so without this the
            // account lookup and the queueing that follow run with two full copies of the message
            // live - up to 2x EENGINE_MAX_SMTP_MESSAGE_SIZE per concurrent submission.
            chunks = null;
            resolve({ message, sizeExceeded: !!rawStream.sizeExceeded });
        });
    });
}

module.exports = { processMessage, collectMessage, ACCOUNT_HEADER, IDEMPOTENCY_HEADER };
