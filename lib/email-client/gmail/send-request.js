'use strict';

// Which Gmail send endpoint a message goes to, and how its body is encoded.
//
// Extracted from GmailClient.submitMessage() because it is a three-way branch on message size
// and threading that decides the endpoint, the content type AND the payload encoding, and it is
// unreachable from a test in place (submitMessage needs a live account, an OAuth app and a
// BullMQ job). Getting it wrong does not fail loudly: the message is simply rejected by Gmail,
// or silently loses its thread.

const crypto = require('crypto');

// The JSON endpoint accepts a 5MB request body, and base64url inflates the raw message by ~4/3,
// so anything above ~3.5MB raw has to go to the upload endpoint (which takes 35MB raw RFC822).
const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;

/**
 * Builds the Gmail send request for a raw RFC822 message.
 *
 * @param {Buffer} raw - Complete RFC822 message
 * @param {String} [threadId] - Gmail thread to attach the message to
 * @returns {Object} { targetEndpoint, contentType, payload } - endpoint is relative to GMAIL_API_BASE
 */
function buildSendRequest(raw, threadId) {
    if (raw.length <= JSON_SEND_LIMIT) {
        // JSON endpoint with base64url encoding (retry-safe, no ArrayBuffer issues)
        const payload = { raw: raw.toString('base64url') };
        if (threadId) {
            payload.threadId = threadId;
        }
        return {
            targetEndpoint: `/gmail/v1/users/me/messages/send`,
            contentType: 'application/json',
            payload
        };
    }

    if (threadId) {
        // Large threaded reply: multipart upload preserves explicit threadId
        // via JSON metadata alongside the raw RFC822 message body
        const boundary = `ee_${crypto.randomBytes(16).toString('hex')}`;
        const metadata = JSON.stringify({ threadId });
        const preamble = Buffer.from(
            `--${boundary}\r\n` +
                `Content-Type: application/json; charset=UTF-8\r\n` +
                `\r\n` +
                `${metadata}\r\n` +
                `--${boundary}\r\n` +
                `Content-Type: message/rfc822\r\n` +
                `\r\n`
        );
        const epilogue = Buffer.from(`\r\n--${boundary}--`);

        return {
            targetEndpoint: `/upload/gmail/v1/users/me/messages/send?uploadType=multipart`,
            contentType: `multipart/related; boundary=${boundary}`,
            payload: Buffer.concat([preamble, raw, epilogue])
        };
    }

    // Large non-threaded message: simple upload with raw RFC822 Buffer
    return {
        targetEndpoint: `/upload/gmail/v1/users/me/messages/send`,
        contentType: 'message/rfc822',
        payload: raw
    };
}

module.exports = { buildSendRequest, JSON_SEND_LIMIT };
