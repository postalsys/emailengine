'use strict';

// Which attachments of an IMAP message its html shows inline, and which body parts have to be
// downloaded to embed them. Shared by Mailbox.getMessage() (embedAttachedImages) and
// Mailbox.processNew() (the web-safe copy of a new message), which carried copies of this loop.

const { collectCidReferences } = require('../../tools');
const { MAX_INLINE_ATTACHMENT_SIZE } = require('../../consts');

/**
 * Collects the attachments the html of a message refers to by content id. Each one that has to be
 * downloaded gets its IMAP body part as a non-enumerable `part` property (read off the attachment
 * id, which carries it after an 8 byte prefix), so it never reaches a serialized message.
 *
 * @param {Object} messageInfo - Message with text.html and attachments
 * @param {Object} [opts]
 * @param {boolean} [opts.reuseLoaded] - Keep content an attachment already carries, and do not
 *     download such an attachment or one larger than MAX_INLINE_ATTACHMENT_SIZE
 * @returns {{attachmentList: Map<string, {attachment: Object, content: *}>, partList: string[]}}
 *     the referenced attachments by content id, and the distinct body parts to download
 */
function collectCidParts(messageInfo, opts) {
    opts = opts || {};

    let attachmentList = new Map();
    let partList = [];
    let cidReferences = collectCidReferences(messageInfo.text.html);

    for (let attachment of messageInfo.attachments || []) {
        let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
        if (!contentId || !cidReferences.has(contentId)) {
            continue;
        }

        attachmentList.set(contentId, {
            attachment,
            content: (opts.reuseLoaded && attachment.content) || null
        });

        if (opts.reuseLoaded && (attachment.content || (attachment.encodedSize && attachment.encodedSize > MAX_INLINE_ATTACHMENT_SIZE))) {
            // already loaded by notifyAttachments, or too large to inline
            continue;
        }

        let buf = Buffer.from(attachment.id, 'base64url');
        let part = buf.subarray(8).toString();

        Object.defineProperty(attachment, 'part', {
            value: part,
            enumerable: false
        });

        if (!partList.includes(part)) {
            partList.push(part);
        }
    }

    return { attachmentList, partList };
}

module.exports = { collectCidParts };
