'use strict';

const { mapConcurrent } = require('./utils/map-concurrent');

// Attachment downloads a Gmail API or Graph client runs at once for one message
const API_ATTACHMENT_CONCURRENCY = 4;

// Whether an attachment's content belongs in a messageNew payload under the notifyAttachmentSize
// setting. Both processNew() implementations ask it before downloading an attachment and
// formatPayload() asks it again for content loaded on other paths, such as inline images the
// web-safe embed fetched, so what is downloaded and what is kept cannot disagree. An attachment is
// measured by the encoded size the message structure reports, and only content without one by its
// decoded size.
function withinNotifyAttachmentSize(attachment, notifyAttachmentSize) {
    if (!notifyAttachmentSize) {
        return true;
    }
    let size = attachment.encodedSize || (attachment.content ? (attachment.content.length / 4) * 3 : 0);
    return size <= notifyAttachmentSize;
}

/**
 * Loads the content of every attachment the messageNew webhook carries (`notifyAttachments`), the
 * ones over `notifyAttachmentSize` excepted. Shared by the IMAP mailbox and the API clients
 * @param {Object[]} attachments - The message's attachments
 * @param {number} sizeLimit - The notifyAttachmentSize setting
 * @param {Function} load - async (attachment) => void, sets attachment.content (base64) when it can
 * @param {number} [concurrency=1] - Downloads at a time: one for IMAP, where they share the
 *     connection, a few for the API clients, where each is an HTTP request of its own
 */
async function loadNotifyAttachments(attachments, sizeLimit, load, concurrency = 1) {
    const pending = (attachments || []).filter(attachment => withinNotifyAttachmentSize(attachment, sizeLimit) && !attachment.content);
    await mapConcurrent(pending, concurrency, load);
}

module.exports = { withinNotifyAttachmentSize, loadNotifyAttachments, API_ATTACHMENT_CONCURRENCY };
