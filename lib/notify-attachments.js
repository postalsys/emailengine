'use strict';

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

module.exports = { withinNotifyAttachmentSize };
