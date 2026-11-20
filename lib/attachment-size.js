'use strict';

// Base64 lines are 76 characters long (RFC 2045 section 6.8) and each ends in CRLF
const BASE64_LINE = 78;

/**
 * The size of an IMAP attachment once its transfer encoding is undone, from the size of the
 * encoded body part the BODYSTRUCTURE reports. base64 carries 3 bytes in 4 characters with a line
 * break after every 76, so the file size is computed from it, assuming the standard 76 character lines (base64 written
 * with other line lengths, or none, comes out up to about 2.5% off).
 * Other encodings are left at the encoded size: 7bit, 8bit and binary are the file itself, and
 * quoted-printable can not be undone without the content, so its encoded size is an upper bound.
 *
 * @param {number} encodedSize - Size of the encoded body part in bytes
 * @param {string} [encoding] - Content-Transfer-Encoding of the part
 * @returns {number|undefined} Size of the attachment in bytes
 */
function decodedAttachmentSize(encodedSize, encoding) {
    if (typeof encodedSize !== 'number' || !Number.isFinite(encodedSize) || encodedSize < 0) {
        return undefined;
    }
    if (String(encoding || '').toLowerCase() !== 'base64') {
        return encodedSize;
    }
    const lineBreaks = Math.floor(encodedSize / BASE64_LINE) * 2;
    return Math.floor(((encodedSize - lineBreaks) * 3) / 4);
}

module.exports = { decodedAttachmentSize };
