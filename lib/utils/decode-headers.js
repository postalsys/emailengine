'use strict';

const libmime = require('libmime');
const { UNSAFE_KEYS } = require('./unsafe-key');

// Largest header block handed to libmime. Its line unfolding used to be quadratic in the line
// count, and the bounce and complaint detectors decode blocks taken from attachments any sender
// controls, so the cut is made here rather than at each caller. No real header block comes
// anywhere near this
const MAX_HEADER_BLOCK_SIZE = 64 * 1024;

/**
 * Returns a header block as a string, cut to MAX_HEADER_BLOCK_SIZE.
 *
 * decodeHeaders() applies this itself; it is exported for the callers that run their own
 * line-based preprocessing over a block before decoding it, so that work is bounded the same way.
 *
 * @param {string|Buffer} content - Raw header block
 * @returns {string}
 */
function capHeaderBlock(content) {
    if (!content) {
        return '';
    }
    if (Buffer.isBuffer(content)) {
        return content.subarray(0, MAX_HEADER_BLOCK_SIZE).toString();
    }
    content = content.toString();
    return content.length > MAX_HEADER_BLOCK_SIZE ? content.substring(0, MAX_HEADER_BLOCK_SIZE) : content;
}

/**
 * Parses a header block into a map of lowercased header name to array of values.
 *
 * Wraps libmime.decodeHeaders() to cut the block to MAX_HEADER_BLOCK_SIZE and to drop names that
 * collide with Object.prototype. Header names come from the message, so any sender can use one,
 * and libmime returns them as real own properties. Neither names a real header, so there is
 * nothing to preserve by keeping them:
 *
 * - an own "__proto__" key is the one thing lib/msgpack.js refuses to decode, so a map carrying it
 *   encodes into webhook logs and message payloads that can never be read back, and it hands
 *   anything that later copies the map with `obj[key] =` or Object.assign a prototype swap
 * - "constructor" is inert on its own, but lib/utils/header-map.js cannot represent it, so keeping
 *   it would describe the same message differently depending on the transport that fetched it
 *
 * Dropping them here rather than at each consumer keeps every parsed header block on one
 * contract: lib/email-client/imap/mailbox.js and lib/bounce-detect.js return these maps to callers
 * verbatim, and lib/arf-detect.js copies them key by key into a published report. It is not the
 * last word on either name though - a consumer that rebuilds a key from the name has to check
 * again, see isUnsafeKey() in lib/utils/unsafe-key.js.
 *
 * @param {String|Buffer} headers - Raw header block
 * @returns {Object} Map of lowercased header name to array of values
 */
function decodeHeaders(headers) {
    let parsed = libmime.decodeHeaders(capHeaderBlock(headers));

    for (let name of UNSAFE_KEYS) {
        // Probing first is not needed for correctness, deleting a missing key is a no-op, but it is
        // the cheaper no-op and almost every message takes this path
        if (Object.hasOwn(parsed, name)) {
            delete parsed[name];
        }
    }

    return parsed;
}

module.exports = { decodeHeaders, capHeaderBlock, MAX_HEADER_BLOCK_SIZE };
