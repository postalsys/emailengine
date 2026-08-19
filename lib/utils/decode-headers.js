'use strict';

const libmime = require('libmime');
const { UNSAFE_KEYS } = require('./unsafe-key');

/**
 * Parses a header block into a map of lowercased header name to array of values.
 *
 * Wraps libmime.decodeHeaders() to drop names that collide with Object.prototype. Header names
 * come from the message, so any sender can use one, and libmime returns them as real own
 * properties. Neither names a real header, so there is nothing to preserve by keeping them:
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
    let parsed = libmime.decodeHeaders(headers);

    for (let name of UNSAFE_KEYS) {
        // Probing first is not needed for correctness, deleting a missing key is a no-op, but it is
        // the cheaper no-op and almost every message takes this path
        if (Object.hasOwn(parsed, name)) {
            delete parsed[name];
        }
    }

    return parsed;
}

module.exports = { decodeHeaders };
