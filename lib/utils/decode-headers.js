'use strict';

const libmime = require('libmime');

/**
 * Parses a header block into a map of lowercased header name to array of values.
 *
 * Wraps libmime.decodeHeaders() to drop a "__proto__" field name. Header names come from the
 * message, so any sender can use one, and libmime returns it as a real own property rather than
 * letting it reach the prototype setter. That own key is the one thing lib/msgpack.js refuses to
 * decode, so a map carrying it encodes into webhook logs and message payloads that can never be
 * read back, and it hands anything that later copies the map with `obj[key] =` or Object.assign a
 * prototype swap. It names no real header, so there is nothing to preserve by keeping it.
 *
 * Dropping it here rather than at each publisher keeps every consumer of a parsed header block on
 * the same contract - lib/email-client/imap/mailbox.js and lib/bounce-detect.js both return these
 * maps to callers verbatim.
 *
 * @param {String|Buffer} headers - Raw header block
 * @returns {Object} Map of lowercased header name to array of values
 */
function decodeHeaders(headers) {
    let parsed = libmime.decodeHeaders(headers);

    if (Object.hasOwn(parsed, '__proto__')) {
        delete parsed['__proto__'];
    }

    return parsed;
}

module.exports = { decodeHeaders };
