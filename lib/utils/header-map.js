'use strict';

// Lives here rather than in lib/tools.js so that pure modules and tests can use it: tools.js
// opens Redis, which drags a connection into anything that only wants to collect header values.

/**
 * Appends one value to a header map keyed by lowercased header name.
 *
 * Header names come from the remote server, so any sender can pick one that names an
 * Object.prototype member. On a plain object `headers['__proto__']` reads back the prototype
 * instead of an array, and assigning to it hands the value to the prototype setter rather than
 * storing a key - so a bare `!headers[key]` probe pushes onto something that is not an array and
 * throws. Lowercasing leaves exactly two such names, "__proto__" and "constructor", and both are
 * dropped rather than collected: storing them would need an own "__proto__" key, which msgpack
 * refuses to decode (test/msgpack-compat-test.js) and which hands webhook consumers a prototype
 * pollution gadget of their own.
 *
 * Only the accumulate-by-assignment shape is guarded here. A header block parsed by libmime
 * arrives with these names already set as own properties, which this cannot detect, so
 * lib/utils/decode-headers.js drops them after the fact for the IMAP and bounce paths.
 *
 * The array is read before the `in` probe on purpose. `in` walks the prototype chain and has no
 * fast path for the freshly lowercased (non-internalized) key, which made it roughly twice the
 * cost of the whole loop; reading first keeps `in` on the miss path only.
 *
 * @param {Object} headers - Map of lowercased header name to array of values
 * @param {String} key - Lowercased header name
 * @param {String} value - Value to append
 * @returns {Boolean} True when the value was stored, false when the name was skipped
 */
function pushHeaderValue(headers, key, value) {
    let values = headers[key];

    if (Array.isArray(values)) {
        values.push(value);
        return true;
    }

    // Not an array: either the name is unused, or it resolves to a prototype member
    if (key in headers) {
        return false;
    }

    headers[key] = [value];
    return true;
}

// Headers the notification path needs for its own processing, whatever the notifyHeaders
// setting asks for: auto-reply detection, threading, the multipart/report check behind bounce
// and complaint detection, and the address fields as a fallback for an ENVELOPE that carries no
// usable address (Lark Mail omits them, and any server can mis-parse a malformed header into a
// display name with no address). They travel with the one header section the path already
// requests and are narrowed back out before the message is published
const NOTIFICATION_HEADERS = [
    'x-autoreply',
    'x-autorespond',
    'auto-submitted',
    'precedence',
    'in-reply-to',
    'references',
    'content-type',
    'from',
    'to',
    'cc',
    'bcc'
];

/**
 * Builds the header field list for a notification fetch: what the operator asked for, what the
 * path needs for itself, and whatever else the caller has a use for this time (the AI summary's
 * headers while summaries are on)
 *
 * @param {String[]|Boolean} configuredHeaders - Headers the notifyHeaders setting asks for
 * @param {String[]} [extraHeaders] - Headers the caller wants fetched as well
 * @returns {String[]} Header names to request from the server
 */
function notificationHeaderFields(configuredHeaders, extraHeaders) {
    const fetchHeaders = new Set(Array.isArray(configuredHeaders) ? configuredHeaders : []);

    for (const key of NOTIFICATION_HEADERS.concat(extraHeaders || [])) {
        fetchHeaders.add(key);
    }

    return Array.from(fetchHeaders);
}

/**
 * Narrows a message's fetched headers to what the caller asked for, once every internal use of
 * the extra ones is over. A list keeps those names, false drops the block, and anything else
 * (every header was asked for) leaves it alone
 *
 * @param {Object} message - Message whose headers were fetched with notificationHeaderFields()
 * @param {String[]|Boolean|undefined} requestedHeaders - What the caller asked for
 */
function narrowHeaders(message, requestedHeaders) {
    if (Array.isArray(requestedHeaders)) {
        const narrowed = {};
        for (const key of Object.keys(message.headers || {})) {
            if (requestedHeaders.includes(key)) {
                narrowed[key] = message.headers[key];
            }
        }
        message.headers = narrowed;
    } else if (requestedHeaders === false) {
        delete message.headers;
    }
}

module.exports = { pushHeaderValue, notificationHeaderFields, narrowHeaders, NOTIFICATION_HEADERS };
