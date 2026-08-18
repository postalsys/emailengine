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

module.exports = { pushHeaderValue };
