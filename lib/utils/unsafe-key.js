'use strict';

// Lives here rather than in lib/tools.js so that pure modules and tests can use it: tools.js opens
// Redis, which drags a connection into anything that only wants to parse a message.

// Names that resolve to an Object.prototype member. Header names come from the message, so any
// sender can pick one, and the maps built from them are plain objects:
//
// - assigning "__proto__" hands the value to the prototype setter and swaps the map's prototype
//   instead of storing a key, and defining it as an own property instead leaves a key
//   lib/msgpack.js refuses to decode - so a map carrying one encodes into webhook logs and message
//   payloads that can never be read back
// - "constructor" is inert on its own, but lib/utils/header-map.js cannot represent it, so keeping
//   it would describe the same message differently depending on the transport that fetched it
//
// The names a message supplies arrive lowercased, which leaves exactly these two. Kept as an
// explicit list rather than an `in {}` probe so that what gets dropped is readable at a glance, and
// so that names like "toString" - which cannot collide with a lowercased key, and which no real
// header or subtype uses either - are not dropped as a side effect.
const UNSAFE_KEYS = ['__proto__', 'constructor'];

/**
 * Tells whether a key is one a plain-object map built from a message must not carry - header names,
 * but also anything else the message names, such as the MIME subtype lib/email-client/imap/mailbox.js
 * groups text parts by.
 *
 * Applied at the parse boundary (lib/utils/decode-headers.js), and again after any transform that
 * rebuilds a key from a name. A transform can manufacture one of these out of an input the parse
 * boundary had no reason to drop: toCamelCase() turns "_-_proto__" into "__proto__", so a guard
 * that only ran before it never saw the name it exists to catch.
 *
 * @param {String} key - Key to test
 * @returns {Boolean} True when the key must be dropped
 */
function isUnsafeKey(key) {
    return UNSAFE_KEYS.includes(key);
}

/**
 * The stricter test for a key REBUILT from a name by a case-changing transform. After
 * toCamelCase() a key is no longer lowercase-only: "to-string" camelCases into "toString" and
 * "has-own-property" into "hasOwnProperty", so the transform can manufacture any Object.prototype
 * member name out of an input the parse boundary had no reason to drop. Assigning one creates an
 * own property that shadows the method on the published object, and the first consumer that
 * string-coerces the report - or calls hasOwnProperty() on it - throws.
 *
 * Probed with `in` against Object.prototype itself (whose own chain ends at null, so this reads
 * exactly its member set, __proto__ and constructor included) rather than extending the list
 * above: the set tracks the runtime, and the parse-boundary check deliberately stays narrower -
 * see the note on UNSAFE_KEYS about not dropping names a lowercased key cannot collide with.
 *
 * @param {String} key - Key to test, after the transform that rebuilt it
 * @returns {Boolean} True when the key must be dropped
 */
function isUnsafeTransformedKey(key) {
    return key in Object.prototype;
}

module.exports = { UNSAFE_KEYS, isUnsafeKey, isUnsafeTransformedKey };
