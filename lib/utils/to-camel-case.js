'use strict';

// Lives here rather than in lib/tools.js so that pure modules can use it: tools.js opens Redis,
// which hangs a unit test that only wants to parse a message. tools.js re-exports it, so the
// existing `require('../tools')` consumers are unaffected.

/**
 * Converts a kebab-case header name into the camelCase key used in payloads,
 * eg. "final-recipient" into "finalRecipient"
 * @param {String} key Header name
 * @returns {String} camelCased key
 */
function toCamelCase(key) {
    return key.replace(/-(.)/g, (m, c) => c.toUpperCase());
}

module.exports = { toCamelCase };
