'use strict';

// Every message EmailEngine parses with mailparser is parsed here, so an option every parse needs
// is set once. test/fips-guardrail-test.js refuses a simpleParser() call anywhere else.
//
// checksumAlgo: mailparser hashes every attachment, with MD5 unless told otherwise, and an OpenSSL
// FIPS provider refuses MD5. Nothing in EmailEngine reads the checksum, so the algorithm only has
// to exist on every host.

const { simpleParser } = require('mailparser');

/**
 * @param {Buffer|String|Stream} input - The message source
 * @param {Object} [options] - mailparser options, applied over the defaults
 * @returns {Promise<Object>} The parsed message
 */
function parseMessage(input, options) {
    return simpleParser(input, { checksumAlgo: 'sha256', ...options });
}

module.exports = { parseMessage };
