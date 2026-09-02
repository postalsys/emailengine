'use strict';

const crypto = require('crypto');

// Expose to the world
module.exports = getTLSOptions;

// No built-in key or certificate. Upstream ships a self-signed localhost pair here as the
// fallback for a server configured with TLS but no certificate, and that private key is the
// same in every copy of the library, so a listener secured by it is readable by anyone with the
// source. EmailEngine's IMAP proxy refuses to start with TLS and no certificate instead
// (assertTlsCredentials in lib/tools.js), and the STARTTLS upgrade is disabled in proxy mode.
const tlsDefaults = {
    honorCipherOrder: true,
    requestOCSP: false,
    sessionIdContext: crypto.createHash('sha256').update(process.argv.join(' ')).digest('hex').slice(0, 32),
    minVersion: 'TLSv1'
};

/**
 * Mixes existing values with the default ones.
 *
 * @param {Object} [opts] TLS options
 * @returns {Object} Object with mixed TLS values
 */
function getTLSOptions(opts) {
    return Object.assign({}, tlsDefaults, opts || {});
}
