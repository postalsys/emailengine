'use strict';

// Every ImapFlow client EmailEngine creates is created here, whatever the connection is for (an
// account's primary and command connections, a subconnection, the verification probes, the IMAP
// proxy's upstream), so an option every connection needs is set once. test/fips-guardrail-test.js
// refuses a `new ImapFlow(` anywhere else.
//
// idHashAlgorithm: ImapFlow derives a fallback message id from path:uidValidity:uid when the server
// provides no email id, with MD5 unless told otherwise, and an OpenSSL FIPS provider has no MD5, so
// every FETCH would fail on such a host. EmailEngine never reads that id (new messages are
// deduplicated on emailId or Message-ID, and the value only appears in a log line), so the
// algorithm is free to differ from ImapFlow's default on every installation.

const { ImapFlow } = require('imapflow');

/**
 * @param {Object} config - Connection options, applied over the defaults
 * @returns {ImapFlow}
 */
function createImapClient(config) {
    return new ImapFlow({ idHashAlgorithm: 'sha256', ...config });
}

module.exports = { createImapClient };
