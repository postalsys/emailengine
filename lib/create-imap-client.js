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
//
// maxLineLength, maxLiteralSize, maxResponseSize: what one server response may make the worker
// buffer. ImapFlow's defaults (1 GB, 1 GB, 2 GB) assume one trusted server; a worker here serves
// many accounts, so a hostile or broken server answering one of them must not exhaust the memory
// of all of them. The values are in lib/consts.js with the reasoning.
//
// doSTARTTLS: a cleartext connection (`secure: false`) upgrades with STARTTLS and must succeed at
// it. Left unset, ImapFlow upgrades only when the server advertises STARTTLS and otherwise logs a
// warning and continues in cleartext, LOGIN included, which is what an on-path attacker who strips
// the capability gets. The account-level `requireTLS: false` is the opt-out for a server on a
// trusted network that has no TLS at all, and it leaves doSTARTTLS unset rather than false: the
// connection still upgrades when the server offers STARTTLS, the same as an SMTP transport with
// requireTLS off (lib/utils/require-tls.js). `requireTLS` is EmailEngine's field, not ImapFlow's,
// so it is consumed here. A connection that is `secure: true` from the start is not affected.

const { ImapFlow } = require('imapflow');
const { IMAP_MAX_LINE_LENGTH, IMAP_MAX_LITERAL_SIZE, IMAP_MAX_RESPONSE_SIZE } = require('./consts');

/**
 * Turns EmailEngine's connection configuration into ImapFlow options.
 *
 * @param {Object} config - Connection options, applied over the defaults
 * @returns {Object} the options ImapFlow is constructed with
 */
function imapClientOptions(config) {
    let { requireTLS, ...options } = config || {};

    options = {
        idHashAlgorithm: 'sha256',
        maxLineLength: IMAP_MAX_LINE_LENGTH,
        maxLiteralSize: IMAP_MAX_LITERAL_SIZE,
        maxResponseSize: IMAP_MAX_RESPONSE_SIZE,
        ...options
    };

    if (!options.secure && options.doSTARTTLS === undefined && requireTLS !== false) {
        options.doSTARTTLS = true;
    }

    return options;
}

/**
 * @param {Object} config - Connection options, applied over the defaults
 * @returns {ImapFlow}
 */
function createImapClient(config) {
    return new ImapFlow(imapClientOptions(config));
}

module.exports = { createImapClient, imapClientOptions };
