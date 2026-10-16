'use strict';

// Whether a cleartext SMTP connection must upgrade with STARTTLS.
//
// Nodemailer's default is opportunistic: with `secure: false` it upgrades when the server
// advertises STARTTLS and otherwise carries on in cleartext, AUTH included, which is what an
// attacker on the path who strips the advertisement gets. Every SMTP transport EmailEngine builds
// (an account's own server, a gateway, the verification probe) therefore asks for `requireTLS`
// unless the stored configuration says `requireTLS: false`, the opt-out for a relay on a trusted
// network that has no TLS at all. A connection that is `secure: true` from the start needs no
// upgrade and is left alone. lib/create-imap-client.js applies the same rule to IMAP.

/**
 * Settles `requireTLS` on an SMTP transport configuration, in place.
 *
 * @param {Object} smtpSettings - Nodemailer transport options, carrying EmailEngine's `requireTLS`
 * @returns {Object} the same object
 */
function applyRequireTls(smtpSettings) {
    if (!smtpSettings || typeof smtpSettings !== 'object') {
        return smtpSettings;
    }

    if (smtpSettings.secure) {
        delete smtpSettings.requireTLS;
        return smtpSettings;
    }

    smtpSettings.requireTLS = smtpSettings.requireTLS !== false;
    return smtpSettings;
}

module.exports = { applyRequireTls };
