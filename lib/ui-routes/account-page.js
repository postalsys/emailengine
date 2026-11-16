'use strict';

// Pure helpers of the account pages in lib/ui-routes/account-routes.js, kept apart so they can be
// tested without registering the routes and so the route module stays inside its size budget.

const { closedAfterConnectMessage } = require('./route-helpers');

// The messages the hosted form's connection check shows for an IMAP error code. Built per call
// with the request's translator, and every message is a literal gettext() call so string
// extraction finds it. The raw socket or ImapFlow error text is not something the person at the
// form can act on. Closed-after-connect keeps the TLS hint the account state badge shows for it,
// because a wrong port/TLS pairing is the usual cause.
const IMAP_ERROR_MESSAGES = gt => ({
    ENOTFOUND: gt.gettext('Server hostname was not found'),
    EAI_AGAIN: gt.gettext('Server hostname was not found'),
    AUTHENTICATIONFAILED: gt.gettext('Invalid username or password'),
    ETIMEDOUT: gt.gettext('Connection timed out'),
    ETIMEOUT: gt.gettext('Connection timed out'),
    GREETING_TIMEOUT: gt.gettext('Connection timed out'),
    ECONNREFUSED: gt.gettext('Could not connect to server'),
    ECONNRESET: gt.gettext('Could not connect to server'),
    EHOSTUNREACH: gt.gettext('Could not connect to server'),
    ENETUNREACH: gt.gettext('Could not connect to server'),
    ClosedAfterConnectTLS: closedAfterConnectMessage('ClosedAfterConnectTLS', gt),
    ClosedAfterConnectText: closedAfterConnectMessage('ClosedAfterConnectText', gt),
    EPROTO: gt.gettext('TLS protocol error'),
    ERR_TLS_CERT_ALTNAME_INVALID: gt.gettext('TLS protocol error'),
    ERR_SSL_WRONG_VERSION_NUMBER: gt.gettext('TLS protocol error'),
    CERT_HAS_EXPIRED: gt.gettext('TLS protocol error'),
    DEPTH_ZERO_SELF_SIGNED_CERT: gt.gettext('TLS protocol error'),
    SELF_SIGNED_CERT_IN_CHAIN: gt.gettext('TLS protocol error'),
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: gt.gettext('TLS protocol error')
});

// The same for the nodemailer error codes of the SMTP check
const SMTP_ERROR_MESSAGES = gt => ({
    EDNS: gt.gettext('Server hostname was not found'),
    EAUTH: gt.gettext('Invalid username or password'),
    ENOAUTH: gt.gettext('Authentication credentials were not provided'),
    EOAUTH2: gt.gettext('OAuth2 authentication failed'),
    ETLS: gt.gettext('TLS protocol error'),
    ETIMEDOUT: gt.gettext('Connection timed out'),
    ECONNECTION: gt.gettext('Could not connect to server'),
    EPROTOCOL: gt.gettext('Unexpected server response')
});

// Replaces `result.error` with the message for `result.code`. An unlisted code keeps its text
// unless `fallback` says the text describes a TLS failure.
function translateCheckError(result, messages, fallback, gt) {
    if (Object.hasOwn(messages, result.code)) {
        result.error = messages[result.code];
    } else if (fallback(result)) {
        result.error = gt.gettext('TLS protocol error');
    }
}

// An unlisted IMAP code still reads as TLS when the text comes from OpenSSL, in any case
const imapTlsFallback = result => /openssl|ssl routines/i.test(result.error);

// Only an SMTP socket error is checked for OpenSSL text, and case-sensitively
const smtpTlsFallback = result => result.code === 'ESOCKET' && /openssl/.test(result.error);

/**
 * Translates the error codes of a connection check (verifyAccountInfo) into messages the person
 * at the hosted form can act on. Modifies the result in place; a side is only translated when it
 * carries both an error and a code.
 *
 * @param {Object} verifyResult - `{ imap, smtp }` as verifyAccountInfo returns it, or a falsy value
 * @param {Object} gt - the request's translator
 */
function translateConnectionErrors(verifyResult, gt) {
    if (!verifyResult) {
        return;
    }

    if (verifyResult.imap && verifyResult.imap.error && verifyResult.imap.code) {
        translateCheckError(verifyResult.imap, IMAP_ERROR_MESSAGES(gt), imapTlsFallback, gt);
    }

    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
        translateCheckError(verifyResult.smtp, SMTP_ERROR_MESSAGES(gt), smtpTlsFallback, gt);
    }
}

module.exports = { translateConnectionErrors };
