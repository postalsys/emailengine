'use strict';

// Helpers of the account pages and the hosted setup form in lib/ui-routes/account-routes.js, kept apart so they can be
// tested without registering the routes and so the route module stays inside its size budget.
// Everything here is pure except loadWebhookRouting(), which reads the settings and routes the
// account page's webhook card describes.

const settings = require('../settings');
const { webhooks: Webhooks } = require('../webhooks');
const { describeEffectiveRouting, isDeliverableRoute } = require('../webhook-routing');
const { formatGmailWatch } = require('../account/account-state');
const { closedAfterConnectMessage } = require('./route-helpers');

// The SASL mechanisms the account page links to a specification, by upper-cased name
const SMTP_AUTH_INFO = {
    LOGIN: { rfc: 'draft-murchison-sasl-login', url: 'https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login' },
    PLAIN: { rfc: 'RFC4616', url: 'https://www.rfc-editor.org/rfc/rfc4616.html' },
    XOAUTH2: { rfc: 'xoauth2-protocol', url: 'https://developers.google.com/gmail/imap/xoauth2-protocol#smtp_protocol_exchange' },
    OAUTHBEARER: { rfc: 'RFC7628', url: 'https://www.rfc-editor.org/rfc/rfc7628.html' }
};

/**
 * Moves the AUTH lines out of an SMTP server's EHLO extension list and describes the mechanisms
 * they name. The lines are read last to first, a repeated mechanism keeps its first place, and a
 * known one becomes `{ auth, rfc, url }` while an unknown one stays a plain name.
 *
 * @param {string[]} smtpServerEhlo - EHLO extension lines, modified in place
 * @returns {Array<string|Object>} the mechanisms
 */
function describeSmtpAuthMechanisms(smtpServerEhlo) {
    let smtpAuthMechanisms = [];
    for (let i = smtpServerEhlo.length - 1; i >= 0; i--) {
        let entry = smtpServerEhlo[i];
        if (/^auth\b/i.test(entry)) {
            let authEntries = entry.split(/\s+/).slice(1);
            if (authEntries.length) {
                smtpAuthMechanisms = smtpAuthMechanisms.concat(authEntries);
            }
            smtpServerEhlo.splice(i, 1);
        }
    }

    return Array.from(new Set(smtpAuthMechanisms)).map(entry => {
        let info = Object.hasOwn(SMTP_AUTH_INFO, entry.toUpperCase()) ? SMTP_AUTH_INFO[entry.toUpperCase()] : null;
        return info ? { auth: entry, rfc: info.rfc, url: info.url } : entry;
    });
}

/**
 * The Gmail watch card of the account page, or false when the account has no watch to report.
 *
 * State comes from the same derivation the API reports, so the page and the response cannot
 * disagree about whether push is working. The reason and the failed request stay here and out of
 * the API: both are text the provider wrote, and this page is behind an admin session. NB! a watch
 * that is still armed but whose last renewal failed now reads Failed rather than Active - it used
 * to show the expiry alone and hide the failure in a tooltip, which said nothing was wrong right
 * up to the day it lapsed
 *
 * @param {Object} accountData - the formatted account record
 * @returns {Object|false}
 */
function buildGmailWatchView(accountData) {
    let watchState = formatGmailWatch(accountData);
    let gmailWatch = watchState
        ? {
              lastCheckStr: watchState.lastCheck,
              expiresStr: watchState.expires || false,
              active: watchState.state === 'active',
              stateLabel: { active: 'Active', error: 'Failed', expired: 'Expired' }[watchState.state] || 'Unknown',
              // The reason and the failed request are read straight off the record here and
              // deliberately absent from the shared derivation: both carry text the
              // provider wrote, including the operator's own Pub/Sub topic path, and this
              // page is behind an admin session while the API field is not
              error: accountData.watchFailure ? accountData.watchFailure.err || 'Failed to set up Gmail pubsub watch' : false
          }
        : false;

    // Not "watchFailure truthy means gmailWatch is": the derivation reports nothing for an
    // account whose application has no Pub/Sub app, whatever record a previous one left
    if (gmailWatch && accountData.watchFailure && accountData.watchFailure.req) {
        gmailWatch.request = {
            url: accountData.watchFailure.req.url,
            status: accountData.watchFailure.req.status,
            contentType: accountData.watchFailure.req.contentType,
            response: accountData.watchFailure.req.response
        };
    }

    return gmailWatch;
}

/**
 * Top-of-page alert for the account's primary problem, so a broken account is impossible to
 * miss. Gated on the effective connection state (stateLabel.type) so a recovered account never
 * shows a stale error; a stalled sync is surfaced separately because the account can otherwise
 * be connected.
 *
 * @param {Object} accountData - the formatted account record
 * @param {string|null} disabledByAuthFailureAt - when the auth-failure safety net parked it
 * @returns {Object|null}
 */
function buildAccountAlert(accountData, disabledByAuthFailureAt) {
    if (disabledByAuthFailureAt) {
        // Ahead of the state alert: a parked account is not connecting at all, so why it
        // was switched off is the more actionable of the two.
        return {
            title: 'Syncing was switched off',
            message:
                'EmailEngine stopped connecting this account after repeated authentication failures. Re-authenticating it turns syncing back on; "Resume syncing" retries with the stored credentials.',
            timeLabel: 'Switched off',
            time: disabledByAuthFailureAt
        };
    }

    if (accountData.stateLabel && accountData.stateLabel.type === 'error') {
        return {
            title: accountData.stateLabel.name,
            message: accountData.stateLabel.error
        };
    }

    if (accountData.syncError) {
        return {
            title: 'Sync stalled',
            path: accountData.syncError.path,
            message: (accountData.syncError.error && (accountData.syncError.error.responseText || accountData.syncError.error.error)) || null
        };
    }

    return null;
}

/**
 * The webhook routing card of the account page: where this account's events go.
 *
 * @param {Object} accountData - the formatted account record
 * @returns {Promise<Object>} describeEffectiveRouting() output
 */
async function loadWebhookRouting(accountData) {
    const [webhookSettings, webhookRoutesList] = await Promise.all([
        settings.getMulti('webhooksEnabled', 'webhooks', 'webhookEvents', 'inboxNewOnly', 'webhooksCustomHeaders'),
        Webhooks.list(0, 1000)
    ]);

    // The listing carries route metadata only, but the worker's delivery gate also
    // requires a filter script, so the card needs the filter-presence markers for the
    // routes it is about to present as delivering
    const routeFilterInfo = await Webhooks.getFilterInfo(webhookRoutesList.webhooks.filter(isDeliverableRoute).map(route => route.id));

    return describeEffectiveRouting({
        webhooksEnabled: webhookSettings.webhooksEnabled,
        globalWebhooks: webhookSettings.webhooks,
        accountWebhooks: accountData.webhooks,
        webhookEvents: webhookSettings.webhookEvents,
        inboxNewOnly: webhookSettings.inboxNewOnly,
        globalCustomHeaders: webhookSettings.webhooksCustomHeaders,
        accountCustomHeaders: accountData.webhooksCustomHeaders,
        // Non-deliverable routes were not probed; their hasFilter stays undefined, which
        // describeEffectiveRouting() reads as "unknown" (and filters them out anyway)
        routes: webhookRoutesList.webhooks.map(route => Object.assign({}, route, { hasFilter: routeFilterInfo.get(route.id) }))
    });
}

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

module.exports = { translateConnectionErrors, describeSmtpAuthMechanisms, buildGmailWatchView, buildAccountAlert, loadWebhookRouting };
