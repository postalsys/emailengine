'use strict';

// The account update the admin account edit form (POST /admin/accounts/{account}/edit in
// account-routes.js) asks for, built from the validated payload and the stored account. Pure, so
// test/account-edit-form-test.js covers it without a route.
//
// The rule that runs through all of it: an untouched form save must not add or change keys,
// because any imap diff forces a reconnect. So a value is written only when the effective state
// changes, and a field the form did not show is not written at all.
//
// The stored connection objects are copied before anything is applied to them: the update is
// built on the copy, so the loaded account is left as it was.

const { SPECIAL_USE_PATH_FIELDS } = require('./special-use-paths');
const { applyImapMaxIdleTimeForm } = require('./imap-idle-field');
const { applySecurityForm } = require('./connection-security-form');
const { parseCustomHeaders } = require('./form-lists');

// A copy of a stored connection object deep enough for the form to apply its changes to: the
// only nested objects it writes into are `auth` and `tls`
function copyConnection(stored) {
    if (!stored) {
        return stored;
    }
    let copy = Object.assign({}, stored);
    for (let key of ['auth', 'tls']) {
        if (copy[key] && typeof copy[key] === 'object') {
            copy[key] = Object.assign({}, copy[key]);
        }
    }
    return copy;
}

/**
 * The account-level fields of the update.
 *
 * @param {String} account - account ID
 * @param {Object} payload - the validated form payload
 * @returns {Object} the update, without the connection sections
 */
function buildBaseUpdates(account, payload) {
    let updates = {
        account,
        name: payload.name || '',
        email: payload.email,
        // Empty clears the pin (Account.update hdel's it), which is the only way an operator
        // can unblock a legitimate mailbox migration on a pinned account.
        expectedEmail: payload.expectedEmail || null,
        proxy: payload.proxy,
        smtpEhloName: payload.smtpEhloName,
        webhooks: payload.webhooks
    };

    // Absent only from a request that did not render the field, keep the stored headers then
    if (typeof payload.customHeaders === 'string') {
        updates.webhooksCustomHeaders = parseCustomHeaders(payload.customHeaders);
    }

    return updates;
}

/**
 * The `imap` object of the update, for a payload whose IMAP section was submitted.
 *
 * @param {Object} payload - the validated form payload
 * @param {Object} [storedImap] - the stored `imap` object
 * @returns {Object} the stored object with the submitted changes applied
 */
function buildImapUpdates(payload, storedImap) {
    let imap = copyConnection(storedImap);
    let imapTls = (imap && imap.tls) || {};

    let updateKeys = {};

    for (let key of ['host', 'port', 'disabled']) {
        if (`imap_${key}` in payload) {
            updateKeys[key] = payload[`imap_${key}`];
        }
    }

    // The special-use folder overrides. An empty input means "no override" and has to
    // be written as null to unset one, while a field the form never showed must not be
    // written at all: these inputs live inside the IMAP section, which is hidden for an
    // account whose IMAP the operator switched off. The schema therefore allows the
    // empty string instead of defaulting to null - a default is inserted by joi for
    // every key the browser did not send, which made the presence check below always
    // true, so an unrelated save (a rename, a new webhook URL) wiped every override set
    // over PUT /v1/account/{account}. Same presence test imap_auth_user relies on.
    for (const field of SPECIAL_USE_PATH_FIELDS) {
        const payloadKey = `imap_${field.key}`;
        if (!(payloadKey in payload)) {
            continue;
        }
        const value = payload[payloadKey] || null;
        // Written only when the effective value changes, like the TLS flags below: an
        // untouched save must not add keys, because any imap diff forces a reconnect
        if (value !== ((imap && imap[field.key]) || null)) {
            updateKeys[field.key] = value;
        }
    }

    applyImapMaxIdleTimeForm(payload, imap, updateKeys);
    if ('imap_auth_user' in payload) {
        let imapAuth = Object.assign((imap && imap.auth) || {}, { user: payload.imap_auth_user });
        if (payload.imap_auth_pass) {
            imapAuth.pass = payload.imap_auth_pass;
        }
        updateKeys.auth = imapAuth;
        updateKeys.secure = payload.imap_secure;
        // The connection settings section is hidden for OAuth2 and disabled
        // accounts, so like `secure` these only apply when it was submitted.
        // Written only when the effective state changes - an untouched form
        // save must not add new keys, as any imap diff forces a reconnect
        applySecurityForm(payload, 'imap', imap, updateKeys, imapTls);
        if (payload.imap_disableIMAP4rev2 !== !!(imap && imap.disableIMAP4rev2)) {
            updateKeys.disableIMAP4rev2 = payload.imap_disableIMAP4rev2;
        }
    }

    // skipped while empty and absent from the stored account for the same
    // reason as above - a no-op save must not introduce a tls:{} key
    if (Object.keys(imapTls).length) {
        updateKeys.tls = imapTls;
    }

    let updated = Object.assign(imap || {}, updateKeys);

    if (payload.imap_resyncDelay) {
        updated.resyncDelay = payload.imap_resyncDelay;
    }

    return updated;
}

/**
 * The `smtp` object of the update, for a payload whose SMTP section was submitted.
 *
 * @param {Object} payload - the validated form payload
 * @param {Object} [storedSmtp] - the stored `smtp` object
 * @returns {Object} the stored object with the submitted changes applied
 */
function buildSmtpUpdates(payload, storedSmtp) {
    let smtp = copyConnection(storedSmtp);
    let smtpAuth = Object.assign((smtp && smtp.auth) || {}, { user: payload.smtp_auth_user });
    let smtpTls = (smtp && smtp.tls) || {};

    if (payload.smtp_auth_pass) {
        smtpAuth.pass = payload.smtp_auth_pass;
    }

    let updated = Object.assign(smtp || {}, {
        host: payload.smtp_host,
        port: payload.smtp_port,
        secure: payload.smtp_secure,
        auth: smtpAuth
    });

    // written only when the effective state changes, and the tls object is
    // skipped while empty - same as the IMAP flags, a no-op save must not
    // modify the stored account. When an SMTP object is stored, `updated` IS `smtp` (Object.assign
    // wrote into the copy), so the comparison already sees the submitted host, port and auth; the
    // security fields it reads are not among them. Without one, the comparison sees undefined.
    applySecurityForm(payload, 'smtp', smtp, updated, smtpTls);

    if (Object.keys(smtpTls).length) {
        updated.tls = smtpTls;
    }

    return updated;
}

/**
 * The whole update the form asks for.
 *
 * @param {String} account - account ID
 * @param {Object} payload - the validated form payload
 * @param {Object} oldData - the stored account
 * @returns {Object} the update for Account.update()
 */
function buildAccountEditUpdates(account, payload, oldData) {
    let updates = buildBaseUpdates(account, payload);

    if (payload.imap) {
        updates.imap = buildImapUpdates(payload, oldData.imap);
    }

    if (payload.smtp) {
        updates.smtp = buildSmtpUpdates(payload, oldData.smtp);
    }

    return updates;
}

module.exports = { buildAccountEditUpdates, buildBaseUpdates, buildImapUpdates, buildSmtpUpdates };
