'use strict';

// Bulk actions on the admin accounts list. The page runs them itself, one account per request and a
// few requests at a time (static/js/accounts-bulk.js), so every request is short, progress is real,
// and an operator can stop half way. This route does one action on one account and says how it
// went: done, skipped (the action does not apply to that account, with the reason), missing, or
// failed.
//
// "Pause" is the operator's switch that stops syncing, `imap.disabled` - the same flag the account
// form's "Disable IMAP" checkbox sets, and the one the Gmail API and Graph clients check too. An
// IMAP account keeps sending while paused. "Resume" lifts either kind of disable: the operator's,
// and a park by the auth-failure safety net, through the same path as "Resume syncing".

const Joi = require('joi');

const { redis } = require('../db');
const getSecret = require('../get-secret');
const { Account, authFailureDisabledAt, isImapDisabled } = require('../account');
const { accountIdSchema } = require('../schemas');
const { isClientError } = require('./route-helpers');

const BULK_ACTIONS = ['reconnect', 'pause', 'resume', 'delete'];

// Why a revocation that was asked for did not happen, as the outcome list says it
const REVOCATION_NOTES = {
    NoToken: 'no stored token to revoke',
    AppNotFound: 'its OAuth2 app no longer exists',
    ServiceAccount: 'service accounts hold no grant to revoke',
    Unsupported: 'the provider offers no revocation',
    AppError: 'the OAuth2 app could not be loaded',
    RequestFailed: 'the provider did not answer'
};

/**
 * Whether an action applies to an account, decided from the stored account alone.
 *
 * @param {String} action - One of BULK_ACTIONS
 * @param {Object} accountData - The unserialized account
 * @returns {String|null} Why the action is skipped, null when it applies
 */
function bulkSkipReason(action, accountData) {
    if (action === 'delete') {
        return null;
    }

    // Nothing to sync: an SMTP-only account. A paused account still has its `imap` object.
    if (!accountData.imap && !accountData.oauth2) {
        return 'Sends only, nothing to sync';
    }

    const paused = isImapDisabled(accountData);
    switch (action) {
        case 'reconnect':
            return paused ? 'Syncing is paused' : null;
        case 'pause':
            return paused ? 'Already paused' : null;
        case 'resume':
            return paused ? null : 'Not paused';
    }
    return null;
}

/**
 * The note for a delete that was asked to revoke the grant and did not, or null.
 *
 * @param {Object} [revocation] - The `revocation` Account#delete() reports
 * @returns {String|null}
 */
function revocationNote(revocation) {
    if (!revocation || revocation.revoked || revocation.reason === 'NotOAuth2') {
        return null;
    }
    return `Deleted, but access was not revoked: ${REVOCATION_NOTES[revocation.reason] || revocation.reason || 'the provider did not confirm'}`;
}

async function runBulkAction(accountObject, action, accountData, opts) {
    switch (action) {
        case 'reconnect':
            // Declines for an account the safety net switched off, like the single button
            return (await accountObject.requestReconnect({ reconnect: true })) ? { result: 'done' } : { result: 'skipped', reason: 'Syncing is paused' };

        case 'pause':
            await accountObject.update({ account: accountObject.account, imap: { disabled: true, partial: true } });
            return { result: 'done' };

        case 'resume':
            if (authFailureDisabledAt(accountData)) {
                await accountObject.resumeAfterAuthFailure();
            } else {
                await accountObject.update({ account: accountObject.account, imap: { disabled: false, partial: true } });
            }
            return { result: 'done' };

        case 'delete': {
            // `revocation` is only reported when revoke was asked for
            const { deleted, revocation } = await accountObject.delete({ revoke: opts.revoke });
            if (!deleted) {
                return { result: 'missing' };
            }
            const note = revocationNote(revocation);
            return note ? { result: 'done', note } : { result: 'done' };
        }
    }
}

function registerPostAccountsBulk(server, args) {
    const { call } = args;

    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/bulk',
        async handler(request) {
            const { account } = request.params;
            const { action, revoke } = request.payload;

            try {
                const accountObject = new Account({ redis, account, call, secret: await getSecret() });
                const accountData = await accountObject.loadAccountData(account, false);

                const reason = bulkSkipReason(action, accountData);
                if (reason) {
                    return { result: 'skipped', reason };
                }

                const outcome = await runBulkAction(accountObject, action, accountData, { revoke });
                request.logger.info({
                    msg: 'Bulk account action',
                    action,
                    account,
                    revoke: action === 'delete' ? !!revoke : undefined,
                    outcome: outcome.result,
                    remoteAddress: request.app.ip
                });
                return outcome;
            } catch (err) {
                if (isClientError(err) && err.output.statusCode === 404) {
                    return { result: 'missing' };
                }
                request.logger.error({ msg: 'Bulk account action failed', action, account, err, remoteAddress: request.app.ip });
                return { result: 'failed', error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    return h.response({ result: 'failed', error: err.message }).code(400).takeover();
                },

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    action: Joi.string()
                        .valid(...BULK_ACTIONS)
                        .required(),
                    revoke: Joi.boolean().default(false)
                })
            }
        }
    });
}

module.exports = { registerPostAccountsBulk, bulkSkipReason, revocationNote };
