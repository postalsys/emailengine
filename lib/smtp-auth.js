'use strict';

// SMTP submission-server authentication handler. Extracted from workers/smtp.js
// so the auth logic can be unit tested without booting the worker thread (which
// connects to a parentPort and starts listening at require time).

const logger = require('./logger');
const settings = require('./settings');
const { redis } = require('./db');
const { Account } = require('./account');
const getSecret = require('./get-secret');
const { validateAuthToken, withAuthFailureBudget, REASON_MESSAGES } = require('./auth-token');
const { constantTimeEqual } = require('./tools');

/**
 * Builds the SMTP server onAuth handler.
 *
 * @param {Object} deps
 * @param {WeakMap} deps.accountCache - session -> Account cache shared with the worker
 * @param {Function} deps.call - RPC function passed to the Account instance
 * @returns {Function} async onAuth(auth, session)
 */
function createSmtpAuthHandler({ accountCache, call }) {
    // The credential check proper. Everything it throws is a refusal the client caused, which
    // is what the failure budget in onAuth() counts.
    async function authenticate(auth, session) {
        let account = auth.username;

        let smtpPassword = await settings.get('smtpServerPassword');
        if (!smtpPassword || !constantTimeEqual(auth.password, smtpPassword)) {
            // fall back to API token authentication
            let result = await validateAuthToken({
                password: auth.password,
                account: auth.username,
                requiredScope: 'smtp',
                remoteAddress: session.remoteAddress
            });

            if (!result.authenticated) {
                throw new Error(REASON_MESSAGES[result.reason] || 'Failed to authenticate user');
            }
        }

        let accountObject = new Account({ account, redis, call, secret: await getSecret() });
        let accountData;
        try {
            accountData = await accountObject.loadAccountData();
        } catch (err) {
            let respErr = new Error('Failed to authenticate user');

            if (!err.output || err.output.statusCode !== 404) {
                // only log non-obvious errors
                logger.error({ msg: 'Failed to load account data', account: auth.username, err });
                respErr.statusCode = 454;
            }

            throw respErr;
        }

        if (!accountData) {
            throw new Error('Failed to authenticate user');
        }

        accountCache.set(session, accountObject);
        return { user: accountData.account };
    }

    return async function onAuth(auth, session) {
        if (!session.eeAuthEnabled) {
            throw new Error('Authentication not enabled');
        }

        return await withAuthFailureBudget(
            { remoteAddress: session.remoteAddress, account: auth.username },
            () => authenticate(auth, session),
            () => {
                let err = new Error(REASON_MESSAGES.limited);
                // A temporary failure, so the client retries later instead of concluding that its
                // credentials are wrong
                err.responseCode = 454;
                return err;
            }
        );
    };
}

/**
 * Builds the resolver that finds the Account a submitted message is sent through.
 *
 * Lives beside the auth handler for the same reason it does: the worker can not be required
 * from a test, and this is the other half of the decision of who may submit through which
 * account. An authenticated session submits through the account it logged in as; a session
 * opened while authentication was off names the account with the X-EE-Account header.
 *
 * @param {Object} deps
 * @param {WeakMap} deps.accountCache - session -> Account cache shared with the auth handler
 * @param {Function} deps.call - RPC function passed to the Account instance
 * @returns {Function} async resolveAccount(session, messageMeta) -> Account
 */
function createSmtpAccountResolver({ accountCache, call }) {
    return async function resolveAccount(session, messageMeta) {
        let accountObject;

        if (!session.eeAuthEnabled) {
            // The session decided at connect time that no authentication was required. A client
            // can hold a connection open for as long as it likes, so if the operator has switched
            // authentication on since, the stale decision must not keep admitting submissions.
            if (await settings.get('smtpServerAuthEnabled')) {
                let err = new Error('Authentication required');
                err.responseCode = 530;
                throw err;
            }
        }

        if (!session.eeAuthEnabled && messageMeta.requestedAccount) {
            // Only a loaded account counts as resolved. Keeping the instance after a failed load
            // let an unknown header value through here, to fail later inside the queueing with
            // an error that never named the reason
            let requested = new Account({ account: messageMeta.requestedAccount, redis, call, secret: await getSecret() });
            try {
                // throws if unknown user
                if (await requested.loadAccountData()) {
                    accountObject = requested;
                    accountCache.set(session, accountObject);
                    logger.debug({ msg: 'Resolved requested account', account: messageMeta.requestedAccount });
                }
            } catch (err) {
                logger.warn({ msg: 'Failed to resolve requested account', account: messageMeta.requestedAccount, err });
            }
        } else {
            accountObject = accountCache.get(session);
        }

        if (!session.eeAuthEnabled && !messageMeta.requestedAccount && !accountObject) {
            let err = new Error('Sender account ID not provided, can not send mail');
            err.responseCode = 451;
            throw err;
        }

        if (!accountObject) {
            let err = new Error('Failed to load account');
            err.responseCode = 451;
            throw err;
        }

        return accountObject;
    };
}

module.exports = { createSmtpAuthHandler, createSmtpAccountResolver };
