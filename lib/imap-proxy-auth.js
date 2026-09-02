'use strict';

// IMAP proxy authentication. Extracted from lib/imapproxy/imap-server.js so the
// auth decision can be unit tested without booting the proxy worker (which uses
// a parentPort at require time). Only the authentication portion is extracted;
// the backend IMAP connection config is still built by the server.

const logger = require('./logger');
const settings = require('./settings');
const { redis } = require('./db');
const { Account } = require('./account');
const getSecret = require('./get-secret');
const { isApiBasedApp } = require('./oauth2-apps');
const { validateAuthToken, withAuthFailureBudget, REASON_MESSAGES } = require('./auth-token');
const { constantTimeEqual } = require('./tools');

/**
 * Tags an error as an IMAP authentication rejection for the proxy client. Shared with the
 * server, which raises the same rejection for a credential it could not load.
 *
 * @param {Error} err - Error to tag
 * @returns {Error} the same error
 */
function failImapAuth(err) {
    err.authenticationFailed = true;
    err.serverResponseCode = 'AUTHENTICATIONFAILED';
    err.responseStatus = 'NO';
    return err;
}

const authenticationFailedError = message => failImapAuth(new Error(message));

/**
 * Builds the IMAP proxy authentication handler.
 *
 * @param {Object} deps
 * @param {Function} deps.call - RPC function passed to the Account instance
 * @returns {Function} async authenticate(auth, session) -> { accountObject, accountData }
 */
function createImapProxyAuthHandler({ call }) {
    // The credential check proper. Everything it throws is a refusal the client caused, which
    // is what the failure budget in authenticate() counts.
    async function verifyCredentials(auth, session) {
        let account = auth.username;

        let imapPassword = await settings.get('imapProxyServerPassword');
        if (!imapPassword || !constantTimeEqual(auth.password, imapPassword)) {
            // fall back to API token authentication
            let result = await validateAuthToken({
                password: auth.password,
                account: auth.username,
                requiredScope: 'imap-proxy',
                remoteAddress: session.remoteAddress
            });

            if (!result.authenticated) {
                throw authenticationFailedError(REASON_MESSAGES[result.reason] || 'Access denied, failed to authenticate user');
            }
        }

        let accountObject = new Account({ account, redis, call, secret: await getSecret() });
        let accountData;
        try {
            accountData = await accountObject.loadAccountData();
        } catch (err) {
            if (!err.output || err.output.statusCode !== 404) {
                // only log non-obvious errors
                logger.error({ msg: 'Failed to load account data', account: auth.username, err });
            }

            throw authenticationFailedError('Failed to authenticate user');
        }

        if (!accountData) {
            throw authenticationFailedError('Access denied, failed to authenticate user');
        }

        return { accountObject, accountData };
    }

    return async function authenticate(auth, session) {
        let verified = await withAuthFailureBudget(
            { remoteAddress: session.remoteAddress, account: auth.username },
            () => verifyCredentials(auth, session),
            () => authenticationFailedError(REASON_MESSAGES.limited)
        );

        // Past the credential check: a refusal from here on is about the account, not about
        // what the client presented, so it does not count against the client's budget
        if (isApiBasedApp(verified.accountData?._app)) {
            let respErr = new Error('IMAP is not supported for API-based accounts');
            respErr.authenticationFailed = true;
            respErr.serverResponseCode = 'ACCOUNTDISABLED';
            respErr.responseStatus = 'NO';
            throw respErr;
        }

        return verified;
    };
}

module.exports = { createImapProxyAuthHandler, failImapAuth };
