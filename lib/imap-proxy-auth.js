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
const { isTransientCredentialError } = require('./email-client/credential-errors');

/**
 * Tags an error as an IMAP authentication rejection for the proxy client.
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
 * Tags an error as a temporary failure the client should retry rather than a rejected password.
 * Deliberately without the authenticationFailed flag: nothing refused the credential, the service
 * that holds it was unreachable. RFC 5530 [UNAVAILABLE] is the code for exactly that, and the
 * response status has to be set explicitly - an error reaching the IMAP server with no `response`
 * is rendered as BAD and counts against the connection's bad-command budget.
 *
 * @param {Error} err - Error to tag
 * @returns {Error} the same error
 */
function failImapUnavailable(err) {
    err.serverResponseCode = 'UNAVAILABLE';
    err.responseStatus = 'NO';
    return err;
}

/**
 * Decides how a failed attempt to obtain the account's upstream credentials is answered. One
 * authentication server serves every account on the instance, so its bad minute must not reach a
 * desktop client as a wrong password - which is what makes the user retype a working one.
 *
 * @param {Error} err - The credential failure
 * @returns {Error} the same error, tagged with the response to send
 */
function classifyCredentialFailure(err) {
    return isTransientCredentialError(err) ? failImapUnavailable(err) : failImapAuth(err);
}

/**
 * Whether an error already names the IMAP response to answer the client with, as opposed to being
 * an internal proxy fault. Both a refusal and a temporary failure carry one.
 *
 * @param {Error} err - The error to check
 * @returns {boolean} True when the error carries an IMAP response
 */
function isImapResponseError(err) {
    return !!err && (!!err.authenticationFailed || err.serverResponseCode === 'AUTHENTICATIONFAILED' || err.serverResponseCode === 'UNAVAILABLE');
}

/**
 * Renders a tagged failure as the error the IMAP server answers the client with. imap-core reads
 * the status off `response`, and an error that carries none is answered BAD, which counts against
 * the connection's bad-command budget instead of telling the client what happened.
 *
 * @param {Error} err - The tagged failure
 * @returns {Error} A new error carrying the response line to send
 */
function toImapResponseError(err) {
    let error = new Error(`${err.serverResponseCode ? `[${err.serverResponseCode}] ` : ''}${err.responseText || err.message || 'Authentication failed'}`);
    error.response = err.responseStatus || 'NO';
    return error;
}

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

// Only what the proxy server and its tests reach for: the two taggers are reached through
// classifyCredentialFailure(), which is the decision that has to be made in one place
module.exports = { createImapProxyAuthHandler, classifyCredentialFailure, isImapResponseError, toImapResponseError };
