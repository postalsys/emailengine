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
const { validateAuthToken, REASON_MESSAGES } = require('./auth-token');

/**
 * Builds the IMAP proxy authentication handler.
 *
 * @param {Object} deps
 * @param {Function} deps.call - RPC function passed to the Account instance
 * @returns {Function} async authenticate(auth, session) -> { accountObject, accountData }
 */
function createImapProxyAuthHandler({ call }) {
    return async function authenticate(auth, session) {
        let account = auth.username;

        let imapPassword = await settings.get('imapProxyServerPassword');
        if (!imapPassword || auth.password !== imapPassword) {
            // fall back to API token authentication
            let result = await validateAuthToken({
                password: auth.password,
                account: auth.username,
                requiredScope: 'imap-proxy',
                remoteAddress: session.remoteAddress
            });

            if (!result.authenticated) {
                let err = new Error(REASON_MESSAGES[result.reason] || 'Access denied, failed to authenticate user');
                err.serverResponseCode = 'AUTHENTICATIONFAILED';
                err.responseStatus = 'NO';
                throw err;
            }
        }

        let accountObject = new Account({ account, redis, call, secret: await getSecret() });
        let accountData;
        try {
            accountData = await accountObject.loadAccountData();
        } catch (err) {
            let respErr = new Error('Failed to authenticate user');
            respErr.serverResponseCode = 'AUTHENTICATIONFAILED';
            respErr.responseStatus = 'NO';

            if (!err.output || err.output.statusCode !== 404) {
                // only log non-obvious errors
                logger.error({ msg: 'Failed to load account data', account: auth.username, err });
            }

            throw respErr;
        }

        if (isApiBasedApp(accountData?._app)) {
            let respErr = new Error('IMAP is not supported for API-based accounts');
            respErr.authenticationFailed = true;
            respErr.serverResponseCode = 'ACCOUNTDISABLED';
            respErr.responseStatus = 'NO';
            throw respErr;
        }

        if (!accountData) {
            let err = new Error('Access denied, failed to authenticate user');
            err.serverResponseCode = 'AUTHENTICATIONFAILED';
            err.responseStatus = 'NO';
            throw err;
        }

        return { accountObject, accountData };
    };
}

module.exports = { createImapProxyAuthHandler };
