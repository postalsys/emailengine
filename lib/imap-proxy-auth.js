'use strict';

// IMAP proxy authentication. Extracted from lib/imapproxy/imap-server.js so the
// auth decision can be unit tested without booting the proxy worker (which uses
// a parentPort at require time). Only the authentication portion is extracted;
// the backend IMAP connection config is still built by the server.

const logger = require('./logger');
const settings = require('./settings');
const tokens = require('./tokens');
const { redis } = require('./db');
const { Account } = require('./account');
const getSecret = require('./get-secret');
const { matchIp } = require('./utils/network');
const { isApiBasedApp } = require('./oauth2-apps');

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
        let authPass = false;

        if (!imapPassword || auth.password !== imapPassword) {
            if (/^[0-9a-f]{64}$/i.test(auth.password)) {
                // fallback to tokens
                let tokenData;
                try {
                    tokenData = await tokens.get(auth.password, false, { log: true, remoteAddress: session.remoteAddress });
                } catch (err) {
                    logger.error({
                        msg: 'Failed to fetch token',
                        err
                    });
                }

                if (tokenData) {
                    if (tokenData.account && tokenData.account !== auth.username) {
                        let err = new Error('Access denied, invalid username');
                        err.serverResponseCode = 'AUTHENTICATIONFAILED';
                        err.responseStatus = 'NO';
                        throw err;
                    }

                    if (tokenData.scopes && !tokenData.scopes.includes('imap-proxy') && !tokenData.scopes.includes('*')) {
                        logger.error({
                            msg: 'Trying to use invalid scope for a token',
                            tokenAccount: tokenData.account,
                            tokenId: tokenData.id,
                            account,
                            requestedScope: 'imap-proxy',
                            scopes: tokenData.scopes
                        });

                        let err = new Error('Access denied, invalid scope');
                        err.serverResponseCode = 'AUTHENTICATIONFAILED';
                        err.responseStatus = 'NO';
                        throw err;
                    }

                    if (tokenData.restrictions && tokenData.restrictions.addresses && !matchIp(session.remoteAddress, tokenData.restrictions.addresses)) {
                        logger.error({
                            msg: 'Trying to use invalid IP for a token',
                            tokenAccount: tokenData.account,
                            tokenId: tokenData.id,
                            account,
                            remoteAddress: session.remoteAddress,
                            addressAllowlist: tokenData.restrictions.addresses
                        });

                        let err = new Error('Access denied, traffic not accepted from this IP');
                        err.serverResponseCode = 'AUTHENTICATIONFAILED';
                        err.responseStatus = 'NO';
                        throw err;
                    }

                    authPass = true;
                }
            }

            if (!authPass) {
                let err = new Error('Access denied, failed to authenticate user');
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
