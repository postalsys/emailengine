'use strict';

// SMTP submission-server authentication handler. Extracted from workers/smtp.js
// so the auth logic can be unit tested without booting the worker thread (which
// connects to a parentPort and starts listening at require time).

const logger = require('./logger');
const settings = require('./settings');
const tokens = require('./tokens');
const { redis } = require('./db');
const { Account } = require('./account');
const getSecret = require('./get-secret');
const { matchIp } = require('./utils/network');

/**
 * Builds the SMTP server onAuth handler.
 *
 * @param {Object} deps
 * @param {WeakMap} deps.accountCache - session -> Account cache shared with the worker
 * @param {Function} deps.call - RPC function passed to the Account instance
 * @returns {Function} async onAuth(auth, session)
 */
function createSmtpAuthHandler({ accountCache, call }) {
    return async function onAuth(auth, session) {
        if (!session.eeAuthEnabled) {
            throw new Error('Authentication not enabled');
        }

        let account = auth.username;

        let smtpPassword = await settings.get('smtpServerPassword');
        let authPass = false;

        if (!smtpPassword || auth.password !== smtpPassword) {
            if (/^[0-9a-f]{64}$/i.test(auth.password)) {
                // fallback to tokens
                let tokenData;
                try {
                    tokenData = await tokens.get(auth.password, false, { log: true, remoteAddress: session.remoteAddress });
                } catch (err) {
                    // ignore?
                }

                if (tokenData) {
                    if (tokenData.account && tokenData.account !== auth.username) {
                        throw new Error('Access denied, invalid username');
                    }

                    if (tokenData.scopes && !tokenData.scopes.includes('smtp') && !tokenData.scopes.includes('*')) {
                        logger.error({
                            msg: 'Trying to use invalid scope for a token',
                            tokenAccount: tokenData.account,
                            tokenId: tokenData.id,
                            account,
                            requestedScope: 'smtp',
                            scopes: tokenData.scopes
                        });

                        throw new Error('Access denied, invalid scope');
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

                        throw new Error('Access denied, traffic not accepted from this IP');
                    }

                    authPass = true;
                }
            }

            if (!authPass) {
                throw new Error('Failed to authenticate user');
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
    };
}

module.exports = { createSmtpAuthHandler };
