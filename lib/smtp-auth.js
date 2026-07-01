'use strict';

// SMTP submission-server authentication handler. Extracted from workers/smtp.js
// so the auth logic can be unit tested without booting the worker thread (which
// connects to a parentPort and starts listening at require time).

const logger = require('./logger');
const settings = require('./settings');
const { redis } = require('./db');
const { Account } = require('./account');
const getSecret = require('./get-secret');
const { validateAuthToken, REASON_MESSAGES } = require('./auth-token');
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
    return async function onAuth(auth, session) {
        if (!session.eeAuthEnabled) {
            throw new Error('Authentication not enabled');
        }

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
    };
}

module.exports = { createSmtpAuthHandler };
