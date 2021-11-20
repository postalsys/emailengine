'use strict';

const { redis } = require('./db');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const config = require('wild-config');
const getSecret = require('./get-secret');

const { DEFAULT_MAX_LOG_LINES } = require('./consts');

config.service = config.service || {};

const ENCRYPTED_KEYS = ['gmailClientSecret', 'outlookClientSecret', 'cookiePassword'];

module.exports = {
    encryptedKeys: ENCRYPTED_KEYS,

    async get(key) {
        const encryptSecret = await getSecret();

        let value = await redis.hget('settings', key);
        if (typeof value === 'string') {
            try {
                if (encryptSecret && ENCRYPTED_KEYS.includes(key) && typeof value === 'string') {
                    // NB! throws if password is invalid
                    value = decrypt(value, encryptSecret);
                }

                value = JSON.parse(value);
            } catch (err) {
                logger.debug({ key, value, err });
                return null;
            }
        }

        switch (key) {
            case 'gmailRedirectUrl':
            case 'outlookRedirectUrl':
                if (!value) {
                    let serviceUrl = await module.exports.get('serviceUrl');

                    if (serviceUrl) {
                        if (key === 'outlookRedirectUrl') {
                            // Outlook does not allow http://127.0.0.1 as the target, use localhost instead
                            serviceUrl = serviceUrl.replace(/^http:\/\/127\.0\.0\.1\b/i, 'http://localhost');
                        }

                        value = `${serviceUrl}/oauth`;
                    }
                }
                break;

            case 'logs':
                if (!value) {
                    value = {
                        all: false,
                        maxLogLines: DEFAULT_MAX_LOG_LINES
                    };
                }
                break;
        }

        return value;
    },

    async set(key, value) {
        const encryptSecret = await getSecret();

        value = JSON.stringify(value);

        if (encryptSecret && ENCRYPTED_KEYS.includes(key)) {
            value = encrypt(value, encryptSecret);
        }

        return await redis.hset('settings', key, value);
    },

    async getLoggingInfo(account, settingData) {
        let loggingSettings = settingData || (await this.get('logs')) || {};

        let maxLogLines = 'maxLogLines' in loggingSettings ? loggingSettings.maxLogLines : DEFAULT_MAX_LOG_LINES;

        if (loggingSettings.all) {
            return {
                enabled: true,
                maxLogLines
            };
        }

        if (account) {
            let accountLoggingEnabled = (await redis.hget(`iad:${account}`, 'logs')) === 'true' ? true : false;
            return {
                enabled: accountLoggingEnabled,
                maxLogLines
            };
        }

        return {
            enabled: false,
            maxLogLines
        };
    }
};
