'use strict';

const { redis } = require('./db');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const config = require('wild-config');
const getSecret = require('./get-secret');

const { DEFAULT_MAX_LOG_LINES } = require('./consts');

config.service = config.service || {};

const ENCRYPTED_KEYS = ['gmailClientSecret', 'cookiePassword'];

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
        if (loggingSettings.all || (account && loggingSettings.accounts && loggingSettings.accounts.includes(account))) {
            return {
                enabled: true,
                maxLogLines: 'maxLogLines' in loggingSettings ? loggingSettings.maxLogLines : DEFAULT_MAX_LOG_LINES
            };
        }
        return {
            enabled: false,
            maxLogLines: 'maxLogLines' in loggingSettings ? loggingSettings.maxLogLines : DEFAULT_MAX_LOG_LINES
        };
    }
};
