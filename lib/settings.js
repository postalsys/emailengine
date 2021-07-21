'use strict';

const { redis } = require('./db');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const config = require('wild-config');

config.service = config.service || {};

const DEFAULT_MAX_LOG_LINES = 10000;
const ENCRYPT_PASSWORD = process.env.IMAPAPI_SECRET || config.service.secret;
const ENCRYPTED_KEYS = ['gmailClientSecret'];

module.exports = {
    encryptedKeys: ENCRYPTED_KEYS,

    async get(key) {
        let value = await redis.hget('settings', key);
        if (typeof value === 'string') {
            try {
                if (ENCRYPT_PASSWORD && ENCRYPTED_KEYS.includes(key) && typeof value === 'string') {
                    // NB! throws if password is invalid
                    value = decrypt(value, ENCRYPT_PASSWORD);
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
        value = JSON.stringify(value);

        if (ENCRYPT_PASSWORD && ENCRYPTED_KEYS.includes(key)) {
            value = encrypt(value, ENCRYPT_PASSWORD);
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
