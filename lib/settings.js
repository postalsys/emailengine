'use strict';

const { redis } = require('./db');
const logger = require('./logger');

const DEFAULT_MAX_LOG_LINES = 10000;

module.exports = {
    async get(key) {
        let value = await redis.hget('settings', key);
        if (typeof value === 'string') {
            try {
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
        return await redis.hset('settings', key, value);
    },

    async getLoggingInfo(account) {
        let loggingSettings = (await this.get('logs')) || {};
        if (loggingSettings.all || (account && loggingSettings.accounts && loggingSettings.accounts.includes(account))) {
            return {
                enabled: true,
                maxLogLines: 'maxLogLines' in loggingSettings ? loggingSettings.maxLogLines : DEFAULT_MAX_LOG_LINES
            };
        }
        return {
            enabled: false,
            maxLogLines: DEFAULT_MAX_LOG_LINES
        };
    }
};
