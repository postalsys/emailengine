'use strict';

const { redis } = require('./db');
const logger = require('./logger');

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

    async accountLogging(account) {
        let loggingSettings = (await this.get('logs')) || {};
        if (loggingSettings.all || (loggingSettings.accounts && loggingSettings.accounts.includes(account))) {
            return {
                enabled: true,
                maxLogLines: loggingSettings.maxLogLines
            };
        }
        return { enabled: false };
    }
};
