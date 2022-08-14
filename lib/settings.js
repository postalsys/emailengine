'use strict';

const { redis } = require('./db');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const config = require('wild-config');
const getSecret = require('./get-secret');

const { DEFAULT_MAX_LOG_LINES, REDIS_PREFIX } = require('./consts');

config.service = config.service || {};

const ENCRYPTED_KEYS = [
    'gmailClientSecret',
    'outlookClientSecret',
    'cookiePassword',
    'smtpServerPassword',
    'serviceSecret',
    'gmailServiceKey',
    'documentStorePassword'
];

module.exports = {
    encryptedKeys: ENCRYPTED_KEYS,

    async get(key) {
        const encryptSecret = await getSecret();

        let value = await redis.hget(`${REDIS_PREFIX}settings`, key);
        if (!value) {
            return null;
        }

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

        if (/^documentStore/.test(key)) {
            // increase version for documentStore settings
            try {
                await redis.hincrby(`${REDIS_PREFIX}settings`, 'documentStoreVersion', 1);
            } catch (err) {
                logger.debug({ msg: 'Failed to increase document store settings version', key, err });
            }
        }

        return await redis.hset(`${REDIS_PREFIX}settings`, key, value);
    },

    async clear(key) {
        return await redis.hdel(`${REDIS_PREFIX}settings`, key);
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
            let accountLoggingEnabled = (await redis.hget(`${REDIS_PREFIX}iad:${account}`, 'logs')) === 'true' ? true : false;
            return {
                enabled: accountLoggingEnabled,
                maxLogLines
            };
        }

        return {
            enabled: false,
            maxLogLines
        };
    },

    async exportLicense() {
        let license = await redis.hget(`${REDIS_PREFIX}settings`, 'license');
        if (!license) {
            return;
        }

        let encodedLicense = Buffer.from(
            license
                .toString()
                .split(/\r?\n/)
                .map(line => line.trim())
                .filter(line => line && !/[^a-z0-9+/=]/i.test(line))
                .join(''),
            'base64'
        ).toString('base64url');

        return encodedLicense;
    },

    async importLicense(licenseFile, checkLicense) {
        if (!licenseFile) {
            throw new Error('License file not provided');
        }
        if (!/BEGIN LICENSE/.test(licenseFile)) {
            licenseFile = `-----BEGIN LICENSE-----
${Buffer.from(licenseFile, 'base64url').toString('base64')}
-----END LICENSE-----`;
        }

        let licenseData = await checkLicense(licenseFile);
        if (!licenseData) {
            throw new Error('Failed to verify provided license');
        }

        return await module.exports.setLicense(licenseData, licenseFile);
    },

    async setLicense(licenseData, licenseFile) {
        if (licenseData.expires && Date.now() > new Date(licenseData.expires)) {
            let err = new Error('License expired');
            err.code = 'ELicenseExpired';
            throw err;
        }

        if (licenseData.trial) {
            // check if can activate a trial license
            let trialActivated = await redis.hget(`${REDIS_PREFIX}settings`, 'tract');
            if (trialActivated) {
                let trialData;
                try {
                    trialData = JSON.parse(trialActivated);
                } catch (err) {
                    // ignore?
                }
                if (trialData && trialData.key !== licenseData.key) {
                    let err = new Error('Trial already activated');
                    err.code = 'ETrialActive';
                    throw err;
                }
            }
        }

        await redis
            .multi()
            .hset(`${REDIS_PREFIX}settings`, 'license', licenseFile)
            .hdel(`${REDIS_PREFIX}settings`, 'subexp')
            .hset(
                `${REDIS_PREFIX}settings`,
                'tract',
                JSON.stringify({
                    created: new Date().toISOString(),
                    expires: licenseData.expires,
                    key: licenseData.key
                })
            )
            .exec();

        return true;
    }
};
