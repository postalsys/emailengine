'use strict';

const { redis } = require('./db');
const logger = require('./logger');
const { encrypt, decrypt } = require('./encrypt');
const config = require('@zone-eu/wild-config');
const getSecret = require('./get-secret');

const { DEFAULT_MAX_LOG_LINES, REDIS_PREFIX } = require('./consts');

config.service = config.service || {};

// Values that are secrets in their entirety. Encrypted at rest, and the settings API returns a
// boolean marker in their place rather than the value.
const SECRET_KEYS = [
    // The gmail*/outlook*/mailRu* secrets belong to the retired settings-based OAuth2
    // configuration. They stay listed so oauth2Apps.migrateLegacyApps() can still decrypt
    // stored values through settings.get() before moving them into the app registry.
    'gmailClientSecret',
    'outlookClientSecret',
    'mailRuClientSecret',
    'cookiePassword',
    'smtpServerPassword',
    'imapProxyServerPassword',
    'serviceSecret',
    'gmailServiceKey',
    'gmailServiceExternalAccount',
    'documentStorePassword',
    'openAiAPIKey',
    'totpSeed'
];

// Values that carry a secret without being one: URLs that may embed `user:pass@` credentials
// (a SOCKS or HTTP proxy, a webhook target, a Sentry DSN with its key) and the custom webhook
// headers, whose example is an Authorization bearer. Encrypted at rest like the secrets, but the
// API reads them back with only the credential part masked (route-helpers maskSecrets()), so they
// are not in the list it turns into booleans. Encryption applies to the JSON encoding, so the
// header list being an array rather than a string makes no difference.
const CREDENTIAL_BEARING_KEYS = ['webhooks', 'webhooksCustomHeaders', 'proxyUrl', 'httpProxyUrl', 'sentryDsn'];

const ENCRYPTED_KEYS = SECRET_KEYS.concat(CREDENTIAL_BEARING_KEYS);

// getValue() runs on an uncached read path - settings.get() is called several times per synced
// message and once per webhook delivery - and a decrypt/parse failure is permanent rather than
// transient (a rotated EENGINE_SECRET, a corrupt stored value). Reporting every occurrence would
// emit a serialized error and stack per message forever, so each key is reported once and rearmed
// only after it parses successfully again.
const reportedParseFailures = new Set();

module.exports = {
    // Everything encrypted at rest: what `emailengine encrypt` re-encrypts on a secret rotation
    encryptedKeys: ENCRYPTED_KEYS,

    // The subset the settings API returns as a boolean marker (lib/api-routes/settings-routes.js).
    // The credential-bearing URLs are encrypted too but are returned with just the credentials
    // masked, so a consumer that hides values has to read this list, not encryptedKeys.
    secretKeys: SECRET_KEYS,

    /**
     * Whether admin authentication is configured for this instance.
     *
     * The single spelling of the test that gates `server.auth.default('session')` in workers/api.js.
     * Routes that are only protected by that default are reachable by anyone when it returns false,
     * so anything they expose has to gate on this explicitly.
     *
     * @returns {Promise<Boolean>} True when an admin password has been set
     */
    async isInstanceSecured() {
        return !!(await module.exports.get('authData'));
    },

    async getValue(encryptSecret, key, value) {
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

                reportedParseFailures.delete(key);
            } catch (err) {
                // NB! never log `value` here. By this point a value for an encrypted key has
                // already been decrypted, so on a parse failure this would write the plaintext
                // secret (OAuth2 client secrets, the SMTP/IMAP proxy passwords) into the log.
                // The error object is not safe either: a JSON.parse SyntaxError quotes the head of
                // its input, which for an encrypted key is that same plaintext.
                let encrypted = ENCRYPTED_KEYS.includes(key);
                if (!reportedParseFailures.has(key)) {
                    reportedParseFailures.add(key);
                    if (encrypted) {
                        logger.warn({ msg: 'Failed to parse stored setting', key, encrypted, errorType: err.name });
                    } else {
                        logger.warn({ msg: 'Failed to parse stored setting', key, encrypted, err });
                    }
                }
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

    async getMulti(...keys) {
        const encryptSecret = await getSecret();

        let values = await redis.hmget(`${REDIS_PREFIX}settings`, keys);
        let result = {};
        for (let i = 0; i < keys.length; i++) {
            let key = keys[i];
            let value = values[i];
            result[key] = await this.getValue(encryptSecret, key, value);
        }

        return result;
    },

    async get(key) {
        const encryptSecret = await getSecret();

        let value = await redis.hget(`${REDIS_PREFIX}settings`, key);

        return await this.getValue(encryptSecret, key, value);
    },

    formatSettingValue(key, value) {
        switch (key) {
            case 'serviceUrl': {
                if (!value) {
                    return value;
                }
                let urlObj = new URL(value);
                return urlObj.origin;
            }

            case 'scriptEnv':
                if (value && typeof value === 'object') {
                    try {
                        value = JSON.stringify(value);
                    } catch (err) {
                        logger.error({ msg: 'Failed to process setting value', key, err });
                        return '';
                    }
                }

                if (typeof value !== 'string') {
                    logger.error({ msg: 'Setting value is not a string', key });
                    return '';
                }

                if (!value || !value.trim()) {
                    return '';
                }

                try {
                    let parsed = JSON.parse(value);
                    return JSON.stringify(parsed, false, 2);
                } catch (err) {
                    logger.error({ msg: 'Failed to process setting value', key, err });
                }

                break;
        }

        return value;
    },

    // Serialize an already-formatted setting value the way get()/getValue() expect it back:
    // JSON-encoded, encrypted for ENCRYPTED_KEYS members. Every writer (set, setMulti,
    // setIfMissing) must go through this so the encoding cannot drift between them.
    encodeSettingValue(key, formattedValue, encryptSecret) {
        let value = JSON.stringify(formattedValue);

        if (encryptSecret && ENCRYPTED_KEYS.includes(key)) {
            value = encrypt(value, encryptSecret);
        }

        return value;
    },

    async set(key, value) {
        // A blank serviceSecret must never be persisted: an empty stored secret breaks HMAC
        // signing/verification for every hosted-form and tracking link, and makes getServiceSecret()
        // silently mint a fresh secret - invalidating every signed link already out in delivered mail.
        // A blank value means "keep the current secret", not "clear it". Enforced here so it covers every
        // writer that reaches set() (the /v1/settings API and the EENGINE_SETTINGS prepared config), not
        // just the admin UI which additionally surfaces a flash. Boot-time minting (server.js) passes a
        // non-empty random value, so it is unaffected.
        if (key === 'serviceSecret' && (typeof value !== 'string' || !value.trim())) {
            return 0;
        }

        // An explicit sentryEnabled write is an operator decision, so it ends the trial-managed
        // state where setLicense() owns the value (the trial default itself is written through
        // setIfMissing(), which skips this rule by design)
        if (key === 'sentryEnabled') {
            await module.exports.clear('sentryAutoEnabled');
        }

        const encryptSecret = await getSecret();

        let formattedValue = module.exports.formatSettingValue(key, value);
        value = module.exports.encodeSettingValue(key, formattedValue, encryptSecret);

        if (/^documentStore/.test(key)) {
            // increase version for documentStore settings
            try {
                await redis.hincrby(`${REDIS_PREFIX}settings`, 'documentStoreVersion', 1);
            } catch (err) {
                logger.debug({ msg: 'Failed to increase document store settings version', key, err });
            }
        }

        if (['generateEmailSummary', 'openAiGenerateEmbeddings'].includes(key) && formattedValue) {
            // AI processing needs access to message text content, so make sure `notifyText` is enabled as well
            await module.exports.set('notifyText', true);
        }

        if (/^openAi/.test(key) || key === 'generateEmailSummary') {
            // increase version for OpenAI settings
            try {
                await redis.hincrby(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion', 1);
            } catch (err) {
                logger.debug({ msg: 'Failed to increase Open AI settings version', key, err });
            }
        }

        return await redis.hset(`${REDIS_PREFIX}settings`, key, value);
    },

    // Store a value only if the key does not exist yet (atomic HSETNX). Meant for one-shot
    // initialization keys (the auto-generated serviceSecret, the trial default for
    // sentryEnabled) where an existing value must never be overwritten. Skips the side effects
    // of set() on purpose. Returns true when the value was stored.
    async setIfMissing(key, value) {
        const encryptSecret = await getSecret();

        value = module.exports.encodeSettingValue(key, module.exports.formatSettingValue(key, value), encryptSecret);

        return (await redis.hsetnx(`${REDIS_PREFIX}settings`, key, value)) === 1;
    },

    // Like setIfMissing(), but stamps a marker key in the same atomic Redis step when the value
    // was stored. For seeded defaults whose marker says "the seeder still owns this value":
    // written as two separate commands, a crash between them leaves the seeded value behind with
    // no marker, indistinguishable from an explicit operator choice (see setLicense()).
    async setIfMissingWithMarker(key, value, markerKey, markerValue) {
        const encryptSecret = await getSecret();

        value = module.exports.encodeSettingValue(key, module.exports.formatSettingValue(key, value), encryptSecret);
        markerValue = module.exports.encodeSettingValue(markerKey, module.exports.formatSettingValue(markerKey, markerValue), encryptSecret);

        return (await redis.hSetNewMark(`${REDIS_PREFIX}settings`, key, value, markerKey, markerValue)) === 1;
    },

    async setMulti(obj) {
        const encryptSecret = await getSecret();
        let docStoreUpdated = false;
        const storeObj = {};
        for (let key of Object.keys(obj)) {
            // See set(): never persist a blank serviceSecret - a blank value means "keep the current one".
            if (key === 'serviceSecret' && (typeof obj[key] !== 'string' || !obj[key].trim())) {
                continue;
            }

            let formattedValue = module.exports.formatSettingValue(key, obj[key]);
            storeObj[key] = module.exports.encodeSettingValue(key, formattedValue, encryptSecret);

            if (/^documentStore/.test(key)) {
                docStoreUpdated = true;
            }
        }

        if (docStoreUpdated) {
            // increase version for documentStore settings
            try {
                await redis.hincrby(`${REDIS_PREFIX}settings`, 'documentStoreVersion', 1);
            } catch (err) {
                logger.debug({ msg: 'Failed to increase document store settings version', err });
            }
        }

        // see set(): an explicit sentryEnabled write ends the trial-managed Sentry state
        if ('sentryEnabled' in obj) {
            await module.exports.clear('sentryAutoEnabled');
        }

        return await redis.hmset(`${REDIS_PREFIX}settings`, storeObj);
    },

    async clear(key) {
        return await redis.hdel(`${REDIS_PREFIX}settings`, key);
    },

    async getLoggingInfo(account, settingData) {
        let loggingSettings = settingData || (await module.exports.get('logs')) || {};

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

        // Trial installations report errors to the shared community Sentry by default, so issues
        // with evaluation instances reach the developers. The default is only applied while the
        // operator has never touched the sentryEnabled setting, tracked through the internal
        // sentryAutoEnabled marker; the value and the marker are written in one atomic step
        // (setIfMissingWithMarker), because a value stored without its marker would read as a
        // permanent operator opt-in. Activating a full license or removing the license clears
        // the default again as long as the marker still owns the state, and any explicit
        // operator write to sentryEnabled drops the marker (see set()/setMulti()), making that
        // choice permanent. A SENTRY_DSN environment value pins the Sentry configuration
        // regardless of these settings. License activation must never fail on this convenience,
        // hence the catch-all.
        try {
            if (licenseData.trial) {
                if (await module.exports.setIfMissingWithMarker('sentryEnabled', true, 'sentryAutoEnabled', true)) {
                    logger.info({ msg: 'Enabled Sentry error reporting for the trial license' });
                }
            } else {
                await module.exports.clearTrialSentryDefault('license activation');
            }
        } catch (err) {
            logger.error({ msg: 'Failed to apply the trial Sentry default', err });
        }

        return true;
    },

    // Undoes the trial Sentry default while the sentryAutoEnabled marker still owns the state;
    // a no-op after any explicit operator choice. Never throws: callers sit on license
    // activation/removal paths that must not fail on this convenience.
    async clearTrialSentryDefault(reason) {
        try {
            if (await module.exports.get('sentryAutoEnabled')) {
                await module.exports.clear('sentryEnabled');
                await module.exports.clear('sentryAutoEnabled');
                logger.info({ msg: 'Disabled the trial default for Sentry error reporting', reason });
            }
        } catch (err) {
            logger.error({ msg: 'Failed to clear the trial Sentry default', reason, err });
        }
    },

    // Owns the stored license state: the license file itself, the subscription grace marker,
    // and the trial Sentry default that activation may have applied. Used by the explicit
    // remove-license actions and by the grace-period expiry in server.js.
    async removeLicense() {
        await redis.multi().hdel(`${REDIS_PREFIX}settings`, 'license').hdel(`${REDIS_PREFIX}settings`, 'subexp').exec();
        await module.exports.clearTrialSentryDefault('license removal');
        return true;
    }
};
