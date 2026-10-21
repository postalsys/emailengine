'use strict';

// Limits that used to exist only as environment variables and are now settings as well, so an
// operator without access to the process environment (a hosted instance, a managed container) can
// change them from the admin UI or the settings API.
//
// The environment variable still wins. It was the only way to set these for years, deployments
// rely on it, and an operator who put a value in the environment meant it: a setting saved in the
// UI must not silently override a pinned deployment value. The settings pages flag a field whose
// variable is set (envOverriddenSettings()), so a value saved there is not mistaken for one in
// effect. An environment value that does not parse is ignored as before, which now means the
// setting applies rather than the default.
//
// Reads are cached per process for a few seconds. Two of these sit on hot paths (the job options
// of every webhook and every queued message, and every audit log write), where a settings round
// trip per call would add up; the cost is that a saved change takes effect within the window.

const settings = require('./settings');
const { readEnvValue, hasEnvValue, getBoolean, getByteSize } = require('./tools');
const { asPositiveInt, asNonNegativeInt } = require('./utils/int-setting');
const { TOKEN_LOG_ENTRIES_DEFAULT, TOKEN_LOG_AGE_DEFAULT } = require('./consts');
const {
    FAILED_JOB_RETENTION_AGE_DEFAULT,
    FAILED_JOB_RETENTION_COUNT_DEFAULT,
    DEFAULT_FAILED_CONTENT_RETENTION_COUNT,
    DEFAULT_FAILED_CONTENT_RETENTION_SIZE
} = require('./queue-retention');

const CACHE_MS = 10 * 1000;

const asByteSize = value => asNonNegativeInt(getByteSize(value));

const asBoolean = value => (typeof value === 'boolean' ? value : undefined);

// key -> the environment variable that overrides it, how each source is read, and the default.
// `fromEnv` reads the raw environment string, `fromSetting` the stored value; either returns
// undefined for a value it cannot use.
const OVERRIDABLE_SETTINGS = {
    disableThreadCollapse: {
        env: 'EENGINE_DISABLE_THREAD_COLLAPSE',
        fromEnv: value => getBoolean(value),
        fromSetting: asBoolean,
        defaultValue: false
    },
    queueKeepFailed: {
        env: 'EENGINE_QUEUE_KEEP_FAILED',
        fromEnv: asPositiveInt,
        fromSetting: asPositiveInt,
        defaultValue: FAILED_JOB_RETENTION_COUNT_DEFAULT
    },
    queueKeepFailedAge: {
        env: 'EENGINE_QUEUE_KEEP_FAILED_AGE',
        fromEnv: asPositiveInt,
        fromSetting: asPositiveInt,
        defaultValue: FAILED_JOB_RETENTION_AGE_DEFAULT
    },
    queueKeepFailedContent: {
        env: 'EENGINE_QUEUE_KEEP_FAILED_CONTENT',
        fromEnv: asNonNegativeInt,
        fromSetting: asNonNegativeInt,
        defaultValue: DEFAULT_FAILED_CONTENT_RETENTION_COUNT
    },
    queueKeepFailedContentSize: {
        env: 'EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE',
        fromEnv: asByteSize,
        fromSetting: asNonNegativeInt,
        defaultValue: DEFAULT_FAILED_CONTENT_RETENTION_SIZE
    },
    tokenLogEntries: {
        env: 'EENGINE_TOKEN_LOG_ENTRIES',
        fromEnv: asPositiveInt,
        fromSetting: asPositiveInt,
        defaultValue: TOKEN_LOG_ENTRIES_DEFAULT
    },
    tokenLogAge: {
        env: 'EENGINE_TOKEN_LOG_AGE',
        fromEnv: asPositiveInt,
        fromSetting: asPositiveInt,
        defaultValue: TOKEN_LOG_AGE_DEFAULT
    }
};

const isOverridableSetting = key => Object.hasOwn(OVERRIDABLE_SETTINGS, key);

/**
 * The value in effect for one overridable setting. Pure: the environment and the stored value are
 * passed in.
 *
 * @param {string} key - A key of OVERRIDABLE_SETTINGS
 * @param {Object} sources
 * @param {boolean} sources.envSet - Whether the environment variable (or its _FILE form) is set
 * @param {*} sources.envValue - The environment value, when set
 * @param {*} sources.storedValue - The stored setting, if any
 * @returns {{value: *, source: 'env'|'setting'|'default'}}
 */
function resolveOverridableSetting(key, { envSet, envValue, storedValue }) {
    const definition = OVERRIDABLE_SETTINGS[key];
    if (!definition) {
        throw new Error(`Unknown overridable setting ${key}`);
    }

    if (envSet) {
        const fromEnv = definition.fromEnv(envValue);
        if (fromEnv !== undefined) {
            return { value: fromEnv, source: 'env' };
        }
    }

    const fromSetting = definition.fromSetting(storedValue);
    if (fromSetting !== undefined) {
        return { value: fromSetting, source: 'setting' };
    }

    return { value: definition.defaultValue, source: 'default' };
}

function envSource(key) {
    const { env } = OVERRIDABLE_SETTINGS[key];
    const envSet = hasEnvValue(env);
    return { envSet, envValue: envSet ? readEnvValue(env) : undefined };
}

/**
 * The environment value or the default, without the stored setting, for the few readers that are
 * fixed when a module loads (the token log route's page size bound) and so can not wait on a read
 * @param {string} key - A key of OVERRIDABLE_SETTINGS
 * @returns {*}
 */
function envOrDefault(key) {
    return resolveOverridableSetting(key, envSource(key)).value;
}

/**
 * The keys whose environment variable is set and readable, for the settings pages to flag.
 * @param {string[]} [keys] - Limit the answer to these keys
 * @returns {Array<{key: string, env: string}>}
 */
function envOverriddenSettings(keys) {
    return Object.keys(OVERRIDABLE_SETTINGS)
        .filter(key => !keys || keys.includes(key))
        .filter(key => {
            const { envSet, envValue } = envSource(key);
            return envSet && OVERRIDABLE_SETTINGS[key].fromEnv(envValue) !== undefined;
        })
        .map(key => ({ key, env: OVERRIDABLE_SETTINGS[key].env }));
}

// key -> { at, value }, where value is the promise of the read that fetched it, so callers that
// arrive while a read is in flight share it instead of each issuing their own
let cache = new Map();

/**
 * Reads the stored values of the given keys and resolves what is in effect for each
 * @param {string[]} keys
 * @returns {Promise<{values: Object, failed: boolean}>} Never rejects
 */
async function readOverridableSettings(keys) {
    let stored;
    let failed = false;
    try {
        stored = (await settings.getMulti(...keys)) || {};
    } catch (err) {
        // A settings read must not decide whether a job is queued or a request is logged; the
        // environment and the defaults still apply, and are not cached, so the next call asks again
        stored = {};
        failed = true;
    }
    const values = {};
    for (const key of keys) {
        values[key] = resolveOverridableSetting(key, Object.assign(envSource(key), { storedValue: stored[key] })).value;
    }
    return { values, failed };
}

/**
 * The values in effect for the given overridable settings, read through a short per-process cache.
 * @param {...string} keys - Keys of OVERRIDABLE_SETTINGS
 * @returns {Promise<Object>} key -> value
 */
async function getOverridableSettings(...keys) {
    const now = Date.now();
    const missing = keys.filter(key => {
        const cached = cache.get(key);
        return !(cached && now - cached.at < CACHE_MS);
    });

    if (missing.length) {
        const read = readOverridableSettings(missing);
        const entries = missing.map(key => {
            const entry = { at: now, value: read.then(({ values }) => values[key]) };
            cache.set(key, entry);
            return [key, entry];
        });
        read.then(({ failed }) => {
            if (failed) {
                for (const [key, entry] of entries) {
                    if (cache.get(key) === entry) {
                        cache.delete(key);
                    }
                }
            }
        });
    }

    const result = {};
    for (const key of keys) {
        result[key] = await cache.get(key).value;
    }
    return result;
}

/**
 * The failed-job bounds for BullMQ's removeOnFail and the periodic queue cleanup.
 * @returns {Promise<{age: number, count: number}>} Age in seconds, and count
 */
async function getFailedJobRetention() {
    const values = await getOverridableSettings('queueKeepFailed', 'queueKeepFailedAge');
    return { age: values.queueKeepFailedAge, count: values.queueKeepFailed };
}

// Exposed so tests, and a settings write in this process, can drop the cache
function resetOverridableSettingsCache() {
    cache = new Map();
}

/**
 * Writes a settings form's values, treating the overridable keys the way their pages show them:
 * an overridable key whose environment variable is in effect is not written, because the form
 * shows the environment value and saving it would copy that value into a setting that outlives
 * the variable; null clears an overridable key, so the environment or the default applies again.
 * Every other key is written as given. Drops the cache, so this process sees the change at once.
 *
 * @param {Object} data - key -> value, as settings.setMulti() takes it
 * @returns {Promise<void>}
 */
async function writeOverridableSettings(data) {
    const pinned = new Set(envOverriddenSettings().map(entry => entry.key));
    const write = {};
    const clear = [];
    for (const [key, value] of Object.entries(data)) {
        if (!isOverridableSetting(key)) {
            write[key] = value;
        } else if (pinned.has(key)) {
            continue;
        } else if (value === null || value === undefined) {
            clear.push(key);
        } else {
            write[key] = value;
        }
    }

    if (Object.keys(write).length) {
        await settings.setMulti(write);
    }
    await settings.clear(...clear);
    resetOverridableSettingsCache();
}

/**
 * Writes one overridable setting through the API, where null (or nothing) clears it, so the
 * environment value or the default applies again. Unlike the settings forms, a key whose
 * environment variable is set is still written when a client sends it: the request names the
 * value, and the environment keeps winning while it is set.
 * @param {string} key - A key of OVERRIDABLE_SETTINGS
 * @param {*} value
 * @returns {Promise<void>}
 */
async function storeOverridableSetting(key, value) {
    if (value === null || value === undefined) {
        await settings.clear(key);
    } else {
        await settings.set(key, value);
    }
    resetOverridableSettingsCache();
}

module.exports = {
    OVERRIDABLE_SETTINGS,
    isOverridableSetting,
    envOrDefault,
    storeOverridableSetting,
    resolveOverridableSetting,
    envOverriddenSettings,
    getOverridableSettings,
    getFailedJobRetention,
    resetOverridableSettingsCache,
    writeOverridableSettings
};
