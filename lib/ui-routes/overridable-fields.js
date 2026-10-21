'use strict';

// Form fields for the settings that an environment variable can override
// (lib/env-setting-overrides.js). Some are shown in a friendlier unit than the one stored - days
// for a setting kept in seconds, megabytes for one kept in bytes - so the conversion lives here,
// next to the values the pages read and write. A blank field arrives as null and stays null,
// which writeOverridableSettings() reads as "clear this setting".

const { getOverridableSettings } = require('../env-setting-overrides');

const DAY = 24 * 3600;
const MEGABYTE = 1024 * 1024;

const isNumber = value => typeof value === 'number' && Number.isFinite(value);

// Rounded to two decimals so an age set through the API in odd seconds still shows something a
// form can submit back unchanged in meaning
const secondsToDays = seconds => (isNumber(seconds) ? Math.round((seconds / DAY) * 100) / 100 : null);
const daysToSeconds = days => (isNumber(days) ? Math.round(days * DAY) : null);

const bytesToMegabytes = bytes => (isNumber(bytes) ? Math.round((bytes / MEGABYTE) * 100) / 100 : null);
const megabytesToBytes = megabytes => (isNumber(megabytes) ? Math.round(megabytes * MEGABYTE) : null);

const msToSeconds = ms => (isNumber(ms) ? Math.round(ms / 10) / 100 : null);
const secondsToMs = seconds => (isNumber(seconds) ? Math.round(seconds * 1000) : null);

// key -> [stored to form, form to stored]; keys not listed are shown as stored. Not limited to the
// overridable settings: any settings form field kept in a unit other than the one it shows is here
const FORM_UNITS = {
    queueKeepFailedAge: [secondsToDays, daysToSeconds],
    queueKeepFailedContentSize: [bytesToMegabytes, megabytesToBytes],
    tokenLogAge: [secondsToDays, daysToSeconds],
    webhooksRetryDelay: [msToSeconds, secondsToMs]
};

/**
 * A stored value in the unit its form field shows
 * @param {string} key - Setting key
 * @param {*} value - Stored value
 * @returns {*}
 */
const toFormValue = (key, value) => (FORM_UNITS[key] ? FORM_UNITS[key][0](value) : value);

/**
 * A form value in the unit the setting is stored in
 * @param {string} key - Setting key
 * @param {*} value - Validated form value, null for a blank field
 * @returns {*}
 */
const fromFormValue = (key, value) => (FORM_UNITS[key] ? FORM_UNITS[key][1](value) : value);

/**
 * The values in effect for the given keys, in the units their form fields show. The page shows
 * what applies whichever source set it, the environment included.
 * @param {...string} keys - Overridable setting keys
 * @returns {Promise<Object>} field name -> value
 */
async function overridableFormValues(...keys) {
    const values = await getOverridableSettings(...keys);
    return Object.fromEntries(keys.map(key => [key, toFormValue(key, values[key])]));
}

/**
 * The settings to write for the given keys from a validated form payload, in stored units.
 * @param {Object} payload - Validated request payload
 * @param {...string} keys - Overridable setting keys
 * @returns {Object} key -> value (null to clear)
 */
function overridableSettingsFromForm(payload, ...keys) {
    return Object.fromEntries(keys.map(key => [key, fromFormValue(key, payload[key] === undefined ? null : payload[key])]));
}

module.exports = {
    overridableFormValues,
    overridableSettingsFromForm,
    toFormValue,
    fromFormValue,
    secondsToDays,
    daysToSeconds,
    bytesToMegabytes,
    megabytesToBytes,
    msToSeconds,
    secondsToMs
};
