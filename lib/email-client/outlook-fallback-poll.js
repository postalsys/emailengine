'use strict';

const { readEnvValue, getDuration } = require('../tools');

const DEFAULT_FALLBACK_POLL_INTERVAL = 10 * 60 * 1000;
const MIN_FALLBACK_POLL_INTERVAL = 10 * 1000;

/**
 * Reads EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL: a duration, 0 switching the periodic pass off.
 * Anything unreadable gets the default, and a positive value is never shorter than ten seconds, so
 * a typo cannot point every account at Graph in a loop
 * @param {*} value - The raw environment value
 * @returns {number} Milliseconds, 0 when the pass is off
 */
function parseFallbackPollInterval(value) {
    // blank is "unset", which getDuration() would read as 0, the value that switches the pass off
    const raw = String(value ?? '').trim();
    const duration = raw ? getDuration(raw) : DEFAULT_FALLBACK_POLL_INTERVAL;
    if (!Number.isFinite(duration) || duration < 0) {
        return DEFAULT_FALLBACK_POLL_INTERVAL;
    }
    return duration && Math.max(duration, MIN_FALLBACK_POLL_INTERVAL);
}

// The interval of the periodic missed-notification recovery pass (OutlookClient.setupFallbackPollTimer()).
// Its own module so the admin UI, which runs in the API worker, reads the same value the account
// workers run with
const FALLBACK_POLL_INTERVAL = parseFallbackPollInterval(readEnvValue('EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL'));

module.exports = { parseFallbackPollInterval, FALLBACK_POLL_INTERVAL };
