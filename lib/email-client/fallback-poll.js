'use strict';

const { readEnvValue, getDuration } = require('../tools');

const DEFAULT_FALLBACK_POLL_INTERVAL = 10 * 60 * 1000;
const MIN_FALLBACK_POLL_INTERVAL = 10 * 1000;

/**
 * Reads a fallback poll interval: a duration ("10m", "30s") or a bare number of milliseconds.
 * Blank and anything unreadable get the default
 * @param {*} value - The raw environment value
 * @param {Object} opts
 * @param {boolean} opts.allowOff - Whether 0 switches the poller off; otherwise 0 gets the default
 * @param {number} [opts.min] - Shortest interval a positive value is raised to
 * @returns {number} Milliseconds, 0 when the poller is off
 */
function parsePollInterval(value, { allowOff, min = 0 }) {
    // blank is "unset", which getDuration() would read as 0
    const raw = String(value ?? '').trim();
    const duration = raw ? getDuration(raw) : DEFAULT_FALLBACK_POLL_INTERVAL;
    if (typeof duration !== 'number' || !Number.isFinite(duration) || duration < 0 || (duration === 0 && !allowOff)) {
        return DEFAULT_FALLBACK_POLL_INTERVAL;
    }
    return duration && Math.max(duration, min);
}

/**
 * EENGINE_GMAIL_FALLBACK_POLL_INTERVAL: how often a Gmail API account polls for changes when no
 * Pub/Sub notification arrives. A bare number of milliseconds was the only form it used to accept,
 * and the integration tier still sets one; a "10m" fell through to the default without a word. This
 * poller can not be switched off, so 0 gets the default
 * @param {*} value - The raw environment value
 * @returns {number} Milliseconds
 */
function parseGmailFallbackPollInterval(value) {
    return parsePollInterval(value, { allowOff: false });
}

/**
 * EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL: 0 switches the periodic pass off, and a positive value is
 * never shorter than ten seconds, so a typo can not point every account at Graph in a loop
 * @param {*} value - The raw environment value
 * @returns {number} Milliseconds, 0 when the pass is off
 */
function parseFallbackPollInterval(value) {
    return parsePollInterval(value, { allowOff: true, min: MIN_FALLBACK_POLL_INTERVAL });
}

const GMAIL_FALLBACK_POLL_INTERVAL = parseGmailFallbackPollInterval(readEnvValue('EENGINE_GMAIL_FALLBACK_POLL_INTERVAL'));

// The interval of the periodic missed-notification recovery pass (OutlookClient.setupFallbackPollTimer()).
// Its own module so the admin UI, which runs in the API worker, reads the same value the account
// workers run with
const OUTLOOK_FALLBACK_POLL_INTERVAL = parseFallbackPollInterval(readEnvValue('EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL'));

module.exports = {
    parseGmailFallbackPollInterval,
    parseFallbackPollInterval,
    GMAIL_FALLBACK_POLL_INTERVAL,
    OUTLOOK_FALLBACK_POLL_INTERVAL,
    DEFAULT_FALLBACK_POLL_INTERVAL
};
