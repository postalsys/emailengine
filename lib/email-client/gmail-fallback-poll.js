'use strict';

const { readEnvValue, getDuration } = require('../tools');

const DEFAULT_FALLBACK_POLL_INTERVAL = 10 * 60 * 1000;

/**
 * Reads EENGINE_GMAIL_FALLBACK_POLL_INTERVAL: how often a Gmail API account polls for changes when
 * no Pub/Sub notification arrives. A duration ("10m", "30s") like its Outlook counterpart, or a bare
 * number of milliseconds, the only form it used to accept and the one the integration tier still
 * sets. Unlike the Outlook pass this poller cannot be switched off, so 0, blank and anything
 * unreadable all get the default. A "10m" used to fall through to the default without a word.
 * @param {*} value - The raw environment value
 * @returns {number} Milliseconds
 */
function parseGmailFallbackPollInterval(value) {
    const raw = String(value ?? '').trim();
    if (!raw) {
        return DEFAULT_FALLBACK_POLL_INTERVAL;
    }
    const duration = getDuration(raw);
    if (typeof duration !== 'number' || !Number.isFinite(duration) || duration <= 0) {
        return DEFAULT_FALLBACK_POLL_INTERVAL;
    }
    return duration;
}

const FALLBACK_POLLING_INTERVAL = parseGmailFallbackPollInterval(readEnvValue('EENGINE_GMAIL_FALLBACK_POLL_INTERVAL'));

module.exports = { parseGmailFallbackPollInterval, FALLBACK_POLLING_INTERVAL, DEFAULT_FALLBACK_POLL_INTERVAL };
