'use strict';

// What a stored MS Graph change subscription needs, by how long it has left. Kept pure so
// test/outlook-subscription-expiry-test.js can pin the boundaries without a client.

const { OUTLOOK_CLOCK_SKEW_BUFFER, OUTLOOK_EXPIRATION_RENEW_TIME } = require('../../consts');

/**
 * Classifies a stored subscription by its expiry.
 *
 * @param {Date|null} expirationDate - the parsed expiry, null when absent or unparseable
 * @param {number} now - current time in ms
 * @returns {'expired'|'renew'|'valid'} `expired` once inside the clock-skew buffer (Graph may
 *   already consider it gone), `renew` inside the renewal window, `valid` otherwise. An expiry
 *   that could not be parsed counts as valid: nothing says it needs anything.
 */
function classifyExistingSubscription(expirationDate, now) {
    if (!expirationDate) {
        return 'valid';
    }
    if (expirationDate.getTime() < now + OUTLOOK_CLOCK_SKEW_BUFFER) {
        return 'expired';
    }
    if (expirationDate.getTime() < now + OUTLOOK_EXPIRATION_RENEW_TIME) {
        return 'renew';
    }
    return 'valid';
}

module.exports = { classifyExistingSubscription };
