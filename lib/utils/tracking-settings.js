'use strict';

// Which kinds of tracking a sent message gets. The message's own flags win, the instance
// settings fill in what it leaves open, and open and click tracking follow trackSentMessages
// unless set on their own.

const TRACKING_SETTINGS = ['trackSentMessages', 'trackClicks', 'trackOpens'];

const isBoolean = value => typeof value === 'boolean';

/**
 * Whether the message leaves anything to the instance settings, so the caller can skip the read
 * @param {Object} message - trackingEnabled, trackClicks, trackOpens as the message set them
 * @returns {boolean}
 */
function needsTrackingSettings(message) {
    return !isBoolean(message.trackingEnabled) || !isBoolean(message.trackClicks) || !isBoolean(message.trackOpens);
}

/**
 * @param {Object} message - trackingEnabled, trackClicks, trackOpens as the message set them
 * @param {Object} [stored] - The TRACKING_SETTINGS values; needed only when needsTrackingSettings()
 * @returns {{trackingEnabled: *, trackClicks: boolean, trackOpens: boolean}}
 */
function resolveTracking(message, stored = {}) {
    const trackingEnabled = isBoolean(message.trackingEnabled) ? message.trackingEnabled : stored.trackSentMessages || false;
    const pick = (own, setting) => [own, setting].find(isBoolean) ?? trackingEnabled;
    return {
        trackingEnabled,
        trackClicks: pick(message.trackClicks, stored.trackClicks),
        trackOpens: pick(message.trackOpens, stored.trackOpens)
    };
}

module.exports = { TRACKING_SETTINGS, needsTrackingSettings, resolveTracking };
