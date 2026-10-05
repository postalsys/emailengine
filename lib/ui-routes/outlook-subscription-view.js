'use strict';

const { FALLBACK_POLL_INTERVAL } = require('../email-client/outlook-fallback-poll');

/**
 * Adds the fields the account page renders for a Graph change subscription, in place
 * @param {Object} subscription - The account's stored `outlookSubscription`
 * @param {string} accountState - The account's connection state
 * @returns {Object} The same subscription object
 */
function formatOutlookSubscription(subscription, accountState) {
    const state = subscription.state || {};
    const expires = subscription.expirationDateTime;

    subscription.subscriptionExpiresStr = expires ? expires.toISOString() : false;
    subscription.isValid = state.state !== 'error' && expires && expires > new Date();

    subscription.stateLabel = (state.state || '').replace(/^./, c => c.toUpperCase());
    if ((state.state === 'created' && !expires) || expires < new Date()) {
        subscription.stateLabel = 'Expired';
    }

    // See OutlookClient.reportSubscriptionFailure()
    subscription.polling = state.state === 'error' && accountState === 'connected' && !!FALLBACK_POLL_INTERVAL;

    // One severity for the badge and the alert: a failure the poller stands in for is a warning
    if (subscription.isValid) {
        subscription.variant = 'success';
    } else {
        subscription.variant = state.state === 'error' && !subscription.polling ? 'error' : 'warning';
    }

    return subscription;
}

module.exports = { formatOutlookSubscription };
