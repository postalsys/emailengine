'use strict';

const { constantTimeEqual } = require('./tools');

// The two MS Graph subscription routes are unauthenticated and deliberately carry no payload
// schema: they must answer 202 to anything, because a 400 would make Graph tear the subscription
// down, and the validation handshake posts an empty body. So the payload is arbitrary JSON and
// every read of it has to be defensive.
const graphNotificationEntries = payload => (Array.isArray(payload && payload.value) ? payload.value.filter(entry => entry && typeof entry === 'object') : []);

// How many entries of an unverified Graph notification body are named in its log record
const MAX_LOGGED_GRAPH_ENTRIES = 5;

// One record per request for the entries that failed validation, rather than one per entry. The
// endpoint is unauthenticated and a body of up to 1 MB can hold thousands of empty entries, and each
// record carries the request's own fields, so one request used to write hundreds of megabytes of log.
function logRejectedGraphEntries(request, rejected, fields) {
    if (!rejected.length) {
        return;
    }
    request.logger.warn(
        Object.assign({ account: request.query.account, rejected: rejected.length, sample: rejected.slice(0, MAX_LOGGED_GRAPH_ENTRIES) }, fields)
    );
}

/**
 * Splits the entries of a notification body into the ones that belong to the account's
 * subscription (its id and its client state both match) and the ones that do not.
 *
 * @param {Object[]} entries - graphNotificationEntries() result
 * @param {Object} subscription - The account's stored subscription (`id`, `clientState`)
 * @param {Function} describe - (entry) => extra fields to log for a rejected entry
 * @returns {{ valid: Object[], rejected: Object[] }}
 */
function partitionGraphEntries(entries, subscription, describe) {
    const valid = [];
    const rejected = [];
    for (const entry of entries) {
        const subscriptionIdMatch = entry.subscriptionId === subscription.id;
        const clientStateMatch = constantTimeEqual(entry.clientState, subscription.clientState);
        if (subscriptionIdMatch && clientStateMatch) {
            valid.push(entry);
        } else {
            rejected.push(Object.assign({ subscriptionIdMatch, clientStateMatch, receivedSubscriptionId: entry.subscriptionId }, describe(entry)));
        }
    }
    return { valid, rejected };
}

// A notification for an account that has no subscription stored: one record naming a few entries
function logUnknownGraphSubscription(request, entries) {
    request.logger.warn({
        msg: 'Subscription not found for account',
        account: request.query.account,
        entries: entries.length,
        subscriptionIds: entries.slice(0, MAX_LOGGED_GRAPH_ENTRIES).map(entry => entry.subscriptionId)
    });
}

module.exports = { graphNotificationEntries, partitionGraphEntries, logRejectedGraphEntries, logUnknownGraphSubscription, MAX_LOGGED_GRAPH_ENTRIES };
