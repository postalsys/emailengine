'use strict';

const { parentPort } = require('worker_threads');
const { webhooks: Webhooks } = require('../webhooks');
const settings = require('../settings');

/**
 * Sends metrics data to the parent thread for aggregation
 * @param {Object} meta - Metadata to include with the metric
 * @param {Object} loggerInstance - Logger instance
 * @param {string} key - Metric key identifier
 * @param {string} method - Metric method (e.g., 'inc', 'dec')
 * @param {...any} args - Additional arguments for the metric
 */
function postMetrics(meta, loggerInstance, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args,
            meta: meta || {}
        });
    } catch (err) {
        loggerInstance.error({ msg: 'Failed to post metrics to parent', err });
    }
}

/**
 * Handles notification delivery for email events
 * Manages webhook delivery and event metrics
 */
class NotificationHandler {
    /**
     * Creates a new NotificationHandler
     * @param {Object} options - Handler options
     * @param {string} options.account - Account identifier
     * @param {Object} options.logger - Logger instance
     */
    constructor(options) {
        this.account = options.account;
        this.logger = options.logger;
    }

    /**
     * Builds the base notification payload
     * @param {Object} mailbox - Mailbox information
     * @param {string} event - Event type constant
     * @param {Object} data - Event data
     * @param {string} serviceUrl - Service URL for callbacks
     * @returns {Object} Base notification payload
     */
    buildPayload(mailbox, event, data, serviceUrl) {
        const payload = {
            serviceUrl,
            account: this.account,
            date: new Date().toISOString()
        };

        const path = (mailbox && mailbox.path) || (data && data.path);
        if (path) {
            payload.path = path;
        }

        // An IMAP Mailbox carries its listing entry, the API clients pass a plain { path, specialUse }
        const specialUse = mailbox && ((mailbox.listingEntry && mailbox.listingEntry.specialUse) || mailbox.specialUse);
        if (specialUse) {
            payload.specialUse = specialUse;
        }

        if (event) {
            payload.event = event;
        }

        if (data) {
            payload.data = data;
        }

        return payload;
    }

    /**
     * Sends a notification for an email event
     * Handles webhook delivery and metrics tracking
     * @param {Object} mailbox - Mailbox information
     * @param {string} event - Event type constant
     * @param {Object} data - Event data payload
     * @returns {Promise<void>}
     */
    async notify(mailbox, event, data) {
        // Track event metrics
        postMetrics({ account: this.account }, this.logger, 'events', 'inc', { event });

        // Get service URL for notification payload
        const serviceUrl = (await settings.get('serviceUrl')) || null;

        // Build notification payload
        const payload = this.buildPayload(mailbox, event, data, serviceUrl);

        const notifyPayload = await Webhooks.formatPayload(event, payload);
        await Webhooks.pushToQueue(event, notifyPayload);
    }
}

module.exports = {
    NotificationHandler,
    postMetrics
};
