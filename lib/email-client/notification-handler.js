'use strict';

const { parentPort } = require('worker_threads');
const logger = require('../logger');
const { webhooks: Webhooks } = require('../webhooks');
const { getESClient } = require('../document-store');
const { getThread } = require('../threads');
const settings = require('../settings');

// Import notification-related constants
const { MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY } = require('../consts');

/**
 * Events that should sync with the document store (ElasticSearch)
 */
const DOCUMENT_SYNC_EVENTS = [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY];

/**
 * Default job options for notification queue
 */
const DEFAULT_JOB_OPTIONS = {
    removeOnComplete: true,
    removeOnFail: true,
    attempts: 10,
    backoff: {
        type: 'exponential',
        delay: 5000
    }
};

/**
 * Job options for document store updates (more retry attempts)
 */
const DOCUMENT_JOB_OPTIONS = Object.assign({}, DEFAULT_JOB_OPTIONS, { attempts: 16 });

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
 * Manages webhook delivery, document store sync, and queue processing
 */
class NotificationHandler {
    /**
     * Creates a new NotificationHandler
     * @param {Object} options - Handler options
     * @param {string} options.account - Account identifier
     * @param {Object} options.logger - Logger instance
     * @param {Object} options.flowProducer - BullMQ flow producer for queue jobs
     * @param {Object} options.documentsQueue - Queue for document store updates
     */
    constructor(options) {
        this.account = options.account;
        this.logger = options.logger;
        this.flowProducer = options.flowProducer;
        this.documentsQueue = options.documentsQueue;
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

        if (mailbox && mailbox.listingEntry && mailbox.listingEntry.specialUse) {
            payload.specialUse = mailbox.listingEntry.specialUse;
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
     * Determines if an event should sync with the document store
     * @param {string} event - Event type
     * @param {boolean} canSync - Whether sync is allowed
     * @returns {Promise<boolean>} Whether to add document queue job
     */
    async shouldSyncDocuments(event, canSync) {
        if (!canSync || !this.documentsQueue) {
            return false;
        }

        if (!DOCUMENT_SYNC_EVENTS.includes(event)) {
            return false;
        }

        return await settings.get('documentStoreEnabled');
    }

    /**
     * Generates a thread ID for new messages using ElasticSearch
     * @param {Object} payload - Notification payload with message data
     * @returns {Promise<void>}
     */
    async generateThreadId(payload) {
        if (!payload.data || payload.data.threadId) {
            return;
        }

        const { index, client } = await getESClient(logger);
        if (!client) {
            return;
        }

        try {
            const thread = await getThread(client, index, this.account, payload.data, logger);
            if (thread) {
                payload.data.threadId = thread;
                this.logger.info({
                    msg: 'Provisioned thread ID for a message',
                    account: this.account,
                    message: payload.data.id,
                    threadId: payload.data.threadId
                });
            }
        } catch (err) {
            if (this.logger.notifyError) {
                this.logger.notifyError(err, event => {
                    event.setUser(this.account);
                    event.addMetadata('ee', { index });
                });
            }
            this.logger.error({
                msg: 'Failed to resolve thread',
                account: this.account,
                message: payload.data.id,
                err
            });
        }
    }

    /**
     * Processes notification with both webhook and document store sync
     * Uses BullMQ flow to ensure proper ordering
     * @param {string} event - Event type
     * @param {Object} payload - Notification payload
     * @param {boolean} queueKeep - Whether to keep completed jobs
     */
    async processWithFlow(event, payload, queueKeep) {
        const notifyPayload = await Webhooks.formatPayload(event, payload);

        const queueFlow = [
            {
                name: event,
                data: payload,
                queueName: 'documents'
            }
        ];

        await Webhooks.pushToQueue(event, notifyPayload, {
            routesOnly: true,
            queueFlow
        });

        const jobOptions = this.buildJobOptions(queueKeep);

        await this.flowProducer.add(
            {
                name: event,
                data: notifyPayload,
                queueName: 'notify',
                children: queueFlow
            },
            {
                queuesOptions: {
                    notify: {
                        defaultJobOptions: jobOptions.notify
                    },
                    documents: {
                        defaultJobOptions: jobOptions.documents
                    }
                }
            }
        );
    }

    /**
     * Processes notification with webhook only (no document sync)
     * @param {string} event - Event type
     * @param {Object} payload - Notification payload
     */
    async processWebhookOnly(event, payload) {
        const notifyPayload = await Webhooks.formatPayload(event, payload);
        await Webhooks.pushToQueue(event, notifyPayload);
    }

    /**
     * Processes notification with document store sync only (no webhook)
     * @param {string} event - Event type
     * @param {Object} payload - Notification payload
     */
    async processDocumentOnly(event, payload) {
        await this.documentsQueue.add(event, payload, DOCUMENT_JOB_OPTIONS);
    }

    /**
     * Builds job options based on queue keep setting
     * @param {boolean} queueKeep - Whether to keep completed/failed jobs
     * @returns {Object} Job options for notify and documents queues
     */
    buildJobOptions(queueKeep) {
        const notifyOptions = Object.assign({}, DEFAULT_JOB_OPTIONS, {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep
        });

        const documentOptions = Object.assign({}, DOCUMENT_JOB_OPTIONS, {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep
        });

        return {
            notify: notifyOptions,
            documents: documentOptions
        };
    }

    /**
     * Sends a notification for an email event
     * Handles webhook delivery, document store sync, and metrics tracking
     * @param {Object} mailbox - Mailbox information
     * @param {string} event - Event type constant
     * @param {Object} data - Event data payload
     * @param {Object} extraOpts - Additional options
     * @param {boolean} extraOpts.skipWebhook - Skip webhook delivery
     * @param {boolean} extraOpts.canSync - Allow document store sync (default: true)
     * @returns {Promise<void>}
     */
    async notify(mailbox, event, data, extraOpts) {
        extraOpts = extraOpts || {};
        const { skipWebhook, canSync = true } = extraOpts;

        // Track event metrics
        postMetrics({ account: this.account }, this.logger, 'events', 'inc', { event });

        // Get service URL for notification payload
        const serviceUrl = (await settings.get('serviceUrl')) || null;

        // Build notification payload
        const payload = this.buildPayload(mailbox, event, data, serviceUrl);

        // Determine if we need to sync with document store
        const addDocumentQueueJob = await this.shouldSyncDocuments(event, canSync);

        // Generate thread ID for new messages if needed
        if (addDocumentQueueJob && event === MESSAGE_NEW_NOTIFY) {
            await this.generateThreadId(payload);
        }

        // Get queue retention setting
        const queueKeep = (await settings.get('queueKeep')) || true;

        // Process notification based on required destinations
        if (!skipWebhook && addDocumentQueueJob) {
            // Add both webhook and document jobs as a flow
            await this.processWithFlow(event, payload, queueKeep);
        } else if (!skipWebhook) {
            // Webhook only
            await this.processWebhookOnly(event, payload);
        } else if (addDocumentQueueJob) {
            // Document store only
            await this.processDocumentOnly(event, payload);
        }
    }
}

module.exports = {
    NotificationHandler,
    DOCUMENT_SYNC_EVENTS,
    DEFAULT_JOB_OPTIONS,
    DOCUMENT_JOB_OPTIONS,
    postMetrics
};
