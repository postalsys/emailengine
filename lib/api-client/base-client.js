'use strict';

const { parentPort } = require('worker_threads');
const crypto = require('crypto');
const logger = require('../logger');
const { webhooks: Webhooks } = require('../webhooks');
const { getESClient } = require('../document-store');
const { getThread } = require('../threads');
const settings = require('../settings');

const {
    ACCOUNT_INITIALIZED_NOTIFY,
    REDIS_PREFIX,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,

    MAILBOX_DELETED_NOTIFY
} = require('../consts');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

async function metricsMeta(meta, logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args,
            meta: meta || {}
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

class BaseClient {
    constructor(account, options) {
        this.account = account;

        this.options = options || {};

        this.cid = this.getRandomId();

        this.runIndex = this.options.runIndex;

        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;
        this.redis = this.options.redis;

        this.call = this.options.call;
        this.logger = this.options.logger || logger;

        this.secret = this.options.secret;

        this.subconnections = [];
    }

    // stub methods

    async init() {
        return null;
    }

    async delete() {
        return null;
    }

    async resume() {
        return null;
    }

    async reconnect() {
        return null;
    }

    async subconnections() {
        return [];
    }

    async getQuota() {
        return false;
    }

    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substring(0, 20);
        }
        return rid;
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    currentState() {
        return 'connected';
    }

    async setStateVal() {
        let [[e1], [e2], [e3, prevVal], [e4, incrVal], [e5, stateVal]] = await this.redis
            .multi()
            .hSetExists(this.getAccountKey(), 'state', this.state)
            .hSetBigger(this.getAccountKey(), 'runIndex', this.runIndex.toString())
            .hget(this.getAccountKey(), `state:count:${this.state}`)
            .hIncrbyExists(this.getAccountKey(), `state:count:${this.state}`, 1)
            .hget(this.getAccountKey(), 'state')
            .exec();

        if (e1 || e2 || e3 || e4 || e5) {
            throw e1 || e2 || e3 || e4 || e5;
        }

        if (stateVal === 'connected' && incrVal === 1 && prevVal === '0') {
            // first connected event!
            await this.notify(false, ACCOUNT_INITIALIZED_NOTIFY, {
                initialized: true
            });
        }
    }

    async notify(mailbox, event, data, extraOpts) {
        extraOpts = extraOpts || {};
        const { skipWebhook, canSync = true } = extraOpts;

        metricsMeta({ account: this.account }, this.logger, 'events', 'inc', {
            event
        });

        switch (event) {
            case 'connectError':
            case 'authenticationError': {
                let shouldNotify = await this.setErrorState(event, data);

                if (!shouldNotify) {
                    // do not send a webhook as nothing really changed
                    return;
                }
                break;
            }
        }

        let serviceUrl = (await settings.get('serviceUrl')) || true;

        let payload = {
            serviceUrl,
            account: this.account,
            date: new Date().toISOString()
        };

        let path = (mailbox && mailbox.path) || (data && data.path);
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

        let queueKeep = (await settings.get('queueKeep')) || true;

        let addDocumentQueueJob =
            canSync &&
            this.documentsQueue &&
            [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY].includes(event) &&
            (await settings.get('documentStoreEnabled'));

        if (addDocumentQueueJob && payload.data && event === MESSAGE_NEW_NOTIFY && !payload.data.threadId) {
            // Generate a thread ID for the email. This is also stored in ElasticSearch.
            const { index, client } = await getESClient(logger);
            try {
                if (client) {
                    let thread = await getThread(client, index, this.account, payload.data, logger);
                    if (thread) {
                        payload.data.threadId = thread;
                        logger.info({
                            msg: 'Provisioned thread ID for a message',
                            account: this.account,
                            message: payload.data.id,
                            threadId: payload.data.threadId
                        });
                    }
                }
            } catch (err) {
                if (logger.notifyError) {
                    logger.notifyError(err, event => {
                        event.setUser(this.account);
                        event.addMetadata('ee', {
                            index
                        });
                    });
                }
                logger.error({ msg: 'Failed to resolve thread', account: this.account, message: payload.data.id, err });
            }
        }

        const defaultJobOptions = {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: 10,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        // use more attempts for ElasticSearch updates
        const documentJobOptions = Object.assign(pfStructuredClone(defaultJobOptions), { attempts: 16 });

        if (!skipWebhook && addDocumentQueueJob) {
            // add both jobs as a Flow

            let notifyPayload = await Webhooks.formatPayload(event, payload);

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
                            defaultJobOptions
                        },
                        documents: {
                            defaultJobOptions: documentJobOptions
                        }
                    }
                }
            );
        } else {
            // add to queues as normal jobs

            if (!skipWebhook) {
                await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
            }

            if (addDocumentQueueJob) {
                await this.documentsQueue.add(event, payload, documentJobOptions);
            }
        }
    }
}

module.exports = { BaseClient };
