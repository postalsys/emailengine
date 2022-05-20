'use strict';

const { parentPort } = require('worker_threads');
const { queueConf } = require('../lib/db');
const { Worker } = require('bullmq');
const logger = require('../lib/logger');
const settings = require('../lib/settings');
const packageData = require('../package.json');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');

const { MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY } = require('../lib/consts');

async function metrics(logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

const clientCache = { version: -1, config: false, client: false, index: false };

const getClient = async () => {
    const documentStoreVersion = (await settings.get('documentStoreVersion')) || 0;
    if (clientCache.version === documentStoreVersion) {
        return clientCache;
    }

    let documentStoreEnabled = await settings.get('documentStoreEnabled');
    let documentStoreUrl = await settings.get('documentStoreUrl');

    if (!documentStoreEnabled || !documentStoreUrl) {
        clientCache.version = documentStoreVersion;
        clientCache.client = false;
        clientCache.index = false;
        return clientCache;
    }

    clientCache.index = (await settings.get('documentStoreIndex')) || 'emailengine';

    let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
    let documentStoreUsername = await settings.get('documentStoreUsername');
    let documentStorePassword = await settings.get('documentStorePassword');

    clientCache.config = {
        node: { url: new URL(documentStoreUrl), tls: { rejectUnauthorized: false } },
        auth:
            documentStoreAuthEnabled && documentStoreUsername
                ? {
                      username: documentStoreUsername,
                      password: documentStorePassword
                  }
                : false
    };

    clientCache.version = documentStoreVersion;
    clientCache.client = new ElasticSearch(clientCache.config);

    return clientCache;
};

const documentsWorker = new Worker(
    'documents',
    async job => {
        switch (job.data.event) {
            case MESSAGE_NEW_NOTIFY:
                {
                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    delete messageData.id;
                    messageData.account = job.data.account;
                    messageData.created = job.data.date;

                    const { index, client } = await getClient();
                    if (!client) {
                        return;
                    }

                    let indexResult;
                    try {
                        indexResult = await client.index({
                            index,
                            id: `${job.data.account}:${messageId}`,
                            document: messageData
                        });
                    } catch (err) {
                        logger.error({
                            msg: 'Failed to index new email',
                            action: 'document',
                            queue: job.queue.name,
                            code: 'document_index_error',
                            job: job.id,
                            event: job.name,
                            account: job.data.account,
                            request: { index, id: `${job.data.account}:${messageId}`, document: messageData },
                            err
                        });
                        throw err;
                    }

                    logger.trace({
                        msg: 'Stored new email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_index',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        indexResult
                    });
                }
                break;

            case MESSAGE_DELETED_NOTIFY:
                {
                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    delete messageData.id;
                    messageData.account = job.data.account;
                    messageData.created = job.data.date;

                    const { index, client } = await getClient();
                    if (!client) {
                        return;
                    }

                    let deleteResult;
                    try {
                        deleteResult = await client.delete({
                            index,
                            id: `${job.data.account}:${messageId}`
                        });
                    } catch (err) {
                        switch (err.meta && err.meta.body && err.meta.body.result) {
                            case 'not_found':
                                // ignore error
                                deleteResult = Object.assign({ failed: true }, err.meta.body);
                                break;
                            default:
                                logger.error({
                                    msg: 'Failed to delete email',
                                    action: 'document',
                                    queue: job.queue.name,
                                    code: 'document_delete_error',
                                    job: job.id,
                                    event: job.name,
                                    account: job.data.account,
                                    request: {
                                        index,
                                        id: `${job.data.account}:${messageId}`
                                    },
                                    err
                                });
                                throw err;
                        }
                    }

                    logger.trace({
                        msg: 'Deleted email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_delete',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        request: {
                            index,
                            id: `${job.data.account}:${messageId}`
                        },
                        deleteResult
                    });
                }
                break;

            case MESSAGE_UPDATED_NOTIFY:
                {
                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    const { index, client } = await getClient();
                    if (!client) {
                        return;
                    }

                    let updates = {};
                    if (messageData.changes && messageData.changes.flags && messageData.changes.flags.value) {
                        updates.flags = messageData.changes.flags.value;
                    }
                    if (messageData.changes && messageData.changes.labels && messageData.changes.labels.value) {
                        updates.labels = messageData.changes.labels.value;
                    }

                    let updateResult;

                    if (Object.keys(updates).length) {
                        try {
                            updateResult = await client.update({
                                index,
                                id: `${job.data.account}:${messageId}`,
                                doc: updates
                            });
                        } catch (err) {
                            switch (err.meta && err.meta.body && err.meta.body.error && err.meta.body.error.type) {
                                case 'document_missing_exception':
                                    // ignore error
                                    updateResult = Object.assign({ failed: true }, err.meta.body);
                                    break;
                                default:
                                    logger.error({
                                        msg: 'Failed to update email',
                                        action: 'document',
                                        queue: job.queue.name,
                                        code: 'document_update_error',
                                        job: job.id,
                                        event: job.name,
                                        account: job.data.account,
                                        request: {
                                            index,
                                            id: `${job.data.account}:${messageId}`,
                                            doc: updates
                                        },
                                        err
                                    });
                                    throw err;
                            }
                        }
                    } else {
                        updateResult = { failed: true, result: 'no_changes' };
                    }

                    logger.trace({
                        msg: 'Updated email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_delete',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        request: {
                            index,
                            id: `${job.data.account}:${messageId}`,
                            doc: updates
                        },
                        updateResult
                    });
                }
                break;
        }
    },
    Object.assign(
        {
            concurrency: 1,
            limiter: {
                max: 10,
                duration: 1000,
                groupKey: 'account'
            }
        },
        queueConf
    )
);

documentsWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'documents',
        status: 'completed'
    });

    logger.info({
        msg: 'Document queue entry completed',
        action: 'document',
        queue: job.queue.name,
        code: 'completed',
        job: job.id,
        account: job.data.account
    });
});

documentsWorker.on('failed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'document',
        status: 'failed'
    });

    logger.info({
        msg: 'Document queue entry failed',
        action: 'document',
        queue: job.queue.name,
        code: 'failed',
        job: job.id,
        account: job.data.account
    });
});

logger.info({ msg: 'Started Documents worker thread', version: packageData.version });
