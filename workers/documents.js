'use strict';

const { parentPort } = require('worker_threads');
const { queueConf } = require('../lib/db');
const { Worker } = require('bullmq');
const logger = require('../lib/logger');
const settings = require('../lib/settings');
const packageData = require('../package.json');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
const { ensureIndex } = require('../lib/es');
const { getThread } = require('../lib/threads');

const { MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, ACCOUNT_DELETED } = require('../lib/consts');

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

    // ensure proper index settings
    let indexResult = await ensureIndex(clientCache.client, clientCache.index);
    if (!indexResult || indexResult.exists) {
        logger.info({ msg: 'Updated document index', index: clientCache.index, result: indexResult });
    }

    return clientCache;
};

const documentsWorker = new Worker(
    'documents',
    async job => {
        switch (job.data.event) {
            case ACCOUNT_DELETED:
                {
                    const { index, client } = await getClient();
                    if (!client) {
                        return;
                    }

                    let deleteResult = {};

                    for (let indexName of [index]) {
                        try {
                            deleteResult[indexName] = await client.deleteByQuery({
                                index: indexName,
                                query: {
                                    match: {
                                        account: job.data.account
                                    }
                                }
                            });
                        } catch (err) {
                            logger.error({
                                msg: 'Failed to delete account data',
                                action: 'document',
                                queue: job.queue.name,
                                code: 'document_delete_account_error',
                                job: job.id,
                                event: job.name,
                                account: job.data.account,
                                request: {
                                    index: indexName,
                                    query: {
                                        match: {
                                            account: job.data.account
                                        }
                                    }
                                },
                                err
                            });
                            throw err;
                        }
                    }

                    logger.trace({
                        msg: 'Deleted account data',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_delete_account',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        deleteResult
                    });
                }
                break;

            case MESSAGE_NEW_NOTIFY:
                {
                    const { index, client } = await getClient();
                    if (!client) {
                        return;
                    }

                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    let baseObject = {
                        account: job.data.account,
                        created: job.data.date,
                        path: job.data.path
                    };

                    // set thread id
                    try {
                        let thread = await getThread(client, index, job.data.account, messageData, logger);
                        if (thread) {
                            messageData.threadId = thread;
                        }
                    } catch (err) {
                        logger.error({ msg: 'Failed to resolve thread', err });
                    }

                    if (job.data.specialUse) {
                        baseObject.specialUse = job.data.specialUse;
                    }

                    messageData = Object.assign(baseObject, messageData);
                    if (messageData.headers) {
                        messageData.headers = Object.keys(messageData.headers).map(key => ({ key, value: [].concat(messageData.headers[key] || []) }));
                    }

                    messageData.unseen = messageData.flags && !messageData.flags.includes('\\Seen') ? true : false;
                    messageData.flagged = messageData.flags && messageData.flags.includes('\\Flagged') ? true : false;
                    messageData.answered = messageData.flags && messageData.flags.includes('\\Answered') ? true : false;
                    messageData.draft = messageData.flags && messageData.flags.includes('\\Draft') ? true : false;

                    let textContent = {};
                    for (let subType of ['id', 'plain', 'html', 'encodedSize']) {
                        if (messageData.text && messageData.text[subType]) {
                            textContent[subType] = messageData.text[subType];
                        }
                    }
                    messageData.text = textContent;

                    if (messageData.attachments) {
                        for (let attachment of messageData.attachments) {
                            if ('filename' in attachment && !attachment.filename) {
                                // remove falys filenames, otherwise these will be casted into strings
                                delete attachment.filename;
                            }
                        }
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

                        updates.unseen = updates.flags && !updates.flags.includes('\\Seen') ? true : false;
                        updates.flagged = updates.flags && updates.flags.includes('\\Flagged') ? true : false;
                        updates.answered = updates.flags && updates.flags.includes('\\Answered') ? true : false;
                        updates.draft = updates.flags && updates.flags.includes('\\Draft') ? true : false;
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
