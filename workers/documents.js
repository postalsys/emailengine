'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const logger = require('../lib/logger');
const { preProcess } = require('../lib/pre-process');

const { readEnvValue, threadStats } = require('../lib/tools');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'documents', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'documents', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'documents', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'documents', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const { redis, queueConf } = require('../lib/db');
const { Worker } = require('bullmq');
const { getESClient } = require('../lib/document-store');
const { getThread } = require('../lib/threads');
const { generateTextPreview } = require('../lib/generate-text-preview');

const {
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    ACCOUNT_DELETED,
    EMAIL_BOUNCE_NOTIFY,
    MAILBOX_DELETED_NOTIFY,
    REDIS_PREFIX
} = require('../lib/consts');

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

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
        default:
            logger.debug({ msg: 'Unhandled command', command });
            return 999;
    }
}

parentPort.on('message', message => {
    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

const documentsWorker = new Worker(
    'documents',
    async job => {
        const dateKeyTdy = new Date().toISOString().substring(0, 10).replace(/-/g, '');
        const dateKeyYdy = new Date(Date.now() - 24 * 3600 * 1000).toISOString().substring(0, 10).replace(/-/g, '');
        const tombstoneTdy = `${REDIS_PREFIX}tomb:${job.data.account}:${dateKeyTdy}`;
        const tombstoneYdy = `${REDIS_PREFIX}tomb:${job.data.account}:${dateKeyYdy}`;

        switch (job.data.event) {
            case ACCOUNT_DELETED:
                {
                    const { index, client } = await getESClient(logger);
                    if (!client) {
                        return;
                    }

                    let deleteResult = {};
                    let deletedCount = 0;

                    let filterQuery = {
                        match: {
                            account: job.data.account
                        }
                    };

                    for (let indexName of [index, `${index}.threads`]) {
                        try {
                            deleteResult[indexName] = await client.deleteByQuery({
                                index: indexName,
                                query: filterQuery
                            });
                            deletedCount += deleteResult[indexName].deleted || 0;
                        } catch (err) {
                            logger.error({
                                msg: 'Failed to delete account emails from index',
                                action: 'document',
                                queue: job.queue.name,
                                code: 'document_delete_account_error',
                                job: job.id,
                                event: job.name,
                                account: job.data.account,
                                index: indexName,
                                request: filterQuery,
                                err
                            });
                            if (indexName === index) {
                                throw err;
                            }
                        }
                    }

                    logger.trace({
                        msg: 'Deleted account emails from index',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_delete_account',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        deletedCount,
                        deleteResult
                    });
                }
                break;

            case MAILBOX_DELETED_NOTIFY:
                {
                    const { index: indexName, client } = await getESClient(logger);
                    if (!client) {
                        return;
                    }

                    let deleteResult = null;

                    let filterQuery = {
                        bool: {
                            must: [
                                {
                                    term: {
                                        account: job.data.account
                                    }
                                },

                                {
                                    term: {
                                        path: job.data.path
                                    }
                                }
                            ]
                        }
                    };

                    try {
                        deleteResult = await client.deleteByQuery({
                            index: indexName,
                            query: filterQuery
                        });
                    } catch (err) {
                        logger.error({
                            msg: 'Failed to delete messages from a mailbox',
                            action: 'document',
                            queue: job.queue.name,
                            code: 'document_delete_mailbox_error',
                            job: job.id,
                            event: job.name,
                            account: job.data.account,
                            path: job.data.path,
                            index: indexName,
                            request: filterQuery,
                            err
                        });
                        throw err;
                    }

                    logger.trace({
                        msg: 'Deleted mailbox messages',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_delete_mailbox',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        path: job.data.path,
                        index: indexName,
                        deletedCount: (deleteResult && deleteResult.deleted) || 0,
                        deleteResult
                    });
                }
                break;

            // returns indexing response for the parent job
            case MESSAGE_NEW_NOTIFY: {
                let accountExists = await redis.exists(`${REDIS_PREFIX}iad:${job.data.account}`);
                if (!accountExists) {
                    // deleted account?
                    return false;
                }

                let messageData = job.data.data;
                let messageId = messageData.id;

                // check tombstone for race conditions (might be already deleted)
                let [[err1, isDeleted1], [err2, isDeleted2]] = await redis
                    .multi()
                    .sismember(tombstoneTdy, `${messageId}`)
                    .sismember(tombstoneYdy, `${messageId}`)
                    .exec();

                if (err1) {
                    logger.trace({ msg: 'Failed checking tombstone', key: tombstoneTdy, err: err1 });
                }

                if (err2) {
                    logger.trace({ msg: 'Failed checking tombstone', key: tombstoneYdy, err: err2 });
                }

                if (isDeleted1 || isDeleted2) {
                    logger.info({
                        msg: 'Skipped deleted email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_tombstone_found',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        entryId: messageId
                    });
                    break;
                }

                const { index, client } = await getESClient(logger);
                if (!client) {
                    return false;
                }

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
                    if (logger.notifyError) {
                        logger.notifyError(err, event => {
                            event.setUser(job.data.account);
                            event.addMetadata('ee', {
                                index
                            });
                        });
                    }
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
                for (let subType of ['id', 'plain', 'html', 'encodedSize', '_generatedHtml']) {
                    if (messageData.text && messageData.text[subType]) {
                        textContent[subType] = messageData.text[subType];
                    }
                }
                messageData.text = textContent;

                if (messageData.attachments) {
                    for (let attachment of messageData.attachments) {
                        if ('filename' in attachment && !attachment.filename) {
                            // remove falsy filenames, otherwise these will be casted into strings
                            delete attachment.filename;
                        }
                    }
                }

                messageData.preview = generateTextPreview(textContent, 220);

                // Remove event file content if the attachment exists
                if (messageData.calendarEvents) {
                    for (let calendarEvent of messageData.calendarEvents) {
                        if (calendarEvent.attachment) {
                            let attachment = messageData.attachments && messageData.attachments.find(attachment => attachment.id === calendarEvent.attachment);
                            if (attachment && attachment.content) {
                                // no need for duplicate data
                                delete calendarEvent.content;
                                delete calendarEvent.encoding;
                            }
                        }
                    }
                }

                let emailDocument = await preProcess.run(messageData);
                if (!emailDocument) {
                    // skip
                    logger.trace({
                        msg: 'Skipped new email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_index',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        entryId: messageId
                    });
                    return false;
                }

                // do not allow earlier updates than this timestamp
                emailDocument.updateTime = new Date(job.data.date).getTime();

                let indexResult;
                try {
                    indexResult = await client.index({
                        index,
                        id: `${job.data.account}:${messageId}`,
                        document: emailDocument
                    });
                    if (!indexResult) {
                        throw new Error('Empty index response');
                    }
                } catch (err) {
                    logger.error({
                        msg: 'Failed to index new email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_index_error',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        entryId: messageId,
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
                    entryId: messageId,
                    indexResult
                });

                return {
                    index: indexResult._index,
                    id: indexResult._id,
                    documentVersion: indexResult._version,
                    threadId: messageData.threadId,
                    result: indexResult.result
                };
            }

            case MESSAGE_DELETED_NOTIFY:
                {
                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    messageData.account = job.data.account;
                    messageData.created = job.data.date;

                    const { index, client } = await getESClient(logger);
                    if (!client) {
                        return;
                    }

                    let deleteResult = null;

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

                                // set tombstone to prevent indexing this message in case of race conditions
                                await redis
                                    .multi()
                                    .sadd(tombstoneTdy, `${messageId}`)
                                    .expire(tombstoneTdy, 24 * 3600)
                                    .exec();

                                logger.info({
                                    msg: 'Added tombstone for missing email',
                                    action: 'document',
                                    queue: job.queue.name,
                                    code: 'document_tombstone_added',
                                    job: job.id,
                                    event: job.name,
                                    account: job.data.account,
                                    entryId: messageId
                                });

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
                                    entryId: messageId,
                                    index,
                                    request: {
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
                        entryId: messageId,
                        index,
                        request: {
                            id: `${job.data.account}:${messageId}`
                        },
                        deletedCount: (deleteResult && deleteResult.deleted) || 0,
                        deleteResult
                    });
                }
                break;

            case MESSAGE_UPDATED_NOTIFY:
                {
                    let messageData = job.data.data;
                    let messageId = messageData.id;

                    let accountExists = await redis.exists(`${REDIS_PREFIX}iad:${job.data.account}`);
                    if (!accountExists) {
                        // deleted account?
                        return;
                    }

                    const { index, client } = await getESClient(logger);
                    if (!client) {
                        return;
                    }

                    let params = {
                        updateTime: new Date(job.data.date).getTime()
                    };

                    if (messageData.changes && messageData.changes.flags && messageData.changes.flags.value) {
                        params.flags = messageData.changes.flags.value;
                        params.unseen = params.flags && !params.flags.includes('\\Seen') ? true : false;
                        params.flagged = params.flags && params.flags.includes('\\Flagged') ? true : false;
                        params.answered = params.flags && params.flags.includes('\\Answered') ? true : false;
                        params.draft = params.flags && params.flags.includes('\\Draft') ? true : false;
                    }

                    if (messageData.changes && messageData.changes.labels && messageData.changes.labels.value) {
                        params.labels = messageData.changes.labels.value;
                    }

                    let script = {
                        lang: 'painless',
                        source: `
                            if ( ctx._source.updateTime != null && ctx._source.updateTime >= params.updateTime ){
                                ctx.op = 'none';
                            } else {
${Object.keys(params)
    .map(k => `${' '.repeat(32)}ctx._source.${k} = params.${k};`)
    .join('\n')}
                            }`,
                        params
                    };

                    let updateResult;

                    if (Object.keys(params).length > 1) {
                        try {
                            updateResult = await client.update({
                                index,
                                id: `${job.data.account}:${messageId}`,
                                script
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
                                        entryId: messageId,
                                        request: {
                                            index,
                                            id: `${job.data.account}:${messageId}`,
                                            doc: params
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
                        code: 'document_updated',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        entryId: messageId,
                        request: {
                            index,
                            id: `${job.data.account}:${messageId}`,
                            doc: params
                        },
                        updateResult
                    });
                }
                break;

            case EMAIL_BOUNCE_NOTIFY:
                {
                    let bounceData = job.data.data;
                    let messageId = bounceData.id;
                    if (!messageId) {
                        // nothing to do here, the bounce was not matched to a message
                        return;
                    }

                    let accountExists = await redis.exists(`${REDIS_PREFIX}iad:${job.data.account}`);
                    if (!accountExists) {
                        // deleted account?
                        return;
                    }

                    const { index, client } = await getESClient(logger);
                    if (!client) {
                        return;
                    }

                    let bounceInfo = {
                        message: bounceData.bounceMessage,
                        date: job.data.date
                    };

                    for (let key of ['recipient', 'action', 'response', 'mta', 'queueId']) {
                        if (bounceData[key]) {
                            bounceInfo[key] = bounceData[key];
                        }
                    }

                    let script = {
                        lang: 'painless',
                        source: `
if( ctx._source.bounces != null) {
    ctx._source.bounces.add(params.bounceInfo)
} else {
    ctx._source.bounces = [params.bounceInfo]
}
`,
                        params: {
                            bounceInfo
                        }
                    };

                    let updateResult;

                    try {
                        updateResult = await client.update({
                            index: `${index}`,
                            id: `${job.data.account}:${messageId}`,
                            refresh: true,
                            script
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
                                    entryId: messageId,
                                    request: {
                                        index,
                                        id: `${job.data.account}:${messageId}`,
                                        bounceData
                                    },
                                    err
                                });
                                throw err;
                        }
                    }

                    logger.trace({
                        msg: 'Updated email',
                        action: 'document',
                        queue: job.queue.name,
                        code: 'document_updated',
                        job: job.id,
                        event: job.name,
                        account: job.data.account,
                        entryId: messageId,
                        request: {
                            index,
                            id: `${job.data.account}:${messageId}`,
                            bounceData
                        },
                        updateResult
                    });
                }
                break;
        }
    },
    Object.assign(
        {
            concurrency: 1
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
        account: job.data.account,

        failedReason: job.failedReason,
        stacktrace: job.stacktrace,
        attemptsMade: job.attemptsMade
    });
});

logger.info({ msg: 'Started Documents worker thread', version: packageData.version });
