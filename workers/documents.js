'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const logger = require('../lib/logger');
const { preProcess } = require('../lib/pre-process');
const settings = require('../lib/settings');
const crypto = require('crypto');

const { readEnvValue, threadStats, getDuration } = require('../lib/tools');

const GB_COLLECT_DELAY = 6 * 3600 * 1000; // 6h
const GB_FAILURE_DELAY = 3 * 1000;
const GB_EMPTY_DELAY = 10 * 1000;

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

const config = require('wild-config');
config.service = config.service || {};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;

const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T4]');
            err.statusCode = 504;
            err.code = 'Timeout';
            err.ttl = ttl;
            reject(err);
        }, ttl);

        callQueue.set(mid, { resolve, reject, timer });

        try {
            parentPort.postMessage(
                {
                    cmd: 'call',
                    mid,
                    message
                },
                transferList
            );
        } catch (err) {
            clearTimeout(timer);
            callQueue.delete(mid);
            return reject(err);
        }
    });
}

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
    if (message && message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
        let { resolve, reject, timer } = callQueue.get(message.mid);
        clearTimeout(timer);
        callQueue.delete(message.mid);
        if (message.error) {
            let err = new Error(message.error);
            if (message.code) {
                err.code = message.code;
            }
            if (message.statusCode) {
                err.statusCode = message.statusCode;
            }
            return reject(err);
        } else {
            return resolve(message.response);
        }
    }

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

                    for (let indexName of [index, `${index}.threads`, `${index}.embeddings`]) {
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

                // Skip embeddings if set for document store (nested dense cosine vectors can not be indexed, must be separate documents)

                let embeddings = messageData.embeddings;
                delete messageData.embeddings;

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

                let storedEmbeddings;

                if ((await settings.get('documentStoreGenerateEmbeddings')) && messageData.messageId) {
                    let embeddingsQuery = {
                        bool: {
                            must: [
                                {
                                    term: {
                                        account: job.data.account
                                    }
                                },
                                {
                                    term: {
                                        messageId: messageData.messageId
                                    }
                                }
                            ]
                        }
                    };

                    let embeddingsIndex = `${index}.embeddings`;

                    let existingResult;

                    try {
                        existingResult = await client.search({
                            index: embeddingsIndex,
                            size: 1,
                            query: embeddingsQuery,
                            _source: false
                        });
                        if (!existingResult || !existingResult.hits) {
                            logger.error({
                                msg: 'Failed to check for existing embeddings',
                                account: job.data.account,
                                messageId: messageData.messageId,
                                existingResult
                            });
                            storedEmbeddings = false;
                        }
                    } catch (err) {
                        logger.error({
                            msg: 'Failed to check for existing embeddings',
                            account: job.data.account,
                            messageId: messageData.messageId,
                            err
                        });
                        storedEmbeddings = false;
                    }

                    if (existingResult?.hits?.total?.value === 0) {
                        if (!embeddings) {
                            try {
                                embeddings = await call({
                                    cmd: 'generateEmbeddings',
                                    data: {
                                        message: {
                                            headers: messageData.headers, // already an array value, so no need to convert
                                            attachments: messageData.attachments,
                                            from: messageData.from,
                                            subject: messageData.subject,
                                            text: messageData.text.plain,
                                            html: messageData.text.html
                                        },
                                        account: job.data.account
                                    },
                                    timeout: 5 * 60 * 1000
                                });
                            } catch (err) {
                                logger.error({ msg: 'Failed to fetch embeddings', account: job.data.account, messageId: messageData.messageId, err });
                                storedEmbeddings = false;
                            }
                        }

                        if (embeddings?.embeddings?.length) {
                            let messageIdHash = crypto.createHash('sha256').update(messageData.messageId).digest('hex');
                            let dataset = embeddings.embeddings.map((entry, i) => ({
                                account: job.data.account,
                                messageId: messageData.messageId,
                                embeddings: entry.embedding,
                                chunk: entry.chunk,
                                model: embeddings.model,
                                chunkNr: i,
                                chunks: embeddings.embeddings.length,
                                date: messageData.date,
                                created: new Date()
                            }));

                            const operations = dataset.flatMap(doc => [
                                { index: { _index: embeddingsIndex, _id: `${job.data.account}:${messageIdHash}:${doc.chunkNr}` } },
                                doc
                            ]);

                            try {
                                const bulkResponse = await client.bulk({ refresh: true, operations });
                                if (bulkResponse?.errors !== false) {
                                    logger.error({
                                        msg: 'Failed to store embeddings',
                                        account: job.data.account,
                                        messageId: messageData.messageId,
                                        bulkResponse
                                    });
                                    storedEmbeddings = false;
                                } else {
                                    logger.info({
                                        msg: 'Stored embeddings for a message',
                                        messageId: messageData.messageId,
                                        items: bulkResponse.items?.length
                                    });
                                    storedEmbeddings = true;
                                }
                            } catch (err) {
                                logger.error({
                                    msg: 'Failed to store embeddings',
                                    account: job.data.account,
                                    messageId: messageData.messageId,
                                    err
                                });
                                storedEmbeddings = false;
                            }
                        }
                    } else {
                        logger.info({ msg: 'Skipped embeddings, already exist', account: job.data.account, messageId: messageData.messageId });
                        storedEmbeddings = false;
                    }
                }

                // remove from embeddings delete queue
                await redis.zrem(`${REDIS_PREFIX}expungequeue`, `${job.data.account}:${messageId}`);

                return {
                    index: indexResult._index,
                    id: indexResult._id,
                    documentVersion: indexResult._version,
                    threadId: messageData.threadId,
                    result: indexResult.result,
                    storedEmbeddings
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
                        let messageIdHeader;
                        try {
                            // resolve Message-ID value for deleted email
                            let getResult = await client.get({
                                index,
                                id: `${job.data.account}:${messageId}`,
                                _source_includes: ['messageId']
                            });
                            messageIdHeader = (getResult?._source?.messageId || '').toString().trim();
                        } catch (err) {
                            if (err.name === 'ResponseError') {
                                logger.trace({ msg: 'Failed to retrieve Message-ID for deleted email', account: job.data.account, message: messageId });
                            } else {
                                logger.error({ msg: 'Failed to retrieve Message-ID for deleted email', account: job.data.account, message: messageId, err });
                            }
                        }

                        deleteResult = await client.delete({
                            index,
                            id: `${job.data.account}:${messageId}`
                        });

                        // add to embeddings delete queue
                        if (messageIdHeader) {
                            await redis.zadd(`${REDIS_PREFIX}expungequeue`, Date.now(), `${job.data.account}:${messageIdHeader}`);
                        }
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
            concurrency: 1,
            maxStalledCount: 5,
            stalledInterval: 60 * 1000
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

const clearExpungedEmbeddings = async () => {
    if (!(await redis.exists(`${REDIS_PREFIX}expungequeue`))) {
        // nothing to do here
        await new Promise(resolve => {
            let timer = setTimeout(resolve, GB_EMPTY_DELAY);
            timer.unref();
        });
        return;
    }

    let rangeEnd = Date.now() - GB_COLLECT_DELAY;
    try {
        let expungedEntry = await redis.zrangebyscore(`${REDIS_PREFIX}expungequeue`, 0, rangeEnd, 'LIMIT', '0', '1');
        if (!expungedEntry?.length) {
            await new Promise(resolve => {
                let timer = setTimeout(resolve, GB_EMPTY_DELAY);
                timer.unref();
            });
            return;
        }

        if (expungedEntry && expungedEntry.length) {
            expungedEntry = expungedEntry[0];
            let [account, ...messageId] = expungedEntry.split(':');
            if (messageId) {
                messageId = messageId.join(':');
            }

            if (account && messageId) {
                let matchQuery = {
                    bool: {
                        must: [
                            {
                                term: {
                                    account
                                }
                            },
                            {
                                term: {
                                    messageId
                                }
                            }
                        ]
                    }
                };

                const { index, client } = await getESClient(logger);

                let existingResult;
                try {
                    existingResult = await client.search({
                        index,
                        size: 1,
                        query: matchQuery,
                        _source: false
                    });

                    if (!existingResult || !existingResult.hits) {
                        logger.error({
                            msg: 'Failed to run query to find emails by Message-ID. Empty result.',
                            account,
                            messageId,
                            existingResult
                        });
                        throw new Error('Empty result');
                    }
                } catch (err) {
                    logger.error({
                        msg: 'Failed to run query to find emails by Message-ID',
                        account,
                        messageId,
                        err
                    });
                    throw err;
                }

                if (existingResult?.hits?.total?.value === 0) {
                    // can purge embeddings
                    logger.trace({
                        msg: 'Deleting embeddings for a missing email',
                        account,
                        messageId
                    });
                    try {
                        let deleteResult = await client.deleteByQuery({
                            index: `${index}.embeddings`,
                            query: {
                                bool: {
                                    must: [
                                        {
                                            term: {
                                                account
                                            }
                                        },

                                        {
                                            term: {
                                                messageId
                                            }
                                        }
                                    ]
                                }
                            }
                        });
                        if (deleteResult?.deleted) {
                            logger.info({
                                msg: 'Deleted embeddings for a missing email',
                                account,
                                messageId,
                                deleted: deleteResult?.deleted
                            });
                        }
                        // clear existing entry
                        await redis.zrem(`${REDIS_PREFIX}expungequeue`, `${account}:${messageId}`);
                        logger.trace({
                            msg: 'Removed entry from expunge queue',
                            account,
                            messageId
                        });
                    } catch (err) {
                        logger.info({
                            msg: 'Dailed to delete embeddings for a missing email',
                            account,
                            messageId,
                            err
                        });
                    }
                } else {
                    // clear existing entry
                    await redis.zrem(`${REDIS_PREFIX}expungequeue`, `${account}:${messageId}`);
                    logger.trace({
                        msg: 'Removed still existing entry from expunge queue',
                        account,
                        messageId
                    });
                }
            }
        }
    } catch (err) {
        logger.error({ msg: 'Failed to retrieve expunged entries', rangeStart: 0, rangeEnd, err });
        await new Promise(resolve => {
            let timer = setTimeout(resolve, GB_FAILURE_DELAY);
            timer.unref();
        });
        return;
    }
};

function runGarbageCollector() {
    clearExpungedEmbeddings()
        .catch(err => {
            logger.error({ msg: 'Failed to run garbage collector for embeddings', err });
        })
        .finally(() => runGarbageCollector());
}

logger.info({ msg: 'Started Documents worker thread', version: packageData.version });

runGarbageCollector();
