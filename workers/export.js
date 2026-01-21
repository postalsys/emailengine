'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');
const fs = require('fs');
const zlib = require('zlib');

const { REDIS_PREFIX, EXPORT_COMPLETED_NOTIFY, EXPORT_FAILED_NOTIFY, DEFAULT_EXPORT_MAX_MESSAGE_SIZE } = require('../lib/consts');
const { getDuration, readEnvValue, threadStats } = require('../lib/tools');
const { webhooks: Webhooks } = require('../lib/webhooks');
const settings = require('../lib/settings');
const { Export } = require('../lib/export');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'export', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'export', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'export', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'export', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const { redis, queueConf } = require('../lib/db');
const { Worker } = require('bullmq');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');

config.queues = config.queues || {
    export: 1
};

config.service = config.service || {};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const EXPORT_QC = (readEnvValue('EENGINE_EXPORT_QC') && Number(readEnvValue('EENGINE_EXPORT_QC'))) || config.queues.export || 1;

const BATCH_SIZE = 100;
const LIST_PAGE_SIZE = 1000;
const FOLDER_INDEX_MAX_RETRIES = 3;
const FOLDER_INDEX_RETRY_DELAY_MS = 1000;

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
        let timer = setTimeout(() => {
            callQueue.delete(mid);
            let err = new Error('Timeout waiting for command response [T6]');
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

async function notify(account, event, data) {
    metrics(logger, 'events', 'inc', { event });

    const serviceUrl = (await settings.get('serviceUrl')) || null;
    const payload = {
        serviceUrl,
        account,
        date: new Date().toISOString(),
        event,
        data
    };

    await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
}

async function indexMessages(job, exportData) {
    const { account, exportId } = job.data;
    const folders = JSON.parse(exportData.folders || '[]');
    const startDate = new Date(Number(exportData.startDate));
    const endDate = new Date(Number(exportData.endDate));

    // Verify account exists before attempting to process
    const accountData = await redis.hgetall(`${REDIS_PREFIX}iad:${account}`);
    if (!accountData || !accountData.account) {
        const err = new Error('Account not found or has been deleted');
        err.code = 'AccountNotFound';
        err.statusCode = 404;
        throw err;
    }

    const accountObject = new Account({
        account,
        redis,
        call,
        secret: await getSecret()
    });

    let mailboxes;
    try {
        mailboxes = await accountObject.listMailboxes();
    } catch (err) {
        throw new Error(`Failed to list mailboxes: ${err.message}`);
    }

    const foldersToProcess = resolveFolders(folders, mailboxes);

    await Export.update(account, exportId, { foldersTotal: foldersToProcess.length });

    logger.info({ msg: 'Starting export indexing', account, exportId, foldersToProcess: foldersToProcess.length });

    for (let i = 0; i < foldersToProcess.length; i++) {
        const folderPath = foldersToProcess[i];
        let retries = FOLDER_INDEX_MAX_RETRIES;
        let lastError = null;

        while (retries > 0) {
            try {
                await indexFolder(accountObject, account, exportId, folderPath, startDate, endDate);

                await Export.update(account, exportId, { foldersScanned: i + 1 });

                logger.trace({
                    msg: 'Folder indexed',
                    account,
                    exportId,
                    folder: folderPath,
                    foldersScanned: i + 1,
                    foldersTotal: foldersToProcess.length
                });

                lastError = null;
                break;
            } catch (err) {
                lastError = err;
                retries--;
                if (retries > 0) {
                    const attemptNumber = FOLDER_INDEX_MAX_RETRIES - retries;
                    const delay = FOLDER_INDEX_RETRY_DELAY_MS * Math.pow(2, attemptNumber - 1);
                    logger.warn({
                        msg: 'Folder indexing failed, retrying',
                        account,
                        exportId,
                        folder: folderPath,
                        retriesLeft: retries,
                        delayMs: delay,
                        err
                    });
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        if (lastError) {
            logger.warn({
                msg: 'Failed to index folder after retries',
                account,
                exportId,
                folder: folderPath,
                maxRetries: FOLDER_INDEX_MAX_RETRIES,
                err: lastError
            });
        }
    }
}

function resolveFolders(folders, mailboxes) {
    if (!folders || folders.length === 0) {
        return mailboxes.filter(mb => !['\\Junk', '\\Trash'].includes(mb.specialUse)).map(mb => mb.path);
    }

    return folders
        .map(folder => {
            if (folder.startsWith('\\')) {
                const match = mailboxes.find(mb => mb.specialUse === folder);
                return match ? match.path : null;
            }
            return folder;
        })
        .filter(Boolean);
}

async function indexFolder(accountObject, account, exportId, folderPath, startDate, endDate) {
    let cursor = null;

    while (true) {
        const searchCriteria = { since: startDate };
        if (endDate < new Date()) {
            searchCriteria.before = endDate;
        }

        const listOptions = {
            path: folderPath,
            pageSize: LIST_PAGE_SIZE,
            search: searchCriteria,
            minimalFields: true,
            cursor
        };

        const result = await accountObject.listMessages(listOptions);

        for (const msg of result.messages || []) {
            await Export.queueMessage(account, exportId, {
                folder: folderPath,
                messageId: msg.id || msg.emailId,
                uid: msg.uid,
                size: msg.size || 0,
                date: msg.date ? new Date(msg.date).getTime() : Date.now()
            });
        }

        cursor = result.nextPageCursor;
        if (!cursor) {
            break;
        }
    }
}

async function exportMessages(job, exportData) {
    const { account, exportId } = job.data;
    const { filePath } = exportData;
    const includeAttachments = exportData.includeAttachments === '1';
    const textType = exportData.textType || '*';
    const maxBytes = Number(exportData.maxBytes) || 5 * 1024 * 1024;
    const maxMessageSize = (await settings.get('exportMaxMessageSize')) || DEFAULT_EXPORT_MAX_MESSAGE_SIZE;
    const isEncrypted = exportData.isEncrypted === '1';

    const accountObject = new Account({
        account,
        redis,
        call,
        secret: await getSecret()
    });

    const gzipStream = zlib.createGzip();
    const fileStream = fs.createWriteStream(filePath);

    // Capture stream errors immediately to catch disk I/O errors during writes
    let streamError = null;
    function handleStreamError(err) {
        if (!streamError) {
            streamError = err;
        }
    }
    gzipStream.on('error', handleStreamError);
    fileStream.on('error', handleStreamError);

    // Set up encryption if enabled and secret is available
    const secret = isEncrypted ? await getSecret() : null;
    if (secret) {
        const { createEncryptStream } = require('../lib/stream-encrypt');
        const encryptStream = createEncryptStream(secret);
        encryptStream.on('error', handleStreamError);
        gzipStream.pipe(encryptStream).pipe(fileStream);
    } else {
        gzipStream.pipe(fileStream);
    }

    function writeWithBackpressure(data) {
        if (streamError) {
            return Promise.reject(streamError);
        }

        if (gzipStream.write(data)) {
            return Promise.resolve();
        }

        return new Promise((resolve, reject) => {
            const cleanup = () => {
                gzipStream.removeListener('drain', onDrain);
                gzipStream.removeListener('error', onError);
            };
            const onDrain = () => {
                cleanup();
                resolve();
            };
            const onError = err => {
                cleanup();
                reject(err);
            };
            gzipStream.once('drain', onDrain);
            gzipStream.once('error', onError);
        });
    }

    let lastScore = Number(exportData.lastProcessedScore) || 0;
    let processed = 0;
    let totalBytesWritten = 0;
    let processingError = null;

    try {
        while (true) {
            if (streamError) {
                throw streamError;
            }

            const batch = await Export.getNextBatch(account, exportId, lastScore, BATCH_SIZE);
            if (batch.length === 0) {
                break;
            }

            for (const entry of batch) {
                if (streamError) {
                    throw streamError;
                }

                if (includeAttachments && entry.size > maxMessageSize) {
                    await Export.incrementSkipped(account, exportId);
                    lastScore = entry.score;
                    continue;
                }

                try {
                    const message = await accountObject.getMessage(entry.messageId, { textType, maxBytes });
                    message.path = entry.folder;

                    if (includeAttachments && message.attachments && message.attachments.length) {
                        for (const attachment of message.attachments) {
                            try {
                                if (attachment.size && attachment.size > maxMessageSize) {
                                    attachment.contentError = `Attachment too large (${attachment.size} bytes, limit ${maxMessageSize})`;
                                    continue;
                                }

                                const stream = await accountObject.getAttachment(attachment.id);
                                const chunks = [];
                                let totalSize = 0;

                                for await (const chunk of stream) {
                                    totalSize += chunk.length;
                                    if (totalSize > maxMessageSize) {
                                        if (typeof stream.destroy === 'function') {
                                            stream.destroy();
                                            await new Promise(resolve => {
                                                const CLEANUP_TIMEOUT_MS = 1000;
                                                stream.once('close', resolve);
                                                setTimeout(resolve, CLEANUP_TIMEOUT_MS);
                                            });
                                        }
                                        throw new Error(`Attachment exceeds size limit (>${maxMessageSize} bytes)`);
                                    }
                                    chunks.push(chunk);
                                }

                                attachment.content = Buffer.concat(chunks).toString('base64');
                            } catch (attachErr) {
                                attachment.contentError = attachErr.message;
                            }
                        }
                    }

                    const line = JSON.stringify(message) + '\n';
                    await writeWithBackpressure(line);
                    totalBytesWritten += Buffer.byteLength(line);

                    await Export.incrementExported(account, exportId, Buffer.byteLength(line));
                    processed++;
                } catch (err) {
                    const isSkippable = err.code === 'MessageNotFound' || err.statusCode === 404 || err.message?.includes('Failed to generate message ID');
                    if (isSkippable) {
                        logger.warn({
                            msg: 'Skipping message during export',
                            account,
                            exportId,
                            messageId: entry.messageId,
                            folder: entry.folder,
                            reason: err.message || err.code
                        });
                        await Export.incrementSkipped(account, exportId);
                    } else {
                        throw err;
                    }
                }

                lastScore = entry.score;
            }

            await Export.updateLastProcessedScore(account, exportId, lastScore);
            logger.trace({ msg: 'Export batch processed', account, exportId, messagesExported: processed });
        }
    } catch (err) {
        processingError = err;
    }

    // Finalize streams regardless of processing outcome
    await new Promise((resolve, reject) => {
        gzipStream.end();
        fileStream.once('finish', resolve);
        fileStream.once('error', err => reject(streamError || err));
    });

    // Propagate errors: prefer processing error, then stream error
    if (processingError) {
        throw processingError;
    }
    if (streamError) {
        throw streamError;
    }

    logger.info({ msg: 'Export messages completed', account, exportId, messagesExported: processed, bytesWritten: totalBytesWritten });
}

const exportWorker = new Worker(
    'export',
    async job => {
        const { account, exportId } = job.data;
        const startTime = Date.now();

        logger.info({ msg: 'Processing export job', account, exportId, job: job.id });

        try {
            const exportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`);
            if (!exportData || !exportData.exportId) {
                throw new Error('Export not found');
            }

            await Export.update(account, exportId, { status: 'processing', phase: 'indexing' });
            await indexMessages(job, exportData);

            await Export.update(account, exportId, { phase: 'exporting' });
            await exportMessages(job, exportData);

            await Export.complete(account, exportId);

            const finalData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`);

            await notify(account, EXPORT_COMPLETED_NOTIFY, {
                exportId,
                folders: JSON.parse(exportData.folders || '[]'),
                startDate: new Date(Number(exportData.startDate)).toISOString(),
                endDate: new Date(Number(exportData.endDate)).toISOString(),
                messagesExported: Number(finalData.messagesExported) || 0,
                messagesSkipped: Number(finalData.messagesSkipped) || 0,
                bytesWritten: Number(finalData.bytesWritten) || 0,
                duration: Date.now() - startTime,
                expiresAt: new Date(Number(finalData.expiresAt)).toISOString()
            });

            logger.info({ msg: 'Export job completed', account, exportId, duration: Date.now() - startTime });
        } catch (err) {
            logger.error({ msg: 'Export job failed', account, exportId, err });

            const exportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`).catch(() => ({}));

            // Clean up partial file on failure
            if (exportData.filePath) {
                await fs.promises.unlink(exportData.filePath).catch(() => {});
            }

            await Export.fail(account, exportId, err.message);

            await notify(account, EXPORT_FAILED_NOTIFY, {
                exportId,
                error: err.message,
                errorCode: err.code,
                phase: exportData.phase || 'unknown',
                messagesExported: Number(exportData.messagesExported) || 0,
                messagesQueued: Number(exportData.messagesQueued) || 0
            });

            throw err;
        }
    },
    { concurrency: EXPORT_QC, ...queueConf }
);

exportWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', { queue: 'export', status: 'completed' });
    logger.info({ msg: 'Export queue entry completed', queue: job.queue.name, job: job.id, account: job.data.account, exportId: job.data.exportId });
});

exportWorker.on('failed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', { queue: 'export', status: 'failed' });
    logger.error({
        msg: 'Export queue entry failed',
        queue: job.queue.name,
        job: job.id,
        account: job.data.account,
        exportId: job.data.exportId,
        failedReason: job.failedReason
    });
});

function onCommand(command) {
    if (command.cmd === 'resource-usage') {
        return threadStats.usage();
    }
    logger.debug({ msg: 'Unhandled command', command });
    return 999;
}

// Startup sequence: clean up interrupted exports before accepting new jobs
(async () => {
    try {
        await Export.markInterruptedAsFailed();
        logger.info({ msg: 'Checked for interrupted exports' });
    } catch (err) {
        logger.error({ msg: 'Failed to check for interrupted exports', err });
    }

    setInterval(() => {
        try {
            parentPort.postMessage({ cmd: 'heartbeat' });
        } catch {
            // Ignore errors, parent might be shutting down
        }
    }, 10 * 1000).unref();

    // Only signal ready after cleanup is complete to prevent race conditions
    parentPort.postMessage({ cmd: 'ready' });
})();

parentPort.on('message', message => {
    if (message && message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
        const { resolve, reject, timer } = callQueue.get(message.mid);
        clearTimeout(timer);
        callQueue.delete(message.mid);

        if (message.error) {
            const err = new Error(message.error);
            if (message.code) err.code = message.code;
            if (message.statusCode) err.statusCode = message.statusCode;
            if (message.info) err.info = message.info;
            return reject(err);
        }
        return resolve(message.response);
    }

    if (message && message.cmd === 'call' && message.mid) {
        Promise.resolve(onCommand(message.message))
            .then(response => parentPort.postMessage({ cmd: 'resp', mid: message.mid, response }))
            .catch(err => parentPort.postMessage({ cmd: 'resp', mid: message.mid, error: err.message, code: err.code, statusCode: err.statusCode }));
    }
});

logger.info({ msg: 'Started export worker thread', version: packageData.version });
