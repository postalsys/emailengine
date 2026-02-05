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

const DEFAULT_EXPORT_TIMEOUT = 5 * 60 * 1000;
const EXPORT_TIMEOUT = getDuration(readEnvValue('EENGINE_EXPORT_TIMEOUT')) || DEFAULT_EXPORT_TIMEOUT;

const EXPORT_QC = (readEnvValue('EENGINE_EXPORT_QC') && Number(readEnvValue('EENGINE_EXPORT_QC'))) || config.queues.export || 1;

const BATCH_SIZE = 100;
const LIST_PAGE_SIZE = 1000;
const FOLDER_INDEX_MAX_RETRIES = 3;
const FOLDER_INDEX_RETRY_DELAY_MS = 1000;

const IMAP_MESSAGE_MAX_RETRIES = 3;
const IMAP_MESSAGE_RETRY_BASE_DELAY = 2000;
const ACCOUNT_CHECK_INTERVAL = 60 * 1000;

function isTransientError(err) {
    if (['ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH'].includes(err.code)) {
        return true;
    }
    if (err.statusCode >= 500 && err.statusCode < 600) {
        return true;
    }
    if (err.code === 'Timeout' || err.message?.includes('timeout')) {
        return true;
    }
    return false;
}

function isSkippableError(err) {
    return err.code === 'MessageNotFound' || err.statusCode === 404 || err.message?.includes('Failed to generate message ID');
}

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
        secret: await getSecret(),
        timeout: EXPORT_TIMEOUT
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
    const resolveFolder = folder => {
        if (folder.startsWith('\\')) {
            const match = mailboxes.find(mb => mb.specialUse === folder);
            return match ? match.path : null;
        }
        return folder;
    };

    if (!folders || folders.length === 0) {
        // If \All folder exists (Gmail/Outlook), use it; otherwise export all except Junk and Trash
        const allMailFolder = mailboxes.find(mb => mb.specialUse === '\\All');
        if (allMailFolder) {
            return [allMailFolder.path];
        }
        return mailboxes.filter(mb => !['\\Junk', '\\Trash'].includes(mb.specialUse)).map(mb => mb.path);
    }

    return folders.map(resolveFolder).filter(Boolean);
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
            metadataOnly: true,
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
        secret: await getSecret(),
        timeout: EXPORT_TIMEOUT
    });

    const gzipStream = zlib.createGzip();
    const fileStream = fs.createWriteStream(filePath, job.data.isResumed ? { flags: 'a' } : undefined);

    let streamError = null;
    function handleStreamError(err) {
        if (!streamError) {
            streamError = err;
        }
    }
    gzipStream.on('error', handleStreamError);
    fileStream.on('error', handleStreamError);

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

    let lastAccountCheck = Date.now();

    const accountData = await accountObject.loadAccountData(account);
    const isApiAccount = await accountObject.isApiClient(accountData);
    const MESSAGE_FETCH_BATCH_SIZE = 10; // Batch size for parallel message fetching
    const MAX_RATE_LIMIT_RETRIES = 5; // Max retries for rate-limited messages
    const RATE_LIMIT_BASE_DELAY = 5000; // Base delay for rate limit backoff (5 seconds)

    async function processMessage(message, entry) {
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
    }

    try {
        while (true) {
            if (streamError) {
                throw streamError;
            }

            if (Date.now() - lastAccountCheck > ACCOUNT_CHECK_INTERVAL) {
                const accountCheck = await redis.hgetall(`${REDIS_PREFIX}iad:${account}`);
                if (!accountCheck || !accountCheck.account) {
                    const err = new Error('Account was deleted during export');
                    err.code = 'AccountDeleted';
                    throw err;
                }
                lastAccountCheck = Date.now();
            }

            const batch = await Export.getNextBatch(account, exportId, lastScore, BATCH_SIZE);
            if (batch.length === 0) {
                break;
            }

            const entriesToFetch = [];
            for (const entry of batch) {
                if (includeAttachments && entry.size > maxMessageSize) {
                    await Export.incrementSkipped(account, exportId);
                    lastScore = entry.score;
                } else {
                    entriesToFetch.push(entry);
                }
            }

            if (entriesToFetch.length === 0) {
                await Export.updateLastProcessedScore(account, exportId, lastScore);
                continue;
            }

            if (isApiAccount && entriesToFetch.length > 1) {
                for (let i = 0; i < entriesToFetch.length; i += MESSAGE_FETCH_BATCH_SIZE) {
                    if (streamError) {
                        throw streamError;
                    }

                    let fetchBatch = entriesToFetch.slice(i, i + MESSAGE_FETCH_BATCH_SIZE);
                    let rateLimitRetry = 0;

                    while (fetchBatch.length > 0) {
                        const messageIds = fetchBatch.map(e => e.messageId);
                        const messageResults = await accountObject.getMessages(messageIds, { textType, maxBytes });

                        const resultMap = new Map();
                        for (const result of messageResults) {
                            resultMap.set(result.messageId, result);
                        }

                        const rateLimitedEntries = [];

                        for (const entry of fetchBatch) {
                            const result = resultMap.get(entry.messageId);

                            if (result && result.error) {
                                const err = result.error;
                                const isRateLimited = err.statusCode === 429 || err.code === 'rateLimitExceeded' || err.code === 'userRateLimitExceeded';

                                if (isSkippableError(err)) {
                                    logger.warn({
                                        msg: 'Skipping message during export',
                                        account,
                                        exportId,
                                        messageId: entry.messageId,
                                        folder: entry.folder,
                                        reason: err.message || err.code
                                    });
                                    await Export.incrementSkipped(account, exportId);
                                    lastScore = entry.score;
                                } else if (isRateLimited && rateLimitRetry < MAX_RATE_LIMIT_RETRIES) {
                                    rateLimitedEntries.push(entry);
                                } else {
                                    const error = new Error(err.message);
                                    error.code = err.code;
                                    error.statusCode = err.statusCode;
                                    throw error;
                                }
                            } else if (result && result.data) {
                                await processMessage(result.data, entry);
                                lastScore = entry.score;
                            } else {
                                logger.warn({
                                    msg: 'Skipping message during export',
                                    account,
                                    exportId,
                                    messageId: entry.messageId,
                                    folder: entry.folder,
                                    reason: 'Message not found in batch results'
                                });
                                await Export.incrementSkipped(account, exportId);
                                lastScore = entry.score;
                            }
                        }

                        if (rateLimitedEntries.length > 0) {
                            rateLimitRetry++;
                            const delay = RATE_LIMIT_BASE_DELAY * Math.pow(2, rateLimitRetry - 1) + Math.random() * 1000;
                            logger.warn({
                                msg: 'Rate limited during export, retrying batch',
                                account,
                                exportId,
                                rateLimitedCount: rateLimitedEntries.length,
                                attempt: rateLimitRetry,
                                maxAttempts: MAX_RATE_LIMIT_RETRIES,
                                delayMs: Math.round(delay)
                            });
                            await new Promise(resolve => setTimeout(resolve, delay));
                            fetchBatch = rateLimitedEntries;
                        } else {
                            break;
                        }
                    }
                }
            } else {
                for (const entry of entriesToFetch) {
                    if (streamError) {
                        throw streamError;
                    }

                    let message = null;
                    let fetchError = null;

                    for (let attempt = 1; attempt <= IMAP_MESSAGE_MAX_RETRIES; attempt++) {
                        try {
                            message = await accountObject.getMessage(entry.messageId, { textType, maxBytes });
                            break; // Success - exit retry loop
                        } catch (err) {
                            if (isSkippableError(err)) {
                                fetchError = err;
                                break;
                            }

                            if (isTransientError(err) && attempt < IMAP_MESSAGE_MAX_RETRIES) {
                                const delay = IMAP_MESSAGE_RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                                logger.warn({
                                    msg: 'Message fetch failed, retrying',
                                    account,
                                    exportId,
                                    messageId: entry.messageId,
                                    folder: entry.folder,
                                    attempt,
                                    maxAttempts: IMAP_MESSAGE_MAX_RETRIES,
                                    delayMs: delay,
                                    errorCode: err.code,
                                    errorMessage: err.message
                                });
                                await new Promise(resolve => setTimeout(resolve, delay));
                                continue;
                            }

                            fetchError = err;
                            break;
                        }
                    }

                    if (message) {
                        await processMessage(message, entry);
                    } else if (fetchError && isSkippableError(fetchError)) {
                        logger.warn({
                            msg: 'Skipping message during export',
                            account,
                            exportId,
                            messageId: entry.messageId,
                            folder: entry.folder,
                            reason: fetchError.message || fetchError.code
                        });
                        await Export.incrementSkipped(account, exportId);
                    } else if (fetchError) {
                        throw fetchError;
                    }

                    lastScore = entry.score;
                }
            }

            await Export.updateLastProcessedScore(account, exportId, lastScore);
            logger.trace({ msg: 'Export batch processed', account, exportId, messagesExported: processed });
        }
    } catch (err) {
        processingError = err;
    }

    const FINALIZATION_TIMEOUT = 30000;
    await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            fileStream.destroy();
            reject(streamError || new Error('Stream finalization timed out'));
        }, FINALIZATION_TIMEOUT);
        gzipStream.end();
        fileStream.once('finish', () => {
            clearTimeout(timeout);
            resolve();
        });
        fileStream.once('error', err => {
            clearTimeout(timeout);
            reject(streamError || err);
        });
    });

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
        const { account, exportId, isResumed } = job.data;
        const startTime = Date.now();

        logger.info({ msg: 'Processing export job', account, exportId, job: job.id, isResumed: !!isResumed });

        try {
            const exportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`);
            if (!exportData || !exportData.exportId) {
                throw new Error('Export not found');
            }

            if (isResumed) {
                logger.info({
                    msg: 'Resuming export from checkpoint',
                    account,
                    exportId,
                    lastProcessedScore: exportData.lastProcessedScore,
                    messagesExported: exportData.messagesExported,
                    messagesQueued: exportData.messagesQueued
                });
                await Export.update(account, exportId, { status: 'processing', phase: 'exporting', error: '' });
            } else {
                await Export.update(account, exportId, { status: 'processing', phase: 'indexing' });
                await indexMessages(job, exportData);
                await Export.update(account, exportId, { phase: 'exporting' });
            }

            const currentExportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`);
            await exportMessages(job, currentExportData);

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

            const isResumable =
                Number(exportData.lastProcessedScore) > 0 &&
                Number(exportData.messagesQueued) > 0 &&
                err.code !== 'AccountDeleted' &&
                err.code !== 'AccountNotFound';

            if (!isResumable && exportData.filePath) {
                await fs.promises.unlink(exportData.filePath).catch(() => {});
            }

            await Export.fail(account, exportId, err.message);

            if (err.code !== 'AccountDeleted' && err.code !== 'AccountNotFound') {
                await notify(account, EXPORT_FAILED_NOTIFY, {
                    exportId,
                    error: err.message,
                    errorCode: err.code,
                    phase: exportData.phase || 'unknown',
                    messagesExported: Number(exportData.messagesExported) || 0,
                    messagesQueued: Number(exportData.messagesQueued) || 0
                });
            }

            throw err;
        }
    },
    {
        concurrency: EXPORT_QC,
        lockDuration: 10 * 60 * 1000,
        stalledInterval: 2 * 60 * 1000,
        maxStalledCount: 5,
        ...queueConf
    }
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

module.exports = {
    isTransientError,
    isSkippableError,
    IMAP_MESSAGE_MAX_RETRIES,
    IMAP_MESSAGE_RETRY_BASE_DELAY,
    ACCOUNT_CHECK_INTERVAL
};
