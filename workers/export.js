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
    const bugsnagLog =
        level =>
        (...args) => {
            const logFn = level === 'warn' ? logger.warn : level === 'error' ? logger.error : logger.debug;
            logFn({ msg: args.shift(), worker: 'export', source: 'bugsnag', args: args.length ? args : undefined });
        };

    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: { debug: bugsnagLog('debug'), info: bugsnagLog('info'), warn: bugsnagLog('warn'), error: bugsnagLog('error') }
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

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
        let timer = setTimeout(() => {
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

        try {
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
                if (!cursor) break;
            }

            await Export.update(account, exportId, { foldersScanned: i + 1 });

            logger.trace({
                msg: 'Folder indexed',
                account,
                exportId,
                folder: folderPath,
                foldersScanned: i + 1,
                foldersTotal: foldersToProcess.length
            });
        } catch (err) {
            logger.warn({ msg: 'Failed to index folder', account, exportId, folder: folderPath, err });
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

async function exportMessages(job, exportData) {
    const { account, exportId } = job.data;
    const { filePath } = exportData;
    const includeAttachments = exportData.includeAttachments === '1';
    const textType = exportData.textType || '*';
    const maxBytes = Number(exportData.maxBytes) || 5 * 1024 * 1024;
    const maxMessageSize = (await settings.get('exportMaxMessageSize')) || DEFAULT_EXPORT_MAX_MESSAGE_SIZE;

    const accountObject = new Account({
        account,
        redis,
        call,
        secret: await getSecret()
    });

    const gzipStream = zlib.createGzip();
    const fileStream = fs.createWriteStream(filePath);
    gzipStream.pipe(fileStream);

    let lastScore = Number(exportData.lastProcessedScore) || 0;
    let processed = 0;
    let totalBytesWritten = 0;

    try {
        while (true) {
            const batch = await Export.getNextBatch(account, exportId, lastScore, BATCH_SIZE);
            if (batch.length === 0) break;

            for (const entry of batch) {
                if (includeAttachments && entry.size > maxMessageSize) {
                    await Export.incrementSkipped(account, exportId);
                    lastScore = entry.score + 0.001;
                    continue;
                }

                try {
                    const message = await accountObject.getMessage(entry.messageId, { textType, maxBytes });
                    message.path = entry.folder;

                    if (includeAttachments && message.attachments && message.attachments.length) {
                        for (const attachment of message.attachments) {
                            try {
                                const content = await accountObject.getAttachment(attachment.id);
                                attachment.content = content.toString('base64');
                            } catch (attachErr) {
                                attachment.contentError = attachErr.message;
                            }
                        }
                    }

                    const line = JSON.stringify(message) + '\n';
                    gzipStream.write(line);
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

                lastScore = entry.score + 0.001;
            }

            await Export.updateLastProcessedScore(account, exportId, lastScore);
            logger.trace({ msg: 'Export batch processed', account, exportId, messagesExported: processed });
        }
    } finally {
        await new Promise((resolve, reject) => {
            gzipStream.end();
            fileStream.on('finish', resolve);
            fileStream.on('error', reject);
        });
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

Export.markInterruptedAsFailed()
    .then(() => logger.info({ msg: 'Checked for interrupted exports' }))
    .catch(err => logger.error({ msg: 'Failed to check for interrupted exports', err }));

setInterval(() => {
    try {
        parentPort.postMessage({ cmd: 'heartbeat' });
    } catch {
        // Ignore errors, parent might be shutting down
    }
}, 10 * 1000).unref();

parentPort.postMessage({ cmd: 'ready' });

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
