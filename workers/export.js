'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('@zone-eu/wild-config');
const logger = require('../lib/logger');

const { REDIS_PREFIX, EXPORT_COMPLETED_NOTIFY, EXPORT_FAILED_NOTIFY } = require('../lib/consts');
const { getDuration, readEnvValue, threadStats } = require('../lib/tools');
const { webhooks: Webhooks } = require('../lib/webhooks');
const settings = require('../lib/settings');
const { Export, parseActiveEntry, getExportKey, ACTIVE_EXPORTS_KEY } = require('../lib/export');
const { createExportJobs } = require('../lib/export-worker');

const { initSentry } = require('../lib/sentry');
initSentry('export');

const { redis, queueConf, logBullErrors } = require('../lib/db');
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

    await Webhooks.enqueue(event, payload);
}

const { indexMessages, exportMessages } = createExportJobs({
    redis,
    settings,
    getSecret,
    logger,
    createAccount: async account =>
        new Account({
            account,
            redis,
            call,
            secret: await getSecret(),
            timeout: EXPORT_TIMEOUT
        })
});

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

            await Export.startProcessing(account, exportId);
            await indexMessages(job, exportData);
            await Export.update(account, exportId, { phase: 'exporting' });

            const currentExportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`);
            await exportMessages(job, currentExportData);

            await Export.complete(account, exportId);

            // The export is complete and persisted. A failure while reading final stats or delivering
            // the completion webhook must NOT fall through to the job catch below, which would delete
            // the finished file and mark the export as failed.
            try {
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
            } catch (notifyErr) {
                logger.error({ msg: 'Failed to deliver export completion notification', account, exportId, err: notifyErr });
            }

            logger.info({ msg: 'Export job completed', account, exportId, duration: Date.now() - startTime });
        } catch (err) {
            // a user-requested cancellation or a deleted account is not an operational failure
            let failLevel = err.code === 'ExportCancelled' ? 'info' : err.code === 'AccountDeleted' ? 'warn' : 'error';
            logger[failLevel]({ msg: 'Export job failed', account, exportId, err });

            // Tells the 'failed' handler that this failure has already been reported with full
            // context. Failures that never reach this catch (see that handler) have not been.
            job.__failureLogged = true;

            const exportData = await redis.hgetall(`${REDIS_PREFIX}exp:${account}:${exportId}`).catch(() => ({}));

            await Export.removeFile(exportId, exportData);

            if (err.code === 'ExportCancelled') {
                await Export.deleteFully(account, exportId);
            } else {
                await Export.fail(account, exportId, err.message);
            }

            if (err.code !== 'AccountDeleted' && err.code !== 'AccountNotFound' && err.code !== 'ExportCancelled') {
                try {
                    await notify(account, EXPORT_FAILED_NOTIFY, {
                        exportId,
                        error: err.message,
                        errorCode: err.code,
                        phase: exportData.phase || 'unknown',
                        messagesExported: Number(exportData.messagesExported) || 0,
                        messagesQueued: Number(exportData.messagesQueued) || 0
                    });
                } catch (notifyErr) {
                    // Never let a failed notification replace the original error below.
                    logger.error({ msg: 'Failed to deliver export failure notification', account, exportId, err: notifyErr });
                }
            }

            throw err;
        }
    },
    {
        concurrency: EXPORT_QC,
        lockDuration: 10 * 60 * 1000,
        stalledInterval: 2 * 60 * 1000,
        maxStalledCount: 5,
        // Do not start consuming jobs at construction. Startup recovery (markInterruptedAsFailed +
        // cleanup) must finish first, otherwise the worker can pick up a queued export and start
        // processing it while recovery concurrently marks that same export failed and deletes its
        // file. run() is called from the startup IIFE once recovery completes.
        autorun: false,
        ...queueConf
    }
);

logBullErrors(exportWorker, 'worker:export');

exportWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', { queue: 'export', status: 'completed' });
    logger.debug({ msg: 'Export queue entry completed', queue: job.queue.name, job: job.id, account: job.data.account, exportId: job.data.exportId });
});

exportWorker.on('failed', async (job, err) => {
    metrics(logger, 'queuesProcessed', 'inc', { queue: 'export', status: 'failed' });
    if (!job) {
        logger.error({ msg: 'Export queue entry failed', err });
        return;
    }
    // A stalled job (worker killed mid-export, lock lost) is failed by BullMQ through its
    // deferred-failure path, which skips the processor entirely - so its catch never logged the
    // failure and never ran Export.fail(). That leaves a dead export recoverable only by the
    // startup pass, and this event is the sole record of it. Anything the processor did report is
    // demoted to debug to avoid logging the same failure twice.
    let level = job.__failureLogged ? 'debug' : 'error';
    logger[level]({
        msg: 'Export queue entry failed',
        queue: job.queue.name,
        job: job.id,
        account: job.data.account,
        exportId: job.data.exportId,
        failedReason: job.failedReason,
        reachedProcessor: !!job.__failureLogged
    });
});

async function onCommand(command) {
    if (command.cmd === 'resource-usage') {
        return threadStats.usage();
    }

    // Shutdown drain, forwarded by server.js because signals only reach the main thread
    if (command.cmd === 'close') {
        await exportWorker.close();
        return true;
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

    try {
        const cleaned = await Export.cleanup();
        if (cleaned > 0) {
            logger.info({ msg: 'Cleaned up orphaned export files', count: cleaned });
        }
    } catch (err) {
        logger.error({ msg: 'Failed to clean up export files', err });
    }

    // Now that interrupted exports have been reconciled and orphaned files cleaned, start consuming
    // jobs. A fatal run() failure leaves a thread that keeps sending heartbeats while consuming
    // nothing, so it exits instead and the main process respawns it. (Re-emitting it as an 'error'
    // event did not crash anything: BullMQ catches an unlistened 'error' and prints it.)
    exportWorker.run().catch(err => {
        logger.fatal({ msg: 'Export queue processing stopped, exiting worker', err });
        logger.flush(() => process.exit(1));
    });

    setInterval(() => {
        try {
            parentPort.postMessage({ cmd: 'heartbeat' });
        } catch {
            // Ignore errors, parent might be shutting down
        }
    }, 10 * 1000).unref();

    setInterval(
        async () => {
            try {
                // The set key, the entry encoding and the export key all come from lib/export.js.
                // Hand-building them here meant this cleanup and the limiter that writes the
                // entries could drift apart: entries added under one encoding and removed under
                // another leave the active set growing forever, and once it reaches the global
                // limit every export in the deployment is refused with 429.
                const activeExports = await redis.smembers(ACTIVE_EXPORTS_KEY);
                for (const entry of activeExports) {
                    const parsed = parseActiveEntry(entry);
                    if (!parsed) continue;
                    const exists = await redis.exists(getExportKey(parsed.account, parsed.exportId));
                    if (!exists) {
                        await redis.srem(ACTIVE_EXPORTS_KEY, entry);
                        logger.info({ msg: 'Cleaned stale active set entry', account: parsed.account, exportId: parsed.exportId });
                    }
                }
            } catch (err) {
                logger.error({ msg: 'Failed to clean stale active set entries', err });
            }
        },
        5 * 60 * 1000
    ).unref();

    // Periodically remove export files whose Redis state has already expired. Without this, files of
    // expired exports would only be reclaimed on the next worker restart.
    setInterval(
        async () => {
            try {
                const cleaned = await Export.cleanup();
                if (cleaned > 0) {
                    logger.info({ msg: 'Cleaned up orphaned export files', count: cleaned });
                }
            } catch (err) {
                logger.error({ msg: 'Failed to clean up export files', err });
            }
        },
        60 * 60 * 1000
    ).unref();

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

logger.info({ msg: 'Started Export worker thread', version: packageData.version });
