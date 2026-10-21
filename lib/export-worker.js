'use strict';

// The work an export job does: index the messages of the requested folders into the export's
// pending set, then fetch and write them out. Moved out of workers/export.js, where nothing could be
// tested without booting the BullMQ worker; the worker builds this with its own collaborators, a
// test with fakes.

const defaultLogger = require('./logger');
const { REDIS_PREFIX, DEFAULT_EXPORT_MAX_MESSAGE_SIZE, DEFAULT_EXPORT_MAX_MESSAGES, DEFAULT_EXPORT_MAX_SIZE } = require('./consts');
const {
    Export: DefaultExport,
    isTransientError,
    isSkippableError,
    isFolderMissingError,
    isRetryableError,
    resolveExportLimit,
    isExportLimitReached,
    exportFilePath,
    openExportOutput: defaultOpenExportOutput
} = require('./export');

const BATCH_SIZE = 100;
const LIST_PAGE_SIZE = 1000;
const FOLDER_INDEX_MAX_RETRIES = 3;
const FOLDER_INDEX_RETRY_DELAY_MS = 1000;

const IMAP_MESSAGE_MAX_RETRIES = 3;
const IMAP_MESSAGE_RETRY_BASE_DELAY = 2000;
const ACCOUNT_CHECK_INTERVAL = 60 * 1000;
const LOCK_EXTENSION_INTERVAL = 5 * 60 * 1000;

const MESSAGE_FETCH_BATCH_SIZE = 10; // Batch size for parallel message fetching
const MAX_BATCH_RETRIES = 5; // Max retries for rate-limited or transient per-message errors within a batch
const BATCH_RETRY_BASE_DELAY = 5000; // Base delay for batch retry backoff (5 seconds)

const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function cancelledError() {
    const err = new Error('Export cancelled by user');
    err.code = 'ExportCancelled';
    return err;
}

/**
 * Picks the folders an export covers: the requested ones (special-use names resolved), or, when
 * none were requested, \All where the account has one and every folder but Junk and Trash otherwise
 * @param {string[]} folders - Requested folders
 * @param {Object[]} mailboxes - The account's folder listing
 * @returns {string[]} Folder paths
 */
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

/**
 * Resolves a stream of writes into the export file, waiting for drain when the gzip stream asks
 * @param {Object} output - From openExportOutput()
 * @returns {Function} Writes one string, resolves when it may write the next
 */
function createBackpressureWriter(output) {
    const gzipStream = output.input;
    return function writeWithBackpressure(data) {
        if (output.error()) {
            return Promise.reject(output.error());
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
    };
}

/**
 * Ends the export file and waits for it to be written out
 * @param {Object} output - From openExportOutput()
 */
function finalizeOutput(output) {
    const FINALIZATION_TIMEOUT = 30000;
    return new Promise((resolve, reject) => {
        if (output.error()) {
            // The chain already failed and pipeline() tore it down, so no 'finish' or 'error'
            // is coming; waiting would only run out the timeout
            output.destroy();
            return reject(output.error());
        }
        const timeout = setTimeout(() => {
            output.destroy();
            reject(output.error() || new Error('Stream finalization timed out'));
        }, FINALIZATION_TIMEOUT);
        output.input.end();
        output.output.once('finish', () => {
            clearTimeout(timeout);
            resolve();
        });
        output.output.once('error', err => {
            clearTimeout(timeout);
            reject(output.error() || err);
        });
    });
}

// One field is enough to tell whether the account still exists; reading the whole hash was not
const accountExists = async (redis, account) => (await redis.hexists(`${REDIS_PREFIX}iad:${account}`, 'account')) === 1;

/**
 * @param {Object} deps
 * @param {Object} deps.redis - ioredis client
 * @param {Function} deps.createAccount - (account) => Promise<Account>
 * @param {Function} deps.getSecret - Resolves the encryption secret
 * @param {Object} deps.settings - lib/settings
 * @param {Object} [deps.logger]
 * @param {Object} [deps.Export] - lib/export Export class
 * @param {Function} [deps.openExportOutput]
 * @param {Function} [deps.sleep] - Waits the given milliseconds
 * @param {Function} [deps.now] - Current time in ms
 * @returns {{ indexMessages: Function, indexFolder: Function, exportMessages: Function, createLeaseExtender: Function }}
 */
function createExportJobs(deps) {
    const { redis, createAccount, getSecret, settings } = deps;
    const logger = deps.logger || defaultLogger;
    const Export = deps.Export || DefaultExport;
    const openExportOutput = deps.openExportOutput || defaultOpenExportOutput;
    const sleep = deps.sleep || defaultSleep;
    const now = deps.now || Date.now;

    // Returns a throttled callback that extends both the BullMQ job lock and the export's Redis key
    // expiry on the LOCK_EXTENSION_INTERVAL cadence. Long-running indexing/exporting loops call it
    // freely; the lock/expiry are refreshed at most once per interval. Without this the lock could lapse
    // (stalling and reprocessing the job) and the export keys could expire mid-run.
    function createLeaseExtender(job, account, exportId) {
        let lastExtension = now();
        return async function maybeExtendLease() {
            if (now() - lastExtension <= LOCK_EXTENSION_INTERVAL) {
                return;
            }
            await Promise.all([
                job.extendLock(job.token, 10 * 60 * 1000).catch(err => {
                    logger.warn({ msg: 'Failed to extend job lock', account, exportId, err });
                }),
                Export.extendExpiry(account, exportId).catch(err => {
                    logger.warn({ msg: 'Failed to extend export expiry', account, exportId, err });
                })
            ]);
            lastExtension = now();
        };
    }

    async function indexFolder(accountObject, account, exportId, folderPath, startDate, endDate, indexingStartTime, maxMessages) {
        let cursor = null;
        let queued = 0;

        while (true) {
            const searchCriteria = { since: startDate };
            if (endDate < indexingStartTime) {
                searchCriteria.before = endDate;
            }

            const listOptions = {
                path: folderPath,
                pageSize: LIST_PAGE_SIZE,
                search: searchCriteria,
                metadataOnly: true,
                cursor
            };

            let result;
            try {
                result = await accountObject.listMessages(listOptions);
            } catch (err) {
                // Other errors (e.g. a deleted account) propagate
                if (isFolderMissingError(err)) {
                    // The folder disappeared mid-export - treat it as empty instead of failing the export
                    logger.warn({ msg: 'Export folder was not found, skipping', account, exportId, folder: folderPath, err });
                    return queued;
                }
                throw err;
            }

            // A page at a time, in one pipeline, up to what the message limit leaves
            let page = result.messages || [];
            if (maxMessages) {
                page = page.slice(0, Math.max(maxMessages - queued, 0));
            }
            await Export.queueMessages(
                account,
                exportId,
                page.map(msg => ({
                    folder: folderPath,
                    messageId: msg.id || msg.emailId,
                    uid: msg.uid,
                    size: msg.size || 0,
                    date: msg.date ? new Date(msg.date).getTime() : Date.now()
                }))
            );
            queued += page.length;

            if (maxMessages && queued >= maxMessages) {
                return queued;
            }

            cursor = result.nextPageCursor;
            if (!cursor) {
                break;
            }
        }

        return queued;
    }

    async function indexFolderWithRetries(accountObject, job, folderPath, range, remaining) {
        const { account, exportId } = job.data;
        let attempt = 0;
        while (true) {
            try {
                return await indexFolder(accountObject, account, exportId, folderPath, range.startDate, range.endDate, range.indexingStartTime, remaining);
            } catch (err) {
                attempt++;
                // A folder that was deleted mid-export is handled inside indexFolder (treated as empty),
                // so any error reaching here is a real failure. Only transient errors are worth retrying;
                // a permanent error (deleted account, auth failure, unexpected server response) is not
                // specific to this folder and would repeat for the rest, so fail the whole export. Silently
                // skipping folders and marking an incomplete export "completed" hides data loss from the caller.
                if (!isTransientError(err) || attempt >= FOLDER_INDEX_MAX_RETRIES) {
                    logger.error({
                        msg: 'Failed to index folder, failing export',
                        account,
                        exportId,
                        folder: folderPath,
                        attempts: attempt,
                        err
                    });
                    err.message = `Failed to index folder "${folderPath}": ${err.message}`;
                    throw err;
                }

                const delay = FOLDER_INDEX_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                logger.warn({
                    msg: 'Folder indexing failed, retrying',
                    account,
                    exportId,
                    folder: folderPath,
                    attempt,
                    maxRetries: FOLDER_INDEX_MAX_RETRIES,
                    delayMs: delay,
                    err
                });
                await sleep(delay);
            }
        }
    }

    async function indexMessages(job, exportData) {
        const { account, exportId } = job.data;
        const folders = JSON.parse(exportData.folders || '[]');
        const range = {
            startDate: new Date(Number(exportData.startDate)),
            endDate: new Date(Number(exportData.endDate)),
            indexingStartTime: new Date()
        };

        if (!(await accountExists(redis, account))) {
            const err = new Error('Account not found or has been deleted');
            err.code = 'AccountNotFound';
            err.statusCode = 404;
            throw err;
        }

        const accountObject = await createAccount(account);

        let mailboxes;
        try {
            mailboxes = await accountObject.listMailboxes();
        } catch (err) {
            throw new Error(`Failed to list mailboxes: ${err.message}`, { cause: err });
        }

        const foldersToProcess = resolveFolders(folders, mailboxes);

        await Export.update(account, exportId, { foldersTotal: foldersToProcess.length });

        const maxMessages = resolveExportLimit(await settings.get('exportMaxMessages'), DEFAULT_EXPORT_MAX_MESSAGES);

        logger.info({ msg: 'Starting export indexing', account, exportId, foldersToProcess: foldersToProcess.length, maxMessages: maxMessages || 'unlimited' });

        let totalIndexed = 0;
        let truncated = false;
        const maybeExtendLease = createLeaseExtender(job, account, exportId);

        for (let i = 0; i < foldersToProcess.length; i++) {
            await maybeExtendLease();

            if (await Export.isCancelled(account, exportId)) {
                throw cancelledError();
            }

            const folderPath = foldersToProcess[i];
            const remaining = maxMessages ? maxMessages - totalIndexed : 0;
            totalIndexed += await indexFolderWithRetries(accountObject, job, folderPath, range, remaining);

            logger.trace({
                msg: 'Folder indexed',
                account,
                exportId,
                folder: folderPath,
                foldersScanned: i + 1,
                foldersTotal: foldersToProcess.length,
                totalIndexed
            });

            // The folder indexed successfully (failures throw above); count it toward progress.
            await Export.update(account, exportId, { foldersScanned: i + 1 });

            if (isExportLimitReached(totalIndexed, maxMessages)) {
                truncated = true;
                logger.warn({
                    msg: 'Export indexing truncated: message limit reached',
                    account,
                    exportId,
                    totalIndexed,
                    limit: maxMessages
                });
                break;
            }
        }

        if (truncated) {
            await Export.update(account, exportId, { truncated: '1' });
        }
    }

    // What one export run writes and where it stands, shared by the steps below
    function createRun(job, exportData, accountObject, output, limits) {
        const { account, exportId } = job.data;
        const rawMaxBytes = Number(exportData.maxBytes);
        return {
            account,
            exportId,
            accountObject,
            output,
            limits,
            includeAttachments: exportData.includeAttachments === '1',
            textType: exportData.textType || '*',
            // Preserve an explicit 0 ("unlimited" per the API contract); only fall back when unset/invalid.
            maxBytes: Number.isFinite(rawMaxBytes) ? rawMaxBytes : 5 * 1024 * 1024,
            write: createBackpressureWriter(output),
            // Progress not yet written to the export record, see flushCounters()
            counts: { exported: 0, bytesWritten: 0, skipped: 0 },
            processed: 0,
            totalBytesWritten: 0,
            sizeLimitReached: false,
            lastAccountCheck: now(),
            // Refreshes the job lock and export key expiry on a fixed cadence; called from the main loop and
            // from inside the retry backoff so a batch stuck retrying does not let the lock lapse.
            maybeExtendLease: createLeaseExtender(job, account, exportId)
        };
    }

    async function loadAttachments(run, message) {
        const maxMessageSize = run.limits.maxMessageSize;
        for (const attachment of message.attachments) {
            try {
                if (attachment.size && attachment.size > maxMessageSize) {
                    attachment.contentError = `Attachment too large (${attachment.size} bytes, limit ${maxMessageSize})`;
                    continue;
                }

                const stream = await run.accountObject.getAttachment(attachment.id);
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

    async function processMessage(run, message, entry) {
        message.path = entry.folder;

        if (run.includeAttachments && message.attachments && message.attachments.length) {
            await loadAttachments(run, message);
        }

        const line = JSON.stringify(message) + '\n';
        await run.write(line);
        const lineBytes = Buffer.byteLength(line);
        run.totalBytesWritten += lineBytes;

        run.counts.exported++;
        run.counts.bytesWritten += lineBytes;
        run.processed++;
    }

    async function skipEntry(run, entry, reason) {
        logger.warn({
            msg: 'Skipping message during export',
            account: run.account,
            exportId: run.exportId,
            messageId: entry.messageId,
            folder: entry.folder,
            reason
        });
        run.counts.skipped++;
    }

    // Writes the progress counted since the last call, once per batch instead of once per message
    async function flushCounters(run) {
        const counts = run.counts;
        if (!counts.exported && !counts.skipped) {
            return;
        }
        run.counts = { exported: 0, bytesWritten: 0, skipped: 0 };
        await Export.incrementCounters(run.account, run.exportId, counts);
    }

    // Writes a fetched message and reports whether the size limit stops the export
    async function writeAndCheckLimit(run, message, entry) {
        await processMessage(run, message, entry);
        if (isExportLimitReached(run.totalBytesWritten, run.limits.maxExportSize)) {
            run.sizeLimitReached = true;
        }
        return run.sizeLimitReached;
    }

    // One getMessages() round for a chunk of entries. Returns the entries worth another round
    async function fetchApiChunkOnce(run, fetchBatch, batchRetry) {
        const messageIds = fetchBatch.map(e => e.messageId);
        const messageResults = await run.accountObject.getMessages(messageIds, { textType: run.textType, maxBytes: run.maxBytes });

        const resultMap = new Map();
        for (const result of messageResults) {
            resultMap.set(result.messageId, result);
        }

        const retryEntries = [];

        for (const entry of fetchBatch) {
            const result = resultMap.get(entry.messageId);

            if (result && result.error) {
                const err = result.error;
                // A single transient blip (rate limit, dropped batch response, network/5xx)
                // must not fail an entire multi-message export; only give up once the retry
                // budget is exhausted. See isRetryableError for the full classification.
                const isRetryable = isRetryableError(err);

                if (isSkippableError(err)) {
                    await skipEntry(run, entry, err.message || err.code);
                } else if (isRetryable && batchRetry < MAX_BATCH_RETRIES) {
                    retryEntries.push(entry);
                } else {
                    const error = new Error(err.message);
                    error.code = err.code;
                    error.statusCode = err.statusCode;
                    throw error;
                }
            } else if (result && result.data) {
                if (await writeAndCheckLimit(run, result.data, entry)) {
                    return [];
                }
            } else {
                await skipEntry(run, entry, 'Message not found in batch results');
            }
        }

        return retryEntries;
    }

    async function fetchApiChunk(run, chunk) {
        let fetchBatch = chunk;
        let batchRetry = 0;

        while (fetchBatch.length > 0) {
            const retryEntries = await fetchApiChunkOnce(run, fetchBatch, batchRetry);

            if (run.sizeLimitReached || retryEntries.length === 0) {
                return;
            }

            batchRetry++;
            const delay = BATCH_RETRY_BASE_DELAY * Math.pow(2, batchRetry - 1) + Math.random() * 1000;
            logger.warn({
                msg: 'Retrying failed messages during export batch',
                account: run.account,
                exportId: run.exportId,
                retryCount: retryEntries.length,
                attempt: batchRetry,
                maxAttempts: MAX_BATCH_RETRIES,
                delayMs: Math.round(delay)
            });
            await sleep(delay);
            await run.maybeExtendLease();
            fetchBatch = retryEntries;
        }
    }

    async function fetchApiEntries(run, entriesToFetch) {
        for (let i = 0; i < entriesToFetch.length; i += MESSAGE_FETCH_BATCH_SIZE) {
            if (run.output.error()) {
                throw run.output.error();
            }
            if (run.sizeLimitReached) {
                break;
            }

            // Per chunk, not only per batch of entries: one batch can outlast the lock
            await run.maybeExtendLease();

            await fetchApiChunk(run, entriesToFetch.slice(i, i + MESSAGE_FETCH_BATCH_SIZE));
        }
    }

    // Fetches one message, retrying transient failures. Resolves { message } or, for a message that
    // is gone, { skipped }; any other failure is thrown
    async function fetchImapMessage(run, entry) {
        let fetchError = null;
        for (let attempt = 1; attempt <= IMAP_MESSAGE_MAX_RETRIES; attempt++) {
            // Per attempt: a fetch can take up to EXPORT_TIMEOUT, so a batch of entries
            // with retries ran well past the 10 minute lock, and BullMQ started a second
            // run of the same export while this one was still writing
            await run.maybeExtendLease();
            try {
                return { message: await run.accountObject.getMessage(entry.messageId, { textType: run.textType, maxBytes: run.maxBytes }) };
            } catch (err) {
                if (isSkippableError(err)) {
                    return { skipped: err };
                }

                if (isTransientError(err) && attempt < IMAP_MESSAGE_MAX_RETRIES) {
                    const delay = IMAP_MESSAGE_RETRY_BASE_DELAY * Math.pow(2, attempt - 1);
                    logger.warn({
                        msg: 'Message fetch failed, retrying',
                        account: run.account,
                        exportId: run.exportId,
                        messageId: entry.messageId,
                        folder: entry.folder,
                        attempt,
                        maxAttempts: IMAP_MESSAGE_MAX_RETRIES,
                        delayMs: delay,
                        err
                    });
                    await sleep(delay);
                    continue;
                }

                fetchError = err;
                break;
            }
        }
        throw fetchError;
    }

    async function fetchImapEntries(run, entriesToFetch) {
        for (const entry of entriesToFetch) {
            if (run.output.error()) {
                throw run.output.error();
            }

            const { message, skipped } = await fetchImapMessage(run, entry);

            if (skipped) {
                await skipEntry(run, entry, skipped.message || skipped.code);
            } else if (message && (await writeAndCheckLimit(run, message, entry))) {
                break;
            }
        }
    }

    // Checks made before each batch: cancelled by the user, or the account deleted meanwhile
    async function checkRunStillWanted(run) {
        if (await Export.isCancelled(run.account, run.exportId)) {
            throw cancelledError();
        }

        if (now() - run.lastAccountCheck > ACCOUNT_CHECK_INTERVAL) {
            if (!(await accountExists(redis, run.account))) {
                const err = new Error('Account was deleted during export');
                err.code = 'AccountDeleted';
                throw err;
            }
            run.lastAccountCheck = now();
        }
    }

    async function processBatches(run, isApiAccount) {
        while (true) {
            if (run.output.error()) {
                throw run.output.error();
            }

            if (run.sizeLimitReached) {
                break;
            }

            await run.maybeExtendLease();
            await checkRunStillWanted(run);

            const batch = await Export.getNextBatch(run.account, run.exportId, BATCH_SIZE);
            if (batch.length === 0) {
                break;
            }

            const entriesToFetch = [];
            for (const entry of batch) {
                if (run.includeAttachments && entry.size > run.limits.maxMessageSize) {
                    run.counts.skipped++;
                } else {
                    entriesToFetch.push(entry);
                }
            }

            if (entriesToFetch.length === 0) {
                await flushCounters(run);
                continue;
            }

            if (isApiAccount && entriesToFetch.length > 1) {
                await fetchApiEntries(run, entriesToFetch);
            } else {
                await fetchImapEntries(run, entriesToFetch);
            }
            await flushCounters(run);

            logger.trace({ msg: 'Export batch processed', account: run.account, exportId: run.exportId, messagesExported: run.processed });
        }
    }

    async function exportMessages(job, exportData) {
        const { account, exportId } = job.data;
        // Derived from the id like every other reader of the record, never the stored path as such
        const filePath = exportFilePath(exportId, exportData);
        const { exportMaxMessageSize, exportMaxSize } = await settings.getMulti('exportMaxMessageSize', 'exportMaxSize');
        const limits = {
            maxMessageSize: resolveExportLimit(exportMaxMessageSize, DEFAULT_EXPORT_MAX_MESSAGE_SIZE),
            maxExportSize: resolveExportLimit(exportMaxSize, DEFAULT_EXPORT_MAX_SIZE)
        };
        const isEncrypted = exportData.isEncrypted === '1';

        const accountObject = await createAccount(account);

        // Everything that can fail before the export starts writing runs before the output file is
        // opened: a failure here used to leave the file descriptor (and the unlinked file's disk space)
        // held for the life of the worker.
        const accountData = await accountObject.loadAccountData(account);
        const isApiAccount = await accountObject.isApiClient(accountData);

        const output = await openExportOutput(filePath, isEncrypted ? await getSecret() : null);
        const run = createRun(job, exportData, accountObject, output, limits);

        let processingError = null;
        try {
            await processBatches(run, isApiAccount);
        } catch (err) {
            processingError = err;
        }

        // What a failed batch got through before the failure still counts
        try {
            await flushCounters(run);
        } catch (err) {
            processingError = processingError || err;
        }

        await finalizeOutput(output);

        if (processingError) {
            throw processingError;
        }
        if (output.error()) {
            throw output.error();
        }

        // Written after the file is closed, so a failure here cannot leave the streams open
        if (run.sizeLimitReached) {
            logger.warn({
                msg: 'Export truncated: size limit reached',
                account,
                exportId,
                totalBytesWritten: run.totalBytesWritten,
                limit: limits.maxExportSize,
                messagesExported: run.processed
            });
            await Export.update(account, exportId, { truncated: '1' });
        }

        logger.info({ msg: 'Export messages completed', account, exportId, messagesExported: run.processed, bytesWritten: run.totalBytesWritten });
    }

    return { indexMessages, indexFolder, exportMessages, createLeaseExtender };
}

module.exports = {
    createExportJobs,
    resolveFolders,
    BATCH_SIZE,
    LIST_PAGE_SIZE,
    MESSAGE_FETCH_BATCH_SIZE,
    LOCK_EXTENSION_INTERVAL,
    IMAP_MESSAGE_MAX_RETRIES
};
