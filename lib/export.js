'use strict';

const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const pathlib = require('path');
const msgpack = require('msgpack5')();
const { redis, exportQueue, queueConf } = require('./db');
const settings = require('./settings');
const logger = require('./logger');

const {
    REDIS_PREFIX,
    DEFAULT_EXPORT_MAX_AGE,
    DEFAULT_EXPORT_MAX_SIZE,
    DEFAULT_EXPORT_MAX_MESSAGES,
    DEFAULT_EXPORT_MAX_CONCURRENT,
    DEFAULT_EXPORT_MAX_MESSAGE_SIZE
} = require('./consts');

// Export ID prefix
const EXPORT_ID_PREFIX = 'exp_';

/**
 * Generate a unique export ID
 * @returns {string} Export ID like "exp_abc123def456"
 */
function generateExportId() {
    return EXPORT_ID_PREFIX + crypto.randomBytes(12).toString('hex');
}

/**
 * Get Redis key for export metadata
 * @param {string} account - Account ID
 * @param {string} exportId - Export ID
 * @returns {string} Redis key
 */
function getExportKey(account, exportId) {
    return `${REDIS_PREFIX}exp:${account}:${exportId}`;
}

/**
 * Get Redis key for export message queue (sorted set)
 * @param {string} account - Account ID
 * @param {string} exportId - Export ID
 * @returns {string} Redis key
 */
function getExportQueueKey(account, exportId) {
    return `${REDIS_PREFIX}exq:${account}:${exportId}`;
}

/**
 * Get the export directory path
 * @returns {Promise<string>} Export directory path
 */
async function getExportPath() {
    return (await settings.get('exportPath')) || process.env.EENGINE_EXPORT_PATH || os.tmpdir();
}

/**
 * Get export max age in ms
 * @returns {Promise<number>} Max age in ms
 */
async function getExportMaxAge() {
    const maxAge = await settings.get('exportMaxAge');
    if (maxAge && !isNaN(maxAge)) {
        return Number(maxAge);
    }
    if (process.env.EENGINE_EXPORT_MAX_AGE && !isNaN(process.env.EENGINE_EXPORT_MAX_AGE)) {
        return Number(process.env.EENGINE_EXPORT_MAX_AGE);
    }
    return DEFAULT_EXPORT_MAX_AGE;
}

/**
 * Export class for managing bulk message exports
 */
class Export {
    /**
     * Create a new export job
     * @param {string} account - Account ID
     * @param {Object} options - Export options
     * @param {string[]} options.folders - Folders to export
     * @param {Date|string} options.startDate - Start date
     * @param {Date|string} options.endDate - End date
     * @param {string} options.textType - Text type to include
     * @param {number} options.maxBytes - Max bytes for text content
     * @param {boolean} options.includeAttachments - Include attachment content
     * @returns {Promise<Object>} Created export info
     */
    static async create(account, options) {
        const exportId = generateExportId();
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        const maxAge = await getExportMaxAge();
        const exportPath = await getExportPath();
        const now = Date.now();
        const expiresAt = now + maxAge;

        // Check concurrent export limit
        const maxConcurrent = (await settings.get('exportMaxConcurrent')) || DEFAULT_EXPORT_MAX_CONCURRENT;
        const activeExports = await Export.listActive(account);
        if (activeExports.length >= maxConcurrent) {
            const err = new Error('Maximum concurrent exports reached');
            err.code = 'TooManyExports';
            err.statusCode = 429;
            throw err;
        }

        // Ensure export directory exists
        try {
            await fs.promises.mkdir(exportPath, { recursive: true });
        } catch (err) {
            // Ignore if already exists
        }

        const filePath = pathlib.join(exportPath, `${exportId}.ndjson.gz`);

        // Parse dates
        const startDate = options.startDate instanceof Date ? options.startDate.getTime() : new Date(options.startDate).getTime();
        const endDate = options.endDate instanceof Date ? options.endDate.getTime() : new Date(options.endDate).getTime();

        // Store export metadata
        const exportData = {
            exportId,
            account,
            status: 'queued',
            phase: 'pending',
            folders: JSON.stringify(options.folders || []),
            startDate,
            endDate,
            textType: options.textType || '*',
            maxBytes: options.maxBytes || 5 * 1024 * 1024,
            includeAttachments: options.includeAttachments ? '1' : '0',
            foldersScanned: 0,
            foldersTotal: 0,
            messagesQueued: 0,
            messagesExported: 0,
            messagesSkipped: 0,
            bytesWritten: 0,
            filePath,
            lastProcessedScore: 0,
            created: now,
            expiresAt,
            error: ''
        };

        const ttl = Math.ceil(maxAge / 1000);

        // Store metadata with TTL
        await redis.multi().hmset(exportKey, exportData).expire(exportKey, ttl).sadd(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`).exec();

        // Add job to BullMQ queue
        await exportQueue.add(
            'export',
            {
                account,
                exportId
            },
            {
                jobId: exportId,
                removeOnComplete: true,
                removeOnFail: true
            }
        );

        logger.info({
            msg: 'Export job created',
            account,
            exportId,
            folders: options.folders,
            startDate: new Date(startDate).toISOString(),
            endDate: new Date(endDate).toISOString()
        });

        return {
            exportId,
            status: 'queued',
            created: new Date(now).toISOString()
        };
    }

    /**
     * Get export status
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @returns {Promise<Object|null>} Export status or null if not found
     */
    static async get(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const data = await redis.hgetall(exportKey);

        if (!data || !data.exportId) {
            return null;
        }

        return Export.formatStatus(data);
    }

    /**
     * Format raw Redis data to status response
     * @param {Object} data - Raw Redis hash data
     * @returns {Object} Formatted status
     */
    static formatStatus(data) {
        return {
            exportId: data.exportId,
            status: data.status,
            phase: data.phase !== 'pending' ? data.phase : undefined,
            folders: data.folders ? JSON.parse(data.folders) : [],
            startDate: data.startDate ? new Date(Number(data.startDate)).toISOString() : undefined,
            endDate: data.endDate ? new Date(Number(data.endDate)).toISOString() : undefined,
            progress: {
                foldersScanned: Number(data.foldersScanned) || 0,
                foldersTotal: Number(data.foldersTotal) || 0,
                messagesQueued: Number(data.messagesQueued) || 0,
                messagesExported: Number(data.messagesExported) || 0,
                messagesSkipped: Number(data.messagesSkipped) || 0,
                bytesWritten: Number(data.bytesWritten) || 0
            },
            created: data.created ? new Date(Number(data.created)).toISOString() : undefined,
            expiresAt: data.expiresAt ? new Date(Number(data.expiresAt)).toISOString() : undefined,
            error: data.error || null
        };
    }

    /**
     * List exports for an account
     * @param {string} account - Account ID
     * @param {Object} options - List options
     * @param {number} options.page - Page number (0-indexed)
     * @param {number} options.pageSize - Page size
     * @returns {Promise<Object>} Paginated export list
     */
    static async list(account, options = {}) {
        const page = Number(options.page) || 0;
        const pageSize = Number(options.pageSize) || 20;

        // Get all export keys for this account
        const pattern = `${REDIS_PREFIX}exp:${account}:${EXPORT_ID_PREFIX}*`;
        const keys = await redis.keys(pattern);

        // Sort by creation time (newest first)
        const exports = [];
        for (const key of keys) {
            const data = await redis.hgetall(key);
            if (data && data.exportId) {
                exports.push({
                    exportId: data.exportId,
                    status: data.status,
                    created: data.created ? new Date(Number(data.created)).toISOString() : undefined,
                    expiresAt: data.expiresAt ? new Date(Number(data.expiresAt)).toISOString() : undefined
                });
            }
        }

        // Sort by created date descending
        exports.sort((a, b) => new Date(b.created) - new Date(a.created));

        const total = exports.length;
        const pages = Math.ceil(total / pageSize) || 1;
        const start = page * pageSize;
        const end = start + pageSize;

        return {
            total,
            page,
            pages,
            exports: exports.slice(start, end)
        };
    }

    /**
     * List active exports for an account
     * @param {string} account - Account ID
     * @returns {Promise<string[]>} Array of export IDs
     */
    static async listActive(account) {
        const activeSet = await redis.smembers(`${REDIS_PREFIX}exp:active`);
        const accountPrefix = `${account}:`;
        return activeSet.filter(entry => entry.startsWith(accountPrefix)).map(entry => entry.substring(accountPrefix.length));
    }

    /**
     * Delete an export
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @returns {Promise<boolean>} True if deleted
     */
    static async delete(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        // Get file path before deleting
        const data = await redis.hgetall(exportKey);
        if (!data || !data.exportId) {
            return false;
        }

        // Remove from BullMQ queue if still pending
        try {
            const job = await exportQueue.getJob(exportId);
            if (job) {
                await job.remove();
            }
        } catch (err) {
            // Job may not exist
        }

        // Delete Redis keys
        await redis.multi().del(exportKey).del(queueKey).srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`).exec();

        // Delete file if exists
        if (data.filePath) {
            try {
                await fs.promises.unlink(data.filePath);
            } catch (err) {
                // File may not exist
            }
        }

        logger.info({
            msg: 'Export deleted',
            account,
            exportId
        });

        return true;
    }

    /**
     * Update export status
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {Object} updates - Fields to update
     * @returns {Promise<void>}
     */
    static async update(account, exportId, updates) {
        const exportKey = getExportKey(account, exportId);
        if (Object.keys(updates).length > 0) {
            await redis.hmset(exportKey, updates);
        }
    }

    /**
     * Queue a message for export
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {Object} messageInfo - Message info
     * @param {string} messageInfo.folder - Folder path
     * @param {string} messageInfo.messageId - Message ID
     * @param {number} messageInfo.uid - Message UID
     * @param {number} messageInfo.size - Message size
     * @param {Date|number} messageInfo.date - Message date
     * @returns {Promise<void>}
     */
    static async queueMessage(account, exportId, messageInfo) {
        const queueKey = getExportQueueKey(account, exportId);
        const exportKey = getExportKey(account, exportId);

        // Use message date as score for oldest-first ordering
        const score = messageInfo.date instanceof Date ? messageInfo.date.getTime() : Number(messageInfo.date) || Date.now();

        // Pack message info as base64url string to preserve binary data through Redis
        const value = msgpack
            .encode({
                folder: messageInfo.folder,
                messageId: messageInfo.messageId,
                uid: messageInfo.uid,
                size: messageInfo.size || 0
            })
            .toString('base64url');

        // Add to sorted set and increment counter
        await redis.multi().zadd(queueKey, score, value).hincrby(exportKey, 'messagesQueued', 1).exec();
    }

    /**
     * Get next batch of messages to export
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {number} lastScore - Last processed score
     * @param {number} limit - Batch size
     * @returns {Promise<Array>} Array of message info objects with scores
     */
    static async getNextBatch(account, exportId, lastScore, limit) {
        const queueKey = getExportQueueKey(account, exportId);

        // Use ZRANGEBYSCORE for cursor-based iteration
        const results = await redis.zrangebyscore(queueKey, lastScore, '+inf', 'WITHSCORES', 'LIMIT', 0, limit);

        const messages = [];
        for (let i = 0; i < results.length; i += 2) {
            const value = results[i];
            const score = Number(results[i + 1]);

            try {
                // Decode base64url string back to msgpack data
                const info = msgpack.decode(Buffer.from(value, 'base64url'));
                messages.push({
                    ...info,
                    score
                });
            } catch (err) {
                logger.error({
                    msg: 'Failed to decode message info',
                    account,
                    exportId,
                    err
                });
            }
        }

        return messages;
    }

    /**
     * Increment exported count
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {number} bytesWritten - Bytes written
     * @returns {Promise<void>}
     */
    static async incrementExported(account, exportId, bytesWritten = 0) {
        const exportKey = getExportKey(account, exportId);
        await redis.multi().hincrby(exportKey, 'messagesExported', 1).hincrby(exportKey, 'bytesWritten', bytesWritten).exec();
    }

    /**
     * Increment skipped count
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @returns {Promise<void>}
     */
    static async incrementSkipped(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        await redis.hincrby(exportKey, 'messagesSkipped', 1);
    }

    /**
     * Update last processed score for resumability
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {number} score - Last processed score
     * @returns {Promise<void>}
     */
    static async updateLastProcessedScore(account, exportId, score) {
        const exportKey = getExportKey(account, exportId);
        await redis.hset(exportKey, 'lastProcessedScore', score);
    }

    /**
     * Mark export as complete
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @returns {Promise<void>}
     */
    static async complete(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        await redis
            .multi()
            .hmset(exportKey, {
                status: 'completed',
                phase: 'complete'
            })
            .del(queueKey)
            .srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`)
            .exec();

        logger.info({
            msg: 'Export completed',
            account,
            exportId
        });
    }

    /**
     * Mark export as failed
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @param {string} error - Error message
     * @returns {Promise<void>}
     */
    static async fail(account, exportId, error) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        await redis
            .multi()
            .hmset(exportKey, {
                status: 'failed',
                error: error || 'Unknown error'
            })
            .del(queueKey)
            .srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`)
            .exec();

        logger.error({
            msg: 'Export failed',
            account,
            exportId,
            error
        });
    }

    /**
     * Mark interrupted exports as failed (called on worker startup)
     * @returns {Promise<void>}
     */
    static async markInterruptedAsFailed() {
        const activeExports = await redis.smembers(`${REDIS_PREFIX}exp:active`);

        for (const entry of activeExports) {
            const [account, exportId] = entry.split(':');
            if (!account || !exportId) continue;

            const exportKey = getExportKey(account, exportId);
            const data = await redis.hgetall(exportKey);

            if (data && data.status === 'processing') {
                // Remove job from BullMQ queue to prevent re-processing after restart
                try {
                    const job = await exportQueue.getJob(exportId);
                    if (job) {
                        await job.remove();
                        logger.info({
                            msg: 'Removed interrupted export job from queue',
                            account,
                            exportId
                        });
                    }
                } catch (err) {
                    // Job may not exist or already completed
                    logger.warn({
                        msg: 'Failed to remove interrupted export job from queue',
                        account,
                        exportId,
                        err
                    });
                }

                await Export.fail(account, exportId, 'Export interrupted by application restart');

                // Delete partial file
                if (data.filePath) {
                    try {
                        await fs.promises.unlink(data.filePath);
                    } catch (err) {
                        // File may not exist
                    }
                }
            }
        }
    }

    /**
     * Cleanup expired export files
     * @returns {Promise<number>} Number of files cleaned up
     */
    static async cleanup() {
        const exportPath = await getExportPath();
        let cleaned = 0;

        try {
            const files = await fs.promises.readdir(exportPath);

            for (const file of files) {
                if (!file.startsWith(EXPORT_ID_PREFIX)) continue;

                const exportId = file.split('.')[0];
                // Check if any account has this export
                const pattern = `${REDIS_PREFIX}exp:*:${exportId}`;
                const keys = await redis.keys(pattern);

                if (keys.length === 0) {
                    // Orphaned file, delete it
                    try {
                        await fs.promises.unlink(pathlib.join(exportPath, file));
                        cleaned++;
                        logger.info({
                            msg: 'Cleaned up orphaned export file',
                            file
                        });
                    } catch (err) {
                        logger.error({
                            msg: 'Failed to clean up export file',
                            file,
                            err
                        });
                    }
                }
            }
        } catch (err) {
            logger.error({
                msg: 'Failed to list export directory',
                exportPath,
                err
            });
        }

        return cleaned;
    }

    /**
     * Get export file path for download
     * @param {string} account - Account ID
     * @param {string} exportId - Export ID
     * @returns {Promise<Object|null>} File info or null
     */
    static async getFile(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const data = await redis.hgetall(exportKey);

        if (!data || !data.exportId) {
            return null;
        }

        if (data.status !== 'completed') {
            const err = new Error('Export not completed');
            err.code = 'ExportNotReady';
            err.statusCode = 400;
            throw err;
        }

        if (!data.filePath) {
            const err = new Error('Export file not found');
            err.code = 'FileNotFound';
            err.statusCode = 404;
            throw err;
        }

        // Check if file exists
        try {
            await fs.promises.access(data.filePath, fs.constants.R_OK);
        } catch (err) {
            const error = new Error('Export file not found');
            error.code = 'FileNotFound';
            error.statusCode = 404;
            throw error;
        }

        return {
            filePath: data.filePath,
            filename: `${exportId}.ndjson.gz`
        };
    }
}

module.exports = {
    Export,
    generateExportId,
    getExportKey,
    getExportQueueKey,
    getExportPath,
    getExportMaxAge,
    DEFAULT_EXPORT_MAX_MESSAGE_SIZE
};
