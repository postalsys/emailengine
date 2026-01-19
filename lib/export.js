'use strict';

const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const pathlib = require('path');
const msgpack = require('msgpack5')();
const { redis, exportQueue } = require('./db');
const settings = require('./settings');
const logger = require('./logger');

const { REDIS_PREFIX, DEFAULT_EXPORT_MAX_AGE, DEFAULT_EXPORT_MAX_CONCURRENT, DEFAULT_EXPORT_MAX_MESSAGE_SIZE } = require('./consts');

const EXPORT_ID_PREFIX = 'exp_';

// Lua script for atomic check-and-add of concurrent exports
// This prevents race conditions when multiple export requests arrive simultaneously
const CONCURRENT_CHECK_SCRIPT = `
local activeKey = KEYS[1]
local maxConcurrent = tonumber(ARGV[1])
local accountPrefix = ARGV[2]
local newEntry = ARGV[3]

local members = redis.call('SMEMBERS', activeKey)
local count = 0
for _, member in ipairs(members) do
    if string.sub(member, 1, #accountPrefix) == accountPrefix then
        count = count + 1
    end
end

if count >= maxConcurrent then
    return 0
end

redis.call('SADD', activeKey, newEntry)
return 1
`;

function generateExportId() {
    return EXPORT_ID_PREFIX + crypto.randomBytes(12).toString('hex');
}

// Helper function to scan keys without blocking Redis
async function scanKeys(pattern) {
    const keys = [];
    let cursor = '0';
    do {
        const [nextCursor, batch] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = nextCursor;
        keys.push(...batch);
    } while (cursor !== '0');
    return keys;
}

function getExportKey(account, exportId) {
    return `${REDIS_PREFIX}exp:${account}:${exportId}`;
}

function getExportQueueKey(account, exportId) {
    return `${REDIS_PREFIX}exq:${account}:${exportId}`;
}

async function getExportPath() {
    return (await settings.get('exportPath')) || process.env.EENGINE_EXPORT_PATH || os.tmpdir();
}

async function getExportMaxAge() {
    const settingsMaxAge = await settings.get('exportMaxAge');
    const envMaxAge = process.env.EENGINE_EXPORT_MAX_AGE;

    if (settingsMaxAge && !isNaN(settingsMaxAge)) return Number(settingsMaxAge);
    if (envMaxAge && !isNaN(envMaxAge)) return Number(envMaxAge);
    return DEFAULT_EXPORT_MAX_AGE;
}

function toTimestamp(date) {
    return date instanceof Date ? date.getTime() : new Date(date).getTime();
}

class Export {
    static async create(account, options) {
        const exportId = generateExportId();
        const exportKey = getExportKey(account, exportId);

        const maxAge = await getExportMaxAge();
        const exportPath = await getExportPath();
        const now = Date.now();
        const expiresAt = now + maxAge;

        const maxConcurrent = (await settings.get('exportMaxConcurrent')) || DEFAULT_EXPORT_MAX_CONCURRENT;

        // Atomically check concurrent limit and add to active set
        const activeKey = `${REDIS_PREFIX}exp:active`;
        const accountPrefix = `${account}:`;
        const activeEntry = `${account}:${exportId}`;
        const added = await redis.eval(CONCURRENT_CHECK_SCRIPT, 1, activeKey, maxConcurrent, accountPrefix, activeEntry);

        if (!added) {
            const err = new Error('Maximum concurrent exports reached');
            err.code = 'TooManyExports';
            err.statusCode = 429;
            throw err;
        }

        await fs.promises.mkdir(exportPath, { recursive: true }).catch(() => {});

        const filePath = pathlib.join(exportPath, `${exportId}.ndjson.gz`);
        const startDate = toTimestamp(options.startDate);
        const endDate = toTimestamp(options.endDate);

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

        // Note: SADD already done atomically in Lua script above
        await redis.multi().hmset(exportKey, exportData).expire(exportKey, ttl).exec();

        await exportQueue.add('export', { account, exportId }, { jobId: exportId, removeOnComplete: true, removeOnFail: true });

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

    static async get(account, exportId) {
        const data = await redis.hgetall(getExportKey(account, exportId));
        return data && data.exportId ? Export.formatStatus(data) : null;
    }

    static formatStatus(data) {
        const toIsoDate = value => (value ? new Date(Number(value)).toISOString() : undefined);

        return {
            exportId: data.exportId,
            status: data.status,
            phase: data.phase !== 'pending' ? data.phase : undefined,
            folders: data.folders ? JSON.parse(data.folders) : [],
            startDate: toIsoDate(data.startDate),
            endDate: toIsoDate(data.endDate),
            progress: {
                foldersScanned: Number(data.foldersScanned) || 0,
                foldersTotal: Number(data.foldersTotal) || 0,
                messagesQueued: Number(data.messagesQueued) || 0,
                messagesExported: Number(data.messagesExported) || 0,
                messagesSkipped: Number(data.messagesSkipped) || 0,
                bytesWritten: Number(data.bytesWritten) || 0
            },
            created: toIsoDate(data.created),
            expiresAt: toIsoDate(data.expiresAt),
            error: data.error || null
        };
    }

    static async list(account, options = {}) {
        const page = Number(options.page) || 0;
        const pageSize = Number(options.pageSize) || 20;

        const pattern = `${REDIS_PREFIX}exp:${account}:${EXPORT_ID_PREFIX}*`;
        const keys = await scanKeys(pattern);

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

        exports.sort((a, b) => new Date(b.created) - new Date(a.created));

        const total = exports.length;
        const pages = Math.ceil(total / pageSize) || 1;

        return {
            total,
            page,
            pages,
            exports: exports.slice(page * pageSize, (page + 1) * pageSize)
        };
    }

    static async listActive(account) {
        const activeSet = await redis.smembers(`${REDIS_PREFIX}exp:active`);
        const accountPrefix = `${account}:`;
        return activeSet.filter(entry => entry.startsWith(accountPrefix)).map(entry => entry.substring(accountPrefix.length));
    }

    static async delete(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        const data = await redis.hgetall(exportKey);
        if (!data || !data.exportId) {
            return false;
        }

        const job = await exportQueue.getJob(exportId).catch(() => null);
        if (job) {
            await job.remove().catch(() => {});
        }

        await redis.multi().del(exportKey).del(queueKey).srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`).exec();

        if (data.filePath) {
            await fs.promises.unlink(data.filePath).catch(() => {});
        }

        logger.info({ msg: 'Export deleted', account, exportId });
        return true;
    }

    static async update(account, exportId, updates) {
        if (Object.keys(updates).length > 0) {
            await redis.hmset(getExportKey(account, exportId), updates);
        }
    }

    static async queueMessage(account, exportId, messageInfo) {
        const queueKey = getExportQueueKey(account, exportId);
        const exportKey = getExportKey(account, exportId);

        const score = messageInfo.date instanceof Date ? messageInfo.date.getTime() : Number(messageInfo.date) || Date.now();

        const value = msgpack
            .encode({
                folder: messageInfo.folder,
                messageId: messageInfo.messageId,
                uid: messageInfo.uid,
                size: messageInfo.size || 0
            })
            .toString('base64url');

        await redis.multi().zadd(queueKey, score, value).hincrby(exportKey, 'messagesQueued', 1).exec();
    }

    static async getNextBatch(account, exportId, lastScore, limit) {
        const queueKey = getExportQueueKey(account, exportId);
        // Use exclusive lower bound to avoid re-processing messages with identical timestamps
        // When lastScore is 0 (initial), use inclusive; otherwise use exclusive '(' prefix
        const minScore = lastScore > 0 ? '(' + lastScore : lastScore;
        const results = await redis.zrangebyscore(queueKey, minScore, '+inf', 'WITHSCORES', 'LIMIT', 0, limit);

        const messages = [];
        for (let i = 0; i < results.length; i += 2) {
            try {
                const info = msgpack.decode(Buffer.from(results[i], 'base64url'));
                messages.push({ ...info, score: Number(results[i + 1]) });
            } catch (err) {
                logger.error({ msg: 'Failed to decode message info', account, exportId, err });
            }
        }

        return messages;
    }

    static async incrementExported(account, exportId, bytesWritten = 0) {
        const exportKey = getExportKey(account, exportId);
        await redis.multi().hincrby(exportKey, 'messagesExported', 1).hincrby(exportKey, 'bytesWritten', bytesWritten).exec();
    }

    static async incrementSkipped(account, exportId) {
        await redis.hincrby(getExportKey(account, exportId), 'messagesSkipped', 1);
    }

    static async updateLastProcessedScore(account, exportId, score) {
        await redis.hset(getExportKey(account, exportId), 'lastProcessedScore', score);
    }

    static async complete(account, exportId) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        await redis
            .multi()
            .hmset(exportKey, { status: 'completed', phase: 'complete' })
            .del(queueKey)
            .srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`)
            .exec();

        logger.info({ msg: 'Export completed', account, exportId });
    }

    static async fail(account, exportId, error) {
        const exportKey = getExportKey(account, exportId);
        const queueKey = getExportQueueKey(account, exportId);

        await redis
            .multi()
            .hmset(exportKey, { status: 'failed', error: error || 'Unknown error' })
            .del(queueKey)
            .srem(`${REDIS_PREFIX}exp:active`, `${account}:${exportId}`)
            .exec();

        logger.error({ msg: 'Export failed', account, exportId, error });
    }

    static async markInterruptedAsFailed() {
        const activeExports = await redis.smembers(`${REDIS_PREFIX}exp:active`);

        for (const entry of activeExports) {
            // Use indexOf to handle account IDs that may contain colons
            // Export IDs always start with 'exp_', so find ':exp_' as the separator
            const separatorIndex = entry.indexOf(':exp_');
            if (separatorIndex === -1) continue;
            const account = entry.substring(0, separatorIndex);
            const exportId = entry.substring(separatorIndex + 1);
            if (!account || !exportId) continue;

            const data = await redis.hgetall(getExportKey(account, exportId));

            if (data && (data.status === 'processing' || data.status === 'queued')) {
                const job = await exportQueue.getJob(exportId).catch(() => null);
                if (job) {
                    await job.remove().catch(() => {});
                    logger.info({ msg: 'Removed interrupted export job from queue', account, exportId });
                }

                await Export.fail(account, exportId, 'Export interrupted by application restart');

                if (data.filePath) {
                    await fs.promises.unlink(data.filePath).catch(() => {});
                }
            }
        }
    }

    static async cleanup() {
        const exportPath = await getExportPath();
        let cleaned = 0;

        try {
            const files = await fs.promises.readdir(exportPath);

            for (const file of files) {
                if (!file.startsWith(EXPORT_ID_PREFIX)) continue;

                const exportId = file.split('.')[0];
                const pattern = `${REDIS_PREFIX}exp:*:${exportId}`;
                const keys = await scanKeys(pattern);

                if (keys.length === 0) {
                    try {
                        await fs.promises.unlink(pathlib.join(exportPath, file));
                        cleaned++;
                        logger.info({ msg: 'Cleaned up orphaned export file', file });
                    } catch (err) {
                        logger.error({ msg: 'Failed to clean up export file', file, err });
                    }
                }
            }
        } catch (err) {
            logger.error({ msg: 'Failed to list export directory', exportPath, err });
        }

        return cleaned;
    }

    static async getFile(account, exportId) {
        const data = await redis.hgetall(getExportKey(account, exportId));

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

        try {
            await fs.promises.access(data.filePath, fs.constants.R_OK);
        } catch {
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
