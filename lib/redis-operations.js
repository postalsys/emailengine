'use strict';

const logger = require('./logger');

/**
 * Default retry configuration for Redis operations
 */
const DEFAULT_RETRY_OPTIONS = {
    maxAttempts: 3,
    baseDelay: 100, // 100ms base delay
    maxDelay: 2000 // 2 second max delay
};

/**
 * Transient error codes that warrant a retry
 */
const TRANSIENT_ERROR_CODES = new Set(['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'EHOSTUNREACH', 'ECONNREFUSED']);

/**
 * Checks if an error is transient and should be retried
 * @param {Error} err - The error to check
 * @returns {boolean} True if the error is transient
 */
function isTransientError(err) {
    if (!err) {
        return false;
    }

    // Check for known transient error codes
    if (err.code && TRANSIENT_ERROR_CODES.has(err.code)) {
        return true;
    }

    // Check for Redis connection errors
    if (err.name === 'ReplyError' && /LOADING|BUSY|READONLY|CLUSTERDOWN/.test(err.message)) {
        return true;
    }

    // Check for connection lost errors
    if (err.message && /connection.*lost|connection.*closed|socket.*closed/i.test(err.message)) {
        return true;
    }

    return false;
}

/**
 * Calculates delay for exponential backoff
 * @param {number} attempt - Current attempt number (1-based)
 * @param {number} baseDelay - Base delay in milliseconds
 * @param {number} maxDelay - Maximum delay in milliseconds
 * @returns {number} Delay in milliseconds
 */
function calculateBackoffDelay(attempt, baseDelay, maxDelay) {
    // Exponential backoff with jitter
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 0.1 * exponentialDelay; // 10% jitter
    return Math.min(exponentialDelay + jitter, maxDelay);
}

/**
 * Sleeps for the specified duration
 * @param {number} ms - Duration in milliseconds
 * @returns {Promise<void>}
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Extracts errors from Redis multi/exec results
 * @param {Array} results - Results from exec()
 * @returns {Error|null} First error found, or null if no errors
 */
function extractMultiError(results) {
    if (!Array.isArray(results)) {
        return null;
    }

    for (const result of results) {
        if (Array.isArray(result) && result[0]) {
            return result[0];
        }
    }

    return null;
}

/**
 * Extracts values from Redis multi/exec results
 * @param {Array} results - Results from exec()
 * @returns {Array} Array of values (without error elements)
 */
function extractMultiValues(results) {
    if (!Array.isArray(results)) {
        return [];
    }

    return results.map(result => {
        if (Array.isArray(result)) {
            return result[1];
        }
        return result;
    });
}

/**
 * Wraps Redis multi/exec operations with consistent error handling and retry logic
 */
class RedisTransaction {
    /**
     * Creates a new RedisTransaction
     * @param {Object} redis - ioredis client instance
     * @param {Object} options - Configuration options
     * @param {Object} [options.logger] - Logger instance
     * @param {number} [options.maxAttempts] - Maximum retry attempts
     * @param {number} [options.baseDelay] - Base delay for retries in ms
     * @param {number} [options.maxDelay] - Maximum delay for retries in ms
     */
    constructor(redis, options = {}) {
        this.redis = redis;
        this.logger = options.logger || logger;
        this.retryOptions = {
            maxAttempts: options.maxAttempts || DEFAULT_RETRY_OPTIONS.maxAttempts,
            baseDelay: options.baseDelay || DEFAULT_RETRY_OPTIONS.baseDelay,
            maxDelay: options.maxDelay || DEFAULT_RETRY_OPTIONS.maxDelay
        };
        this.commands = [];
        this.commandNames = [];
    }

    /**
     * Adds a command to the transaction
     * @param {string} command - Redis command name
     * @param {...any} args - Command arguments
     * @returns {RedisTransaction} this instance for chaining
     */
    add(command, ...args) {
        this.commands.push({ command, args });
        this.commandNames.push(command);
        return this;
    }

    /**
     * Executes the transaction with retry logic
     * @returns {Promise<Object>} Object containing results array and any error
     */
    async exec() {
        const { maxAttempts, baseDelay, maxDelay } = this.retryOptions;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                const multi = this.redis.multi();

                // Add all commands to the multi
                for (const { command, args } of this.commands) {
                    multi[command](...args);
                }

                const results = await multi.exec();
                const error = extractMultiError(results);

                if (error && isTransientError(error) && attempt < maxAttempts) {
                    const delay = calculateBackoffDelay(attempt, baseDelay, maxDelay);
                    this.logger.warn({
                        msg: 'Redis transaction encountered transient error, retrying',
                        attempt,
                        maxAttempts,
                        delay,
                        error: error.message,
                        commands: this.commandNames
                    });
                    await sleep(delay);
                    continue;
                }

                return {
                    results,
                    values: extractMultiValues(results),
                    error
                };
            } catch (err) {
                if (isTransientError(err) && attempt < maxAttempts) {
                    const delay = calculateBackoffDelay(attempt, baseDelay, maxDelay);
                    this.logger.warn({
                        msg: 'Redis transaction failed with transient error, retrying',
                        attempt,
                        maxAttempts,
                        delay,
                        error: err.message,
                        commands: this.commandNames
                    });
                    await sleep(delay);
                    continue;
                }
                throw err;
            }
        }
    }

    /**
     * Executes the transaction and throws if any command failed
     * @returns {Promise<Array>} Array of values from successful commands
     */
    async execOrThrow() {
        const { results, values, error } = await this.exec();

        if (error) {
            throw error;
        }

        return values;
    }
}

/**
 * Executes an atomic update operation with retry logic
 * Sets multiple hash fields in a single transaction
 *
 * @param {Object} redis - ioredis client instance
 * @param {string} key - Redis hash key
 * @param {Object} fields - Object of field-value pairs to set
 * @param {Object} options - Configuration options
 * @param {Object} [options.logger] - Logger instance
 * @param {number} [options.expireSeconds] - Optional TTL in seconds
 * @returns {Promise<Object>} Result object with success status
 */
async function atomicUpdate(redis, key, fields, options = {}) {
    const txn = new RedisTransaction(redis, options);

    if (Object.keys(fields).length > 0) {
        txn.add('hmset', key, fields);
    }

    if (options.expireSeconds) {
        txn.add('expire', key, options.expireSeconds);
    }

    const { error, values } = await txn.exec();

    return {
        success: !error,
        error,
        values
    };
}

/**
 * Performs a batch get operation for multiple keys
 *
 * @param {Object} redis - ioredis client instance
 * @param {Array<string>} keys - Array of Redis keys to get
 * @param {Object} options - Configuration options
 * @param {string} [options.type='get'] - Type of get operation ('get', 'hgetall', 'smembers')
 * @returns {Promise<Array>} Array of values
 */
async function batchGet(redis, keys, options = {}) {
    if (!keys.length) {
        return [];
    }

    const type = options.type || 'get';
    const txn = new RedisTransaction(redis, options);

    for (const key of keys) {
        txn.add(type, key);
    }

    return txn.execOrThrow();
}

/**
 * Performs a batch set operation for multiple key-value pairs
 *
 * @param {Object} redis - ioredis client instance
 * @param {Array<{key: string, value: any}>} items - Array of key-value pairs
 * @param {Object} options - Configuration options
 * @param {number} [options.expireSeconds] - Optional TTL in seconds for all keys
 * @returns {Promise<Object>} Result object with success status
 */
async function batchSet(redis, items, options = {}) {
    if (!items.length) {
        return { success: true, values: [] };
    }

    const txn = new RedisTransaction(redis, options);

    for (const { key, value } of items) {
        txn.add('set', key, value);
        if (options.expireSeconds) {
            txn.add('expire', key, options.expireSeconds);
        }
    }

    const { error, values } = await txn.exec();

    return {
        success: !error,
        error,
        values
    };
}

/**
 * Performs a conditional set operation (only if key exists)
 * Uses hSetExists custom command if available, falls back to check-then-set
 *
 * @param {Object} redis - ioredis client instance
 * @param {string} key - Redis hash key
 * @param {string} field - Hash field name
 * @param {any} value - Value to set
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} Result with success status and whether value was set
 */
async function conditionalSet(redis, key, field, value, options = {}) {
    // Check if hSetExists is available (custom Lua command)
    if (typeof redis.hSetExists === 'function') {
        const txn = new RedisTransaction(redis, options);
        txn.add('hSetExists', key, field, value);
        const { error, values } = await txn.exec();

        return {
            success: !error,
            error,
            wasSet: values[0] === 1
        };
    }

    // Fallback: use HSETNX behavior with existence check
    const exists = await redis.exists(key);
    if (!exists) {
        return {
            success: true,
            wasSet: false
        };
    }

    await redis.hset(key, field, value);
    return {
        success: true,
        wasSet: true
    };
}

/**
 * Executes a rate-limited increment operation atomically
 *
 * @param {Object} redis - ioredis client instance
 * @param {string} key - Redis key
 * @param {number} count - Amount to increment by
 * @param {number} expireSeconds - TTL for the key in seconds
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} Result with new value and success status
 */
async function atomicIncrement(redis, key, count, expireSeconds, options = {}) {
    const txn = new RedisTransaction(redis, options);
    txn.add('incrby', key, count);
    txn.add('expire', key, expireSeconds);

    const { error, values } = await txn.exec();

    return {
        success: !error,
        error,
        value: values[0]
    };
}

/**
 * Executes a push and trim operation atomically (for bounded lists)
 *
 * @param {Object} redis - ioredis client instance
 * @param {string} key - Redis list key
 * @param {any} value - Value to push
 * @param {number} maxLength - Maximum list length to maintain
 * @param {Object} options - Configuration options
 * @param {string} [options.direction='right'] - Push direction ('left' or 'right')
 * @returns {Promise<Object>} Result with success status
 */
async function boundedPush(redis, key, value, maxLength, options = {}) {
    const direction = options.direction || 'right';
    const pushCmd = direction === 'left' ? 'lpush' : 'rpush';
    const trimStart = direction === 'left' ? 0 : -maxLength;
    const trimEnd = direction === 'left' ? maxLength - 1 : -1;

    const txn = new RedisTransaction(redis, options);
    txn.add(pushCmd, key, value);
    txn.add('ltrim', key, trimStart, trimEnd);

    const { error, values } = await txn.exec();

    return {
        success: !error,
        error,
        listLength: values[0]
    };
}

/**
 * Executes a get-and-delete operation atomically
 *
 * @param {Object} redis - ioredis client instance
 * @param {string} key - Redis key
 * @param {Object} options - Configuration options
 * @param {string} [options.type='get'] - Type of get operation ('get', 'lrange', 'hgetall')
 * @param {Array} [options.rangeArgs] - Arguments for lrange [start, stop]
 * @returns {Promise<Object>} Result with value and success status
 */
async function getAndDelete(redis, key, options = {}) {
    const type = options.type || 'get';
    const txn = new RedisTransaction(redis, options);

    if (type === 'lrange' && options.rangeArgs) {
        txn.add('lrange', key, options.rangeArgs[0], options.rangeArgs[1]);
    } else {
        txn.add(type, key);
    }

    txn.add('del', key);

    const { error, values } = await txn.exec();

    return {
        success: !error,
        error,
        value: values[0]
    };
}

/**
 * Creates a RedisTransaction builder with a fluent API
 *
 * @param {Object} redis - ioredis client instance
 * @param {Object} options - Configuration options
 * @returns {RedisTransaction} New transaction instance
 */
function createTransaction(redis, options = {}) {
    return new RedisTransaction(redis, options);
}

module.exports = {
    // Class export
    RedisTransaction,

    // Helper functions
    createTransaction,
    atomicUpdate,
    batchGet,
    batchSet,
    conditionalSet,
    atomicIncrement,
    boundedPush,
    getAndDelete,

    // Utility functions
    isTransientError,
    extractMultiError,
    extractMultiValues
};
