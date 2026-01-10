'use strict';

const crypto = require('crypto');
const nodemailer = require('nodemailer');
const socks = require('socks');
const logger = require('../logger');

// Cache for SMTP connection pools to reuse connections
const SMTP_POOLS = new Map();
// Track last usage time for each pool to enable LRU-based cleanup
const SMTP_POOL_LAST_USED = new Map();

// Maximum idle time for SMTP pool connections (10 minutes of inactivity)
const SMTP_POOL_MAX_IDLE = 10 * 60 * 1000;
// Cleanup interval for idle SMTP pools (2 minutes)
const SMTP_POOL_CLEANUP_INTERVAL = 2 * 60 * 1000;

// Keys that affect SMTP connection identity
const CONNECTION_IDENTITY_KEYS = ['name', 'localAddress', 'auth', 'host', 'port', 'secure', 'transactionLog', 'proxy'];

/**
 * Generates a unique pool key from SMTP settings
 * @param {Object} smtpSettings - SMTP configuration settings
 * @returns {string} SHA256 hash of connection-relevant settings
 */
function generatePoolKey(smtpSettings) {
    const limitedSettings = {};
    for (const key of CONNECTION_IDENTITY_KEYS) {
        limitedSettings[key] = smtpSettings[key];
    }
    const serializedSettings = JSON.stringify(limitedSettings);
    return crypto.createHash('sha256').update(serializedSettings).digest('hex');
}

/**
 * Sets up event handlers for a new transporter
 * @param {Object} transporter - Nodemailer transport instance
 * @param {string} poolKey - Pool key for this transport
 */
function setupTransporterHandlers(transporter, poolKey) {
    // Handle connection pool cleanup when idle
    transporter.once('clear', () => {
        // All emails processed and connection timed out
        logger.trace({ msg: 'Clearing disconnected SMTP pool', poolKey });
        SMTP_POOLS.delete(poolKey);
        SMTP_POOL_LAST_USED.delete(poolKey);
        try {
            transporter.close();
        } catch (closeErr) {
            logger.error({ msg: 'Failed to close transporter', err: closeErr });
        }
    });

    // Handle transport errors by removing from pool
    transporter.once('error', err => {
        // Not sure what happened, but do not re-use this transporter object anymore
        logger.error({ msg: 'Transporter failed', err });
        SMTP_POOLS.delete(poolKey);
        SMTP_POOL_LAST_USED.delete(poolKey);
        try {
            transporter.close();
        } catch (closeErr) {
            logger.error({ msg: 'Failed to close transporter', err: closeErr });
        }
    });
}

/**
 * Creates a new SMTP transport with pooling enabled
 * @param {Object} smtpSettings - SMTP configuration settings
 * @param {string} poolKey - Pool key for this transport
 * @returns {Object} Configured nodemailer transport instance
 */
function createPooledTransport(smtpSettings, poolKey) {
    // Configure connection pooling settings
    smtpSettings.pool = true;
    smtpSettings.maxConnections = 1;
    smtpSettings.maxMessages = 100;
    smtpSettings.socketTimeout = 2 * 60 * 1000; // 2 minute timeout

    // Create new transport with pooling enabled
    const transporter = nodemailer.createTransport(smtpSettings);
    transporter.set('proxy_socks_module', socks);

    setupTransporterHandlers(transporter, poolKey);

    return transporter;
}

/**
 * Gets or creates a reusable SMTP transport for the given configuration
 * Connection pooling improves performance by reusing SMTP connections
 * @param {Object} smtpSettings - SMTP configuration settings
 * @returns {Object} Nodemailer transport instance
 */
function getMailTransport(smtpSettings) {
    const poolKey = generatePoolKey(smtpSettings);

    // Return existing transport if available
    if (SMTP_POOLS.has(poolKey)) {
        const transporter = SMTP_POOLS.get(poolKey);
        // Update last used time for LRU tracking
        SMTP_POOL_LAST_USED.set(poolKey, Date.now());
        return transporter;
    }

    // Create new transport
    const transporter = createPooledTransport(smtpSettings, poolKey);

    // Cache the transport for reuse
    SMTP_POOLS.set(poolKey, transporter);
    SMTP_POOL_LAST_USED.set(poolKey, Date.now());
    logger.trace({ msg: 'Created SMTP pool', poolKey });

    return transporter;
}

/**
 * Closes a pooled connection by key
 * @param {string} poolKey - The pool key to close
 */
function closePooledConnection(poolKey) {
    const transporter = SMTP_POOLS.get(poolKey);
    if (transporter) {
        try {
            transporter.close();
        } catch (err) {
            logger.error({ msg: 'Failed to close pooled transporter', poolKey, err });
        }
        SMTP_POOLS.delete(poolKey);
        SMTP_POOL_LAST_USED.delete(poolKey);
    }
}

/**
 * Performs cleanup of idle SMTP pool connections
 */
function cleanupIdlePools() {
    const now = Date.now();
    const idleKeys = [];

    for (const [poolKey, lastUsed] of SMTP_POOL_LAST_USED.entries()) {
        if (now - lastUsed > SMTP_POOL_MAX_IDLE) {
            idleKeys.push(poolKey);
        }
    }

    for (const poolKey of idleKeys) {
        const transporter = SMTP_POOLS.get(poolKey);
        if (transporter) {
            // Check if the transporter has active connections
            if (transporter._connectionPool && transporter._connectionPool.size > 0) {
                // Still has active connections, update last used time
                SMTP_POOL_LAST_USED.set(poolKey, now);
                logger.trace({ msg: 'SMTP pool still has active connections, skipping cleanup', poolKey });
                continue;
            }

            logger.debug({ msg: 'Cleaning up idle SMTP pool connection', poolKey, idleTime: now - SMTP_POOL_LAST_USED.get(poolKey) });
            try {
                transporter.close();
            } catch (err) {
                logger.error({ msg: 'Failed to close idle SMTP transporter', poolKey, err });
            }
        }
        SMTP_POOLS.delete(poolKey);
        SMTP_POOL_LAST_USED.delete(poolKey);
    }

    if (idleKeys.length > 0) {
        logger.info({ msg: 'SMTP pool cleanup completed', cleaned: idleKeys.length, remaining: SMTP_POOLS.size });
    }
}

// Periodic cleanup of idle SMTP pool connections
const smtpPoolCleanupTimer = setInterval(cleanupIdlePools, SMTP_POOL_CLEANUP_INTERVAL);

// Prevent the timer from keeping the process alive
smtpPoolCleanupTimer.unref();

/**
 * Gets the current pool size (for testing/monitoring)
 * @returns {number} Number of active pools
 */
function getPoolSize() {
    return SMTP_POOLS.size;
}

module.exports = {
    getMailTransport,
    closePooledConnection,
    getPoolSize,
    // Export constants for testing
    SMTP_POOL_MAX_IDLE,
    SMTP_POOL_CLEANUP_INTERVAL
};
