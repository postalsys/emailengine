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

// Keys that affect SMTP connection identity. The TLS options are part of it: two accounts on the
// same server that differ only in certificate checking or STARTTLS policy must not share a pool.
const CONNECTION_IDENTITY_KEYS = ['name', 'localAddress', 'auth', 'host', 'port', 'secure', 'transactionLog', 'proxy', 'tls', 'requireTLS', 'ignoreTLS'];

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
    // A transaction log is written through the account's own logger, so two accounts on the same
    // gateway must not share a logged pool: the first account's log used to receive the envelopes
    // and server replies of every account sending through it
    if (smtpSettings.transactionLog && smtpSettings.account) {
        limitedSettings.account = smtpSettings.account;
    }
    const serializedSettings = JSON.stringify(limitedSettings);
    return crypto.createHash('sha256').update(serializedSettings).digest('hex');
}

/**
 * Sets up event handlers for a new transporter
 * @param {Object} transporter - Nodemailer transport instance
 * @param {string} poolKey - Pool key for this transport
 */
// Removes a transporter from the pool map, unless the key already names its successor: a pool
// that was replaced under this key must not take the live one out of the map on a late event, or
// that one is no longer reused nor closed by the idle sweep
function forgetTransporter(poolKey, transporter) {
    if (SMTP_POOLS.get(poolKey) === transporter) {
        SMTP_POOLS.delete(poolKey);
        SMTP_POOL_LAST_USED.delete(poolKey);
    }
}

function setupTransporterHandlers(transporter, poolKey) {
    const forget = () => forgetTransporter(poolKey, transporter);

    // Handle connection pool cleanup when idle
    transporter.once('clear', () => {
        // All emails processed and connection timed out
        logger.trace({ msg: 'Clearing disconnected SMTP pool', poolKey });
        forget();
        try {
            transporter.close();
        } catch (closeErr) {
            logger.error({ msg: 'Failed to close transporter', err: closeErr });
        }
    });

    // Handle transport errors by removing from pool
    transporter.once('error', err => {
        // Not sure what happened, but do not re-use this transporter object anymore
        logger.warn({ msg: 'Transporter failed', err });
        forget();
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

// Closes a transporter including the connections in the middle of a delivery, which the pool's own
// close() leaves running. Reaches into nodemailer's pool for its resources; nodemailer is
// maintained alongside EmailEngine.
function forceCloseTransporter(transporter) {
    try {
        transporter.close();
        const pool = transporter.transporter;
        for (const resource of pool && Array.isArray(pool._connections) ? [...pool._connections] : []) {
            resource.close();
        }
    } catch (err) {
        logger.error({ msg: 'Failed to close pooled transporter', err });
    }
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
 * Whether a pooled transport still has a message queued or being transmitted. isIdle() turns true
 * while a message is still on the wire, so it can not tell. nodemailer (10.2.0) counts them itself,
 * including a message between a dropped connection and its requeue, which reading the pool's queue
 * and connections used to miss
 * @param {Object} transporter - Nodemailer transport instance
 * @returns {boolean}
 */
function hasPendingDeliveries(transporter) {
    const pool = transporter && transporter.transporter;
    return !!pool && typeof pool.pendingCount === 'function' && pool.pendingCount() > 0;
}

/**
 * Performs cleanup of idle SMTP pool connections
 * @param {number} [now] - Current time, for tests
 */
function cleanupIdlePools(now) {
    now = now || Date.now();
    const idleKeys = [];

    for (const [poolKey, lastUsed] of SMTP_POOL_LAST_USED.entries()) {
        if (now - lastUsed > SMTP_POOL_MAX_IDLE) {
            idleKeys.push(poolKey);
        }
    }

    for (const poolKey of idleKeys) {
        const transporter = SMTP_POOLS.get(poolKey);
        if (transporter) {
            // "Idle" is measured from the last time a message was handed to the pool, so a single
            // transmission that outlasts the idle window would otherwise be cut off
            if (hasPendingDeliveries(transporter)) {
                SMTP_POOL_LAST_USED.set(poolKey, now);
                logger.trace({ msg: 'SMTP pool still has deliveries in progress, skipping cleanup', poolKey });
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
        logger.debug({ msg: 'SMTP pool cleanup completed', cleaned: idleKeys.length, remaining: SMTP_POOLS.size });
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

// The longest one delivery may take, whatever the server does. socketTimeout only notices a silent
// server: one that trickles a byte at a time keeps the socket alive forever, and the submit worker
// that waits on the delivery held its only slot for the whole ten minute call timeout, delaying
// every other account's mail behind it. Below that timeout, so the delivery fails here first and the
// connection is closed rather than left running, and long enough for a large message on a slow
// link. What keeps a stalling server from costing this once per message is the account penalty
// the failure sets (lib/submit-penalty.js).
const SMTP_SEND_DEADLINE = 8 * 60 * 1000;

/**
 * Sends a message through the pooled transport for the settings, within a total deadline. On expiry
 * the pooled connection is closed and the send rejects with code ETIMEDOUT and `deadlineExceeded`.
 * @param {Object} smtpSettings - SMTP configuration settings
 * @param {Object} message - nodemailer message
 * @param {number} [deadline] - milliseconds
 * @returns {Promise<Object>} sendMail() info
 */
async function sendWithDeadline(smtpSettings, message, deadline = SMTP_SEND_DEADLINE) {
    // through the export, so a test can stand in a transport
    const transporter = module.exports.getMailTransport(smtpSettings);
    let timer;
    const expired = new Promise((resolve, reject) => {
        timer = setTimeout(() => {
            // the transporter this send went through, which the key may no longer name by now
            forceCloseTransporter(transporter);
            forgetTransporter(generatePoolKey(smtpSettings), transporter);
            const err = new Error(`SMTP delivery did not complete within ${Math.round(deadline / 1000)} seconds`);
            err.code = 'ETIMEDOUT';
            err.deadlineExceeded = true;
            // Not retried: nothing tells whether the server already has the whole message (a
            // server can stall after the final dot as well as before it), and a retry of that one
            // delivers it twice. The message ends as failed and keeps its content, so an operator
            // can retry it from the outbox once the server behaves.
            err.permanent = true;
            reject(err);
        }, deadline);
    });
    try {
        return await Promise.race([transporter.sendMail(message), expired]);
    } finally {
        clearTimeout(timer);
    }
}

module.exports = {
    getMailTransport,
    sendWithDeadline,
    closePooledConnection,
    getPoolSize,
    // Exported for testing
    generatePoolKey,
    cleanupIdlePools,
    SMTP_POOL_MAX_IDLE,
    SMTP_POOL_CLEANUP_INTERVAL
};
