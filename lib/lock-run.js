'use strict';

const Boom = require('@hapi/boom');

// Runs a critical section under an ioredfour lock through its withLock(), which owns the acquire,
// the release in every case, and a failed release (the lock expires on its own). What a caller
// does when the lock is not there to take differs per site: refuse with an error of its own, or go
// ahead unserialized, so that is the one thing left to it.

let sharedLock = null;

/**
 * The lock instance every EmailEngine lock is taken from: one namespace, one subscriber connection
 * per worker, and the one place a failed release (which withLock() reports as an 'error' event and
 * never as the result) is logged. Built on first use, so requiring this module opens nothing
 * @returns {Object} ioredfour Lock
 */
function getSharedLock() {
    if (!sharedLock) {
        const Lock = require('ioredfour');
        const { redis } = require('./db');
        const logger = require('./logger');
        sharedLock = new Lock({ redis, namespace: 'ee' });
        sharedLock.on('error', err => logger.warn({ msg: 'Lock operation failed, the lock expires on its own', err }));
    }
    return sharedLock;
}

/**
 * @param {Object} lock - ioredfour Lock instance
 * @param {string} id - Lock id
 * @param {Object} opts
 * @param {number} opts.ttl - Lock TTL in ms
 * @param {number|false} opts.wait - How long to wait for the lock in ms, false for one try
 * @param {boolean} [opts.extend] - Keep extending the lock while fn runs, so ttl only has to cover a
 *     stalled process rather than the whole job
 * @param {Function} fn - The critical section
 * @param {Function} onUnavailable - (err) => value or throw, when the lock was not obtained (err is
 *     ioredfour's ELOCKNOTACQUIRED LockError, or the Redis error that kept it from being taken)
 * @returns {Promise<*>} What fn resolves with, or what onUnavailable returns
 */
async function runLocked(lock, id, { ttl, wait, extend }, fn, onUnavailable) {
    // withLock() rejects the same way whether the lock was not taken or fn failed; only the first
    // goes to onUnavailable
    let entered = false;
    try {
        return await lock.withLock(
            id,
            ttl,
            wait === false ? 0 : wait,
            async (...args) => {
                entered = true;
                return await fn(...args);
            },
            { wait: wait !== false, extend: !!extend }
        );
    } catch (err) {
        if (entered) {
            throw err;
        }
        return await onUnavailable(err);
    }
}

const isContention = err => !!err && err.code === 'ELOCKNOTACQUIRED';

/**
 * An onUnavailable for runLocked() that refuses with a Boom error: contention (someone else held the
 * lock for the whole wait) is logged as a warning and answered with `contention` (a 500 with no code
 * of its own by default), a lock that could not be taken at all as an error and a 500 carrying the
 * Redis error's code
 * @param {Object} logger
 * @param {string} message - What failed, e.g. 'Failed to get renewal lock'
 * @param {Object} fields - Fields for the log entry
 * @param {Object} [contention] - `{ statusCode, code, message, logMessage }` for the contention answer
 * @returns {Function}
 */
function refuseUnavailableLock(logger, message, fields, contention = {}) {
    return err => {
        let error;
        if (isContention(err)) {
            logger.warn(Object.assign({ msg: contention.logMessage || `${message}, timed out waiting for the current holder` }, fields));
            error = Boom.boomify(new Error(contention.message || message), { statusCode: contention.statusCode || 500 });
            if (contention.code) {
                error.output.payload.code = contention.code;
            }
        } else {
            logger.error(Object.assign({ msg: message }, fields, { err }));
            error = Boom.boomify(new Error(contention.failureMessage || message), { statusCode: 500 });
            if (err && err.code) {
                error.output.payload.code = err.code;
            }
        }
        throw error;
    };
}

/**
 * An onUnavailable for runLocked() outside the API: contention becomes an Error of its own (code
 * LockNotAcquired) after a warning, any other failure is logged and rethrown as it is
 * @param {Object} logger
 * @param {string} message - What failed, e.g. 'Failed to get connection lock'
 * @param {Object} fields - Fields for the log entry
 * @returns {Function}
 */
function rethrowUnavailableLock(logger, message, fields) {
    return err => {
        if (isContention(err)) {
            logger.warn(Object.assign({ msg: `${message}, timed out waiting for the current holder` }, fields));
            const error = new Error(message);
            error.code = 'LockNotAcquired';
            throw error;
        }
        logger.error(Object.assign({ msg: message }, fields, { err }));
        throw err;
    };
}

module.exports = { runLocked, refuseUnavailableLock, rethrowUnavailableLock, getSharedLock, isContention };
