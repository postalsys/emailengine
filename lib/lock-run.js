'use strict';

const Boom = require('@hapi/boom');

// Runs a critical section under an ioredfour lock through its withLock(), which owns the acquire,
// the release in every case, and a failed release (the lock expires on its own). What a caller
// does when the lock is not there to take differs per site: refuse with an error of its own, or go
// ahead unserialized, so that is the one thing left to it.

/**
 * @param {Object} lock - ioredfour Lock instance
 * @param {string} id - Lock id
 * @param {number} ttl - Lock TTL in ms
 * @param {number|null} waitTtl - How long to wait for the lock in ms; null to not wait at all
 * @param {Function} fn - The critical section
 * @param {Function} onUnavailable - (err) => value or throw, when the lock was not obtained (err is
 *     ioredfour's ELOCKNOTACQUIRED LockError, or the Redis error that kept it from being taken)
 * @returns {Promise<*>} What fn resolves with, or what onUnavailable returns
 */
async function runLocked(lock, id, ttl, waitTtl, fn, onUnavailable) {
    let entered = false;
    try {
        return await lock.withLock(
            id,
            ttl,
            waitTtl === null ? 0 : waitTtl,
            async (...args) => {
                entered = true;
                return await fn(...args);
            },
            waitTtl === null ? { wait: false } : undefined
        );
    } catch (err) {
        if (entered) {
            throw err;
        }
        return await onUnavailable(err);
    }
}

/**
 * An onUnavailable for runLocked() that refuses with a 500: contention (someone else held the lock
 * for the whole wait) is logged as a warning, a lock that could not be taken at all as an error. The
 * response carries the Redis error's code, not one of its own for contention
 * @param {Object} logger
 * @param {string} message - What failed, e.g. 'Failed to get renewal lock'
 * @param {Object} fields - Fields for the log entry
 * @returns {Function}
 */
function refuseUnavailableLock(logger, message, fields) {
    return err => {
        const contention = err && err.code === 'ELOCKNOTACQUIRED';
        if (contention) {
            logger.warn(Object.assign({ msg: `${message}, timed out waiting for the current holder` }, fields));
        } else {
            logger.error(Object.assign({ msg: message }, fields, { err }));
        }
        const error = Boom.boomify(new Error(message), { statusCode: 500 });
        if (err && err.code && !contention) {
            error.output.payload.code = err.code;
        }
        throw error;
    };
}

module.exports = { runLocked, refuseUnavailableLock };
