'use strict';

// The checks behind the health endpoints, kept free of Hapi and of the worker's own globals so each
// failure branch can be tested without booting the API.
//
// Two questions with different consequences. Liveness asks whether this process should be
// restarted, so it only depends on the process itself: answering it with a Redis check would make
// an orchestrator restart every pod whenever Redis has a hiccup. Readiness asks whether this process
// should get traffic, and that needs the IMAP workers and Redis, and is false while the API worker is
// draining on shutdown.

const crypto = require('crypto');
const { statusError } = require('./utils/status-error');

const notReady = (message, code) => statusError(message, code, 503);

/**
 * @param {Object} deps
 * @param {Function} deps.call - RPC to the main thread, resolves with the command's answer
 * @param {Object} deps.redis - ioredis client
 * @param {string} deps.prefix - Redis key prefix
 * @param {number} deps.expectedImapWorkers - IMAP worker threads the instance is configured for
 * @param {Function} deps.isDraining - True once the worker has started shutting down
 * @returns {{ live: Function, ready: Function }}
 */
function createHealthChecks(deps) {
    const { call, redis, prefix, expectedImapWorkers, isDraining } = deps;

    function live() {
        if (isDraining()) {
            // Still alive while it drains; reporting otherwise would get it killed mid-request
            return { success: true, draining: true };
        }
        return { success: true };
    }

    /**
     * @param {number} [timeout] - RPC timeout, already validated by the caller
     */
    async function ready(timeout) {
        if (isDraining()) {
            throw notReady('Shutting down', 'ShuttingDown');
        }

        let workers;
        try {
            ({ workers } = (await call({ cmd: 'imapWorkerCount', timeout })) || {});
        } catch (err) {
            throw notReady(`Worker check failed: ${err.message}`, 'WorkerCheckFailed');
        }
        // The answer used to be compared as a whole object, which is never less than a number, so
        // missing workers were never reported
        if (!(workers >= expectedImapWorkers)) {
            throw notReady('Not all IMAP workers available', 'WorkersUnavailable');
        }

        const checkKey = `${prefix}test:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`;
        const expected = crypto.randomBytes(8).toString('hex');
        let res;
        try {
            res = await redis.multi().set(checkKey, expected).get(checkKey).del(checkKey).exec();
        } catch (err) {
            throw notReady(`Database check failed: ${err.message}`, 'DatabaseCheckFailed');
        }
        if (!(res?.[1]?.[1] === expected && res?.[2]?.[1] === 1)) {
            throw notReady('Database check failed', 'DatabaseCheckFailed');
        }

        return { success: true };
    }

    return { live, ready };
}

module.exports = { createHealthChecks };
