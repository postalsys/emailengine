'use strict';

// The worker side of the RPC protocol between a worker thread and the main thread (server.js).
//
// A worker calls the main thread with `{ cmd: 'call', mid, message }` and gets back
// `{ cmd: 'resp', mid, response }` or `{ cmd: 'resp', mid, error, ...fields }`; the main thread
// calls a worker the same way. Every worker used to carry its own copy of both halves, and the
// copies had drifted: some rebuilt errors without `responseCode` and `permanent`, one call() did
// not guard postMessage, and no reply guarded against a response that cannot be cloned, which
// would surface as a rejection nothing handles and end the worker. Errors cross the hop through
// lib/worker-rpc-error.js, the same field list everywhere.
//
// The main thread's hub (server.js) routes calls between workers and keeps its own bookkeeping
// (the worker each call went to, rejecting them when it exits), so it does not use this module.

const { packRpcError, unpackRpcError } = require('./worker-rpc-error');

/**
 * Creates the calling half: call() sends a command to the main thread and settles when its
 * response arrives or the timeout passes, handleResponse() settles a call from a received message.
 *
 * @param {Object} opts
 * @param {Object} opts.port - the MessagePort to talk over (parentPort)
 * @param {Number} opts.defaultTimeout - lowest timeout in ms, a command may ask for longer
 * @param {String} opts.timeoutTag - short marker in the timeout message that names the worker
 * @returns {{ call: Function, handleResponse: Function, pendingCount: Function }}
 */
function createRpcClient({ port, defaultTimeout, timeoutTag }) {
    const pending = new Map();
    let mids = 0;

    function call(message, transferList) {
        return new Promise((resolve, reject) => {
            const mid = `${Date.now()}:${++mids}`;

            const ttl = Math.max(message.timeout || 0, defaultTimeout || 0);
            const timer = setTimeout(() => {
                pending.delete(mid);
                const err = new Error(`Timeout waiting for command response [${timeoutTag}]`);
                err.statusCode = 504;
                err.code = 'Timeout';
                err.ttl = ttl;
                reject(err);
            }, ttl);

            pending.set(mid, { resolve, reject, timer });

            try {
                port.postMessage({ cmd: 'call', mid, message }, transferList);
            } catch (err) {
                clearTimeout(timer);
                pending.delete(mid);
                reject(err);
            }
        });
    }

    /**
     * Settles the call a response belongs to
     * @param {Object} message - a received message
     * @returns {Boolean} true when the message was the response to a pending call
     */
    function handleResponse(message) {
        if (!message || message.cmd !== 'resp' || !message.mid || !pending.has(message.mid)) {
            return false;
        }

        const { resolve, reject, timer } = pending.get(message.mid);
        clearTimeout(timer);
        pending.delete(message.mid);

        if (message.error) {
            reject(unpackRpcError(message));
        } else {
            resolve(message.response);
        }
        return true;
    }

    return { call, handleResponse, pendingCount: () => pending.size };
}

/**
 * Runs a command the main thread sent and posts its result back. Never rejects: a response that
 * cannot be sent (a value postMessage cannot clone, a closed port) is answered with an error
 * instead, and a failure to send even that is logged rather than left to the global handler.
 *
 * @param {Object} port - the MessagePort to answer over (parentPort)
 * @param {Object} message - the received `{ cmd: 'call', mid, message }`
 * @param {Function} handler - async (command) => response
 * @param {Object} opts
 * @param {Object} opts.logger - where an undeliverable response is reported
 * @param {Function} [opts.onError] - (err, message) => void, sees a command's error before it is sent
 * @returns {Promise<void>}
 */
async function respond(port, message, handler, { logger, onError }) {
    const mid = message.mid;

    const send = payload => {
        try {
            port.postMessage(payload);
        } catch (err) {
            try {
                port.postMessage(Object.assign({ cmd: 'resp', mid }, packRpcError(err)));
            } catch (fallbackErr) {
                logger.error({ msg: 'Failed to send a command response', mid, err: fallbackErr });
            }
        }
    };

    let response;
    try {
        response = await handler(message.message);
    } catch (err) {
        if (onError) {
            try {
                onError(err, message);
            } catch (hookErr) {
                logger.error({ msg: 'Failed to process a command error', mid, err: hookErr });
            }
        }
        send(Object.assign({ cmd: 'resp', mid }, packRpcError(err)));
        return;
    }

    send({ cmd: 'resp', mid, response });
}

/**
 * Whether a received message is a command for this worker to run
 * @param {Object} message
 * @returns {Boolean}
 */
function isCall(message) {
    return !!(message && message.cmd === 'call' && message.mid);
}

module.exports = { createRpcClient, respond, isCall };
