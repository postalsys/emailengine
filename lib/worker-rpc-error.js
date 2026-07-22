'use strict';

// Serialization of an Error across a worker-thread RPC hop.
//
// submitMessage() runs in the IMAP worker and the error it throws reaches the submit worker through
// two postMessage relays (workers/imap.js -> server.js -> workers/submit.js). postMessage cannot
// clone an Error's own enumerable-but-non-standard properties reliably, so each hop copies an
// explicit field list onto a plain payload and rebuilds an Error on the far side. Any field not
// listed here is silently dropped in transit.
//
// `responseCode` (the numeric SMTP reply code) is on the list because lib/delivery-error.js needs it
// to tell a transient 4xx rejection (e.g. greylisting) from a permanent 5xx one. It used to be
// dropped, so the predicate's SMTP-reply branch never fired in production; keeping the field list in
// one place makes that dependency explicit and unit-testable (see test/worker-rpc-error-test.js).
//
// These helpers are used at the delivery-error RPC path - the imap/submit workers and the main-thread
// hub (server.js) that relays between them. The other workers (webhooks/export/documents/smtp/api)
// keep their own inline resp-handler copies: they never carry a delivery error, so `responseCode`
// does not apply to them. Route a delivery error through a new worker and it must switch to these too.
const RPC_ERROR_FIELDS = ['code', 'statusCode', 'responseCode', 'info'];

/**
 * Serializes an Error into the plain payload sent over postMessage.
 *
 * @param {Error} err - Error to serialize
 * @returns {Object} Payload with `error` (the message) plus every present RPC_ERROR_FIELD
 */
function packRpcError(err) {
    let payload = { error: err.message };
    for (let field of RPC_ERROR_FIELDS) {
        if (err[field] != null) {
            payload[field] = err[field];
        }
    }
    return payload;
}

/**
 * Rebuilds an Error from a received postMessage payload.
 *
 * @param {Object} message - Payload produced by packRpcError (may carry extra fields, e.g. cmd/mid)
 * @returns {Error} Error with its message and every present RPC_ERROR_FIELD restored
 */
function unpackRpcError(message) {
    let err = new Error(message.error);
    for (let field of RPC_ERROR_FIELDS) {
        if (message[field] != null) {
            err[field] = message[field];
        }
    }
    return err;
}

module.exports = { packRpcError, unpackRpcError };
