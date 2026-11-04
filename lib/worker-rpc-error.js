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
// `permanent` is nodemailer's own verdict on that reply, which the predicate prefers when present.
//
// Every worker's RPC goes through these helpers (lib/worker-rpc.js on the worker side, server.js as
// the hub that relays between workers), so a field added here reaches every hop.
const RPC_ERROR_FIELDS = ['code', 'statusCode', 'responseCode', 'permanent', 'info'];

/**
 * Serializes an Error into the plain payload sent over postMessage.
 *
 * @param {Error} err - Error to serialize
 * @returns {Object} Payload with `error` (the message) plus every present RPC_ERROR_FIELD
 */
function packRpcError(err) {
    // A command may reject with something that is not an Error (a string, undefined). Reading
    // .message off that used to throw inside the reply handler, a rejection nothing caught
    if (!err || typeof err !== 'object') {
        return { error: String(err) };
    }
    // Never empty: the receiving side tells an error reply from a result by this field being set,
    // so an Error with no message would otherwise arrive as a successful, empty response
    let payload = { error: err.message || err.name || 'Error' };
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

// Longest string value describeRpcCommand() copies into a log line
const MAX_LOGGED_VALUE_LENGTH = 256;

/**
 * What a failed-command log line says about an RPC command. The payload itself stays out: a
 * submitMessage carries the whole message (attachment content, html and text bodies), and the log
 * redaction only knows the request and error paths. Scalar fields (cmd, account, message id, path)
 * are kept, nested objects are reduced to their key list and a size
 * @param {Object} envelope - The RPC envelope ({ cmd: 'call', mid, message })
 * @returns {Object}
 */
function describeRpcCommand(envelope) {
    let command = (envelope && envelope.message) || {};
    let summary = { mid: envelope && envelope.mid };

    for (let [key, value] of Object.entries(command)) {
        switch (typeof value) {
            case 'string':
                summary[key] = value.length > MAX_LOGGED_VALUE_LENGTH ? `${value.slice(0, MAX_LOGGED_VALUE_LENGTH)}...` : value;
                break;
            case 'number':
            case 'boolean':
                summary[key] = value;
                break;
        }
    }

    let data = command.data;
    if (data && typeof data === 'object' && !Buffer.isBuffer(data)) {
        summary.dataKeys = Object.keys(data);
        if (data.raw && typeof data.raw.length === 'number') {
            summary.rawSize = data.raw.length;
        }
        if (Array.isArray(data.attachments)) {
            summary.attachments = data.attachments.length;
        }
    }

    return summary;
}

module.exports = { packRpcError, unpackRpcError, describeRpcCommand };
