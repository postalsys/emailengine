'use strict';

/**
 * An error that carries the HTTP status and the machine-readable code a refusal is reported
 * with: the API's handleError() reads both off any thrown error, and the admin routes turn the
 * status into a flash message. One factory so every module refusing an operation shapes it the
 * same way.
 *
 * @param {string} message - Error message
 * @param {string} code - Machine-readable code, e.g. NotFailed
 * @param {number} statusCode - HTTP status to answer with
 * @returns {Error}
 */
function statusError(message, code, statusCode) {
    const err = new Error(message);
    err.code = code;
    err.statusCode = statusCode;
    return err;
}

module.exports = { statusError };
