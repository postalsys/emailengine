'use strict';

const { fetch: fetchCmd } = require('undici');
const { httpAgent } = require('../tools');

/**
 * Performs a token-endpoint request, and says which endpoint failed when the request never got there.
 *
 * A rejected response is already described in detail by each provider client (`ETokenRefresh`, the
 * status, the parsed body). A request that never reaches the endpoint is not: undici rejects a failed
 * fetch with a bare `fetch failed` whose own `code` is unset, the reason (ENOTFOUND, ECONNREFUSED,
 * UND_ERR_CONNECT_TIMEOUT, a TLS failure) sitting on `err.cause`. Such a failure is correctly treated
 * as transient - the account reports a connectError and keeps retrying rather than being parked - but
 * the webhook then carried "fetch failed" and no serverResponseCode, which is indistinguishable from
 * the mail server itself being unreachable. That is the one thing it is not.
 *
 * The error is ANNOTATED rather than replaced. Its code and cause are what isTransientNetworkError()
 * reads (lib/email-client/credential-errors.js), and a token endpoint that could not be reached has
 * not refused the refresh token: a replacement error carrying a code of its own would be read as an
 * authentication failure and would park the account.
 *
 * @param {String} url - the token endpoint
 * @param {Object} options - fetch options; the retrying dispatcher is applied here
 * @param {Object} context - what to record about the attempt, as the rejected-response path records it
 * @returns {Promise<Response>} the response, whatever its status
 */
async function fetchTokenRequest(url, options, context) {
    try {
        return await fetchCmd(url, Object.assign({ dispatcher: httpAgent.retry }, options));
    } catch (err) {
        // The cause carries the actionable code. Promoted onto the error itself so the connectError
        // webhook has something to report - the transient check consults both, so no verdict changes.
        if (!err.code && err.cause && err.cause.code) {
            err.code = err.cause.code;
        }

        err.tokenRequest = Object.assign({ url, error: err.message, errorCode: err.code }, context);
        err.message = `Token request to ${url} failed${err.code ? ` [${err.code}]` : ''}: ${(err.cause && err.cause.message) || err.message}`;

        throw err;
    }
}

module.exports = { fetchTokenRequest };
