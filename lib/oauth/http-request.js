'use strict';

// The parts of a provider API request that the OAuth2 clients (Gmail, Outlook, Mail.ru) share. Each
// client keeps what differs: how it spells the method, where the access token goes, which fields
// describe a request in its errors and logs, and how it reads a successful answer.

const packageData = require('../../package.json');
const { fetch: fetchCmd } = require('undici');
const { promoteCauseCode } = require('../network-errors');
const { formatPartialSecretKey, parseRetryAfter } = require('../tools');

const USER_AGENT = `${packageData.name}/${packageData.version} (+${packageData.homepage})`;

/**
 * Sets the request body: a Buffer is sent as is, anything else as JSON
 * @param {Object} reqData - fetch() options, updated in place
 * @param {Object|Buffer} payload - Request body
 * @param {string} [contentType] - Content type that overrides the default
 */
function encodeBody(reqData, payload, contentType) {
    if (!Buffer.isBuffer(payload)) {
        reqData.headers.Accept = 'application/json';
        reqData.headers['Content-Type'] = contentType || 'application/json';
        reqData.body = JSON.stringify(payload);
    } else {
        reqData.headers['Content-Type'] = contentType || 'application/x-www-form-urlencoded';
        reqData.body = payload;
    }
}

/**
 * Places the payload of a request: in the query string of a GET (values that are null or
 * undefined left out), in the body otherwise
 * @param {Object} reqData - fetch() options, updated in place
 * @param {string} url - Request URL
 * @param {string} method - Method as the client spells it; only the exact string 'get' is a GET here
 * @param {Object|Buffer} [payload] - Request payload
 * @param {Object} [options] - Request options, `contentType` overrides the body content type
 * @returns {string} The URL to request
 */
function encodeRequest(reqData, url, method, payload, options) {
    if (!payload) {
        return url;
    }
    if (method !== 'get') {
        encodeBody(reqData, payload, options?.contentType);
    } else {
        let parsedUrl = new URL(url);
        for (let key of Object.keys(payload)) {
            if (typeof payload[key] === 'undefined' || payload[key] === null) {
                continue;
            }
            parsedUrl.searchParams.append(key, payload[key].toString());
        }
        url = parsedUrl.href;
    }
    return url;
}

/**
 * Sends the request once and measures how long the answer took
 * @param {string} url - Request URL
 * @param {Object} reqData - fetch() options
 * @returns {Promise<{res: Response, reqTime: number}>}
 */
async function timedFetch(url, reqData) {
    let startTime = Date.now();
    let res = await fetchCmd(url, reqData).catch(err => {
        // undici puts the network code on err.cause; callers read err.code
        throw promoteCauseCode(err);
    });
    return { res, reqTime: Date.now() - startTime };
}

/**
 * The error for an answer that is not 2xx. Carries the HTTP status, and the Retry-After the
 * provider sent (with 429, and with rate-limit 403s and 503s) so the retry layer can honour it
 * @param {Response} res - The answer
 * @param {Object} oauthRequest - Description of the request, becomes err.oauthRequest
 * @returns {Error}
 */
function buildRequestFailure(res, oauthRequest) {
    let err = new Error('OAuth2 request failed');
    err.statusCode = res.status;
    err.oauthRequest = oauthRequest;

    let retryAfter = parseRetryAfter(res.headers);
    if (retryAfter !== null) {
        err.retryAfter = retryAfter;
        err.oauthRequest.retryAfter = retryAfter;
    }

    return err;
}

/**
 * Reads the provider's error body onto a failed request and raises the flag it maps to. A body
 * that is not JSON, or any failure on the way, leaves the error as it is
 * @param {Object} client - The OAuth2 client (its setFlag() and clientSecret are used)
 * @param {Response} res - The failed answer
 * @param {Error} err - The error to complete, with err.oauthRequest set
 * @param {Object} opts
 * @param {Function} opts.checkForFlags - Maps an error body to a flag, or false
 * @param {Function} [opts.exposeSecret] - Whether the error body blames the client secret, so err.oauthRequest shows part of it
 * @param {boolean} [opts.recordFlag] - Also keep the flag on err.oauthRequest.flag
 * @param {Object} [opts.logger] - Logs err.oauthRequest at warn level once done
 * @returns {Promise<Error>} The same error
 */
async function handleFailedResponse(client, res, err, opts) {
    try {
        err.oauthRequest.response = await res.json();

        // Without a configured secret there is nothing to show, and the flag below must still be raised
        if (client.clientSecret && opts.exposeSecret && opts.exposeSecret(err.oauthRequest.response)) {
            // key might have been invalidated or renewed
            err.oauthRequest.clientSecret = formatPartialSecretKey(client.clientSecret);
        }

        let flag = opts.checkForFlags(err.oauthRequest.response);
        if (flag) {
            await client.setFlag(flag);
            if (opts.recordFlag) {
                err.oauthRequest.flag = flag;
            }
            if (flag.code && !err.code) {
                err.code = flag.code;
            }
        }
    } catch (E) {
        // ignore
    } finally {
        if (opts.logger) {
            opts.logger.warn(Object.assign({ msg: 'API request failed' }, err.oauthRequest));
        }
    }

    return err;
}

/**
 * Parses a JSON answer read as text. An empty body (Graph sometimes answers 200 with nothing) is
 * EmptyResponse and one that does not parse is InvalidJSON, each describing the request through
 * `describe(extra)` and logged at error level when a logger is given
 * @param {string} responseText - The body of the answer
 * @param {Function} describe - Returns the err.oauthRequest fields, with the extra fields given appended
 * @param {Object} [opts]
 * @param {number} [opts.statusCode] - Set on the error when given
 * @param {Object} [opts.logger] - Logs the failure
 * @returns {*} The parsed body
 */
function parseJsonResponse(responseText, describe, opts) {
    opts = opts || {};

    if (!responseText || !responseText.trim()) {
        let err = new Error('Empty response from API');
        err.code = 'EmptyResponse';
        if (typeof opts.statusCode === 'number') {
            err.statusCode = opts.statusCode;
        }
        err.oauthRequest = describe();
        if (opts.logger) {
            opts.logger.error(Object.assign({ msg: 'API returned empty response' }, err.oauthRequest));
        }
        throw err;
    }

    try {
        return JSON.parse(responseText);
    } catch (parseErr) {
        let err = new Error('Invalid JSON response from API');
        err.code = 'InvalidJSON';
        if (typeof opts.statusCode === 'number') {
            err.statusCode = opts.statusCode;
        }
        err.oauthRequest = describe({
            responseLength: responseText.length,
            responseStart: responseText.slice(0, 200),
            responseEnd: responseText.length > 200 ? responseText.slice(-200) : undefined
        });
        if (opts.logger) {
            opts.logger.error(Object.assign({ msg: 'API returned invalid JSON' }, err.oauthRequest, { err: parseErr }));
        }
        throw err;
    }
}

module.exports = {
    USER_AGENT,
    encodeBody,
    encodeRequest,
    timedFetch,
    buildRequestFailure,
    handleFailedResponse,
    parseJsonResponse
};
