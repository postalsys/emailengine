'use strict';

// A one-off test delivery to a webhook target: the admin Webhooks page's "Test" button and
// POST /v1/webhooks/test. It goes out through the same request function, dispatcher and egress
// check as a real delivery, and is signed the way one is, so a receiver that verifies
// X-EE-Wh-Signature accepts the probe as it would accept the events.

const crypto = require('crypto');
const { fetch: fetchCmd } = require('undici');
const packageData = require('../package.json');
const { splitUrlCredentials, httpAgent, getServiceSecret } = require('./tools');
const { validateWebhookTarget } = require('./webhook-egress');
const { sendWebhookRequest } = require('./webhook-request');
const { isReservedDeliveryHeader } = require('./webhook-routing');
const { NONCE_BYTES } = require('./consts');

/**
 * The body of a test event, as the receiver gets it
 * @param {string} serviceUrl - The instance's service URL
 * @param {string} [account] - Account ID, when the test is for an account's target
 * @returns {string} JSON
 */
function testEventBody(serviceUrl, account) {
    return JSON.stringify({
        serviceUrl,
        account: account || null,
        date: new Date().toISOString(),
        event: 'test',
        data: {
            nonce: crypto.randomBytes(NONCE_BYTES).toString('base64url')
        }
    });
}

/**
 * Posts a test delivery and reports how it went. Never throws for a failed delivery: the result
 * says why it failed, which is the point of a test.
 *
 * @param {Object} options
 * @param {string} options.url - Target URL, credentials in it are sent as basic auth
 * @param {Array} [options.customHeaders] - `{ key, value }` headers to add, the X-EE-Wh-* and
 *     framing headers excepted, as for a real delivery
 * @param {string} options.body - Request body
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} `{ success, duration }`, plus `error`, `code` and `statusCode` on failure
 */
async function sendTestWebhook(options) {
    const { url, customHeaders, body, logger } = options;

    const headers = {
        'Content-Type': 'application/json',
        'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
    };

    const { url: parsed, authorization } = splitUrlCredentials(url);
    if (authorization) {
        headers.Authorization = authorization;
    }

    for (const header of [].concat(customHeaders || [])) {
        if (header && header.key && !isReservedDeliveryHeader(header.key)) {
            headers[header.key] = header.value;
        }
    }

    const hmac = crypto.createHmac('sha256', await getServiceSecret());
    hmac.update(body);
    headers['X-EE-Wh-Signature'] = hmac.digest('base64url');

    const start = Date.now();
    try {
        await sendWebhookRequest(fetchCmd, parsed.toString(), {
            method: 'post',
            body,
            headers,
            dispatcher: httpAgent.webhook,
            validateTarget: validateWebhookTarget
        });
        return { success: true, duration: Date.now() - start };
    } catch (err) {
        // undici wraps a connection failure in a generic "fetch failed"; the cause is the part
        // worth reporting back
        const failure = err.cause || err;
        // the parsed URL, not the given one, so embedded basic-auth credentials stay out of the log
        logger.warn({ msg: 'Failed to post test webhook', webhooks: parsed.toString(), event: 'test', err: failure });
        return {
            success: false,
            duration: Date.now() - start,
            error: failure.message,
            code: failure.code,
            // Same field the stored webhookErrorFlag carries, so a probe and a failed delivery are
            // described the same way
            statusCode: failure.statusCode
        };
    }
}

module.exports = { sendTestWebhook, testEventBody };
