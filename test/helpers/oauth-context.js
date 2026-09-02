'use strict';

// A fake OAuth2 client context for driving the real Gmail API and Graph API request layers
// (lib/email-client/gmail/gmail-api.js, lib/email-client/outlook/graph-api.js) without a
// network or an account. The transports take the client as their first argument and reach
// `account`, `logger`, `getTokenData()`, `invalidateAccessToken()` and `oAuth2Client.request()`
// on it, nothing else. Shared by the token-rejection and retry suites so the two do not drift.

const { noopLogger } = require('./auth-failure');

/**
 * @param {Object} [opts]
 * @param {boolean} [opts.cached] - Whether getTokenData() reports the token as served from the cache
 * @param {Array} [opts.responses] - What oAuth2Client.request() does on each successive call: a
 *     value to resolve with, or an Error to throw. The last entry repeats once the list runs out
 * @param {Function} [opts.request] - Alternative to `responses`: receives the 0-based attempt
 *     index and returns a value to resolve with, or throws
 * @returns {Object} `context` to hand to the transport, and `calls` counting `requests` and
 *     `invalidations` as they happen
 */
function createOAuth2Context({ cached = false, responses, request } = {}) {
    const calls = { requests: 0, invalidations: 0 };

    const respond =
        request ||
        (attempt => {
            const response = responses[Math.min(attempt, responses.length - 1)];
            if (response instanceof Error) {
                throw response;
            }
            return response;
        });

    const context = {
        account: 'test-account',
        logger: noopLogger,
        getTokenData: async () => ({ accessToken: 'access-token', cached }),
        invalidateAccessToken: async () => {
            calls.invalidations++;
        },
        oAuth2Client: {
            apiBase: 'https://graph.microsoft.com',
            provider: 'outlook',
            request: async () => respond(calls.requests++)
        }
    };

    return { context, calls };
}

module.exports = { createOAuth2Context };
