'use strict';

// Both API clients report a failed OAuth2 token refresh through the same
// BaseClient.reportTokenRefreshFailure(), so both suites assert the same contract: an endpoint that
// throttles or 5xxs is left for the caller to retry, and only a refused refresh token is announced
// and parked. Kept here rather than written out twice so the two cannot drift, the same reason
// test/helpers/oauth-context.js exists for the pair.

const test = require('node:test');
const assert = require('node:assert').strict;

const tokenError = statusCode => Object.assign(new Error('Token request failed'), { code: 'ETokenRefresh', statusCode });

/**
 * Runs the shared token-refresh classification suite against one API client.
 *
 * @param {Object} t - The enclosing node:test context
 * @param {Function} makeClient - Builds a client with `logger` and `setStateVal` already stubbed
 * @param {String} serverResponseCode - The code the client reports a refused token under
 * @returns {Promise<void>}
 */
async function assertTokenRefreshClassification(t, makeClient, serverResponseCode = 'TokenGenerationError') {
    const withFailure = err => {
        const client = makeClient();
        client.state = 'connecting';
        client.setStateVal = async () => {};
        client.notifications = [];
        client.notify = async (mailbox, event, data) => {
            client.notifications.push({ event, data });
        };
        client.accountObject = {
            getActiveAccessTokenData: async () => {
                throw err;
            }
        };
        return client;
    };

    for (const statusCode of [429, 503]) {
        await t.test(`an endpoint answering ${statusCode} is left for the caller to retry`, async () => {
            const client = withFailure(tokenError(statusCode));

            await assert.rejects(
                () => client.getToken(),
                err => {
                    assert.equal(err.authenticationFailed, undefined, 'must not be marked as an authentication failure');
                    return true;
                }
            );

            assert.deepEqual(client.notifications, [], 'no authenticationError webhook');
            assert.equal(client.state, 'connecting', 'the account must not be parked');
        });
    }

    await t.test('a refused refresh token is still reported as an authentication failure', async () => {
        // 400 invalid_grant is the expired or revoked refresh token this event exists to report
        const client = withFailure(tokenError(400));

        await assert.rejects(
            () => client.getToken(),
            err => {
                assert.equal(err.authenticationFailed, true);
                return true;
            }
        );

        assert.equal(client.state, 'authenticationError');
        assert.equal(client.notifications.length, 1);
        assert.equal(client.notifications[0].event, 'authenticationError');
        assert.equal(client.notifications[0].data.serverResponseCode, serverResponseCode);
    });
}

// Registers the suite as a top-level test for one client.
function testTokenRefreshClassification(name, makeClient) {
    test(name, async t => assertTokenRefreshClassification(t, makeClient));
}

module.exports = { assertTokenRefreshClassification, testTokenRefreshClassification, tokenError };
