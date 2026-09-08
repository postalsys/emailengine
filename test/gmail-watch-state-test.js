'use strict';

// A Gmail account whose Pub/Sub watch cannot be renewed keeps syncing - the fallback poller runs
// every 10 minutes - so it is deliberately not an error state and nothing webhooks. The cost of
// that decision was that a dead push channel was invisible to anything driving EmailEngine over
// HTTP: the failure reached the admin page and nowhere else, and absence of it could not be told
// apart from a healthy watch.
//
// formatGmailWatch() answers the question an operator actually has - is push working right now -
// from the two records the account keeps: the last successful arm and the last failure. It quotes
// no text the provider wrote - the stored failure carries Google's response body verbatim, and its
// message is formatTokenError() output whenever a token fetch was what failed, which interpolates
// the provider's error_description - while this endpoint is reachable by a tenant token, by an MCP
// token whose contents reach an LLM, and by a session token that lives in page HTML.

const test = require('node:test');
const assert = require('node:assert').strict;

const { formatGmailWatch } = require('../lib/account/account-state');

const HOUR = 3600 * 1000;

test('formatGmailWatch()', async t => {
    await t.test('reports nothing for an account that never armed a watch', () => {
        // Every non-Gmail account, and a Gmail account before its first renewal
        assert.equal(formatGmailWatch({}), null);
        assert.equal(formatGmailWatch(null), null);
    });

    await t.test('an armed watch that has not lapsed is active', () => {
        const watch = formatGmailWatch({
            lastWatch: new Date(Date.now() - HOUR),
            watchResponse: { historyId: '3663748', expiration: String(Date.now() + 24 * HOUR) }
        });

        assert.equal(watch.state, 'active');
        assert.ok(watch.expires, 'an operator needs to know when it lapses');
        assert.ok(watch.lastCheck);
    });

    await t.test('an armed watch past its expiration is expired, not active', () => {
        const watch = formatGmailWatch({
            lastWatch: new Date(Date.now() - 8 * 24 * HOUR),
            watchResponse: { expiration: String(Date.now() - 24 * HOUR) }
        });

        assert.equal(watch.state, 'expired');
    });

    await t.test('a failed renewal is reported as an error state', () => {
        const watch = formatGmailWatch({
            lastWatch: new Date(Date.now() - 26 * HOUR),
            watchResponse: { expiration: String(Date.now() + 24 * HOUR) },
            watchFailure: { err: 'OAuth2 request failed', time: new Date(Date.now() - HOUR).toISOString() }
        });

        assert.equal(watch.state, 'error', 'a live expiration does not make a failing renewal fine');
    });

    await t.test('the reported time is the attempt, not the last success', () => {
        // The whole point of the failure record carrying its own timestamp: lastWatch stops moving
        // once renewals start failing, so reporting it would hide how stale the answer is.
        const attempted = new Date(Date.now() - HOUR).toISOString();
        const watch = formatGmailWatch({
            lastWatch: new Date(Date.now() - 8 * 24 * HOUR),
            watchResponse: { expiration: String(Date.now() - HOUR) },
            watchFailure: { err: 'OAuth2 request failed', time: attempted }
        });

        assert.equal(watch.lastCheck, attempted);
    });

    await t.test('falls back to the last successful arm when the failure predates the timestamp', () => {
        const lastWatch = new Date(Date.now() - 2 * HOUR);
        const watch = formatGmailWatch({ lastWatch, watchFailure: { err: 'OAuth2 request failed' } });

        assert.equal(watch.lastCheck, lastWatch.toISOString());
    });

    await t.test('reports nothing the provider wrote', () => {
        // The real shape of a stored rejection: Google names the operator's project and topic in
        // the body it answers with, and the message can be provider text too. Reporting either
        // would hand the operator's infrastructure naming to a tenant token.
        const watch = formatGmailWatch({
            watchFailure: {
                err: 'Error sending test message to Cloud PubSub projects/customer-prod-project/topics/ee : User not authorized to perform this action.',
                time: new Date().toISOString(),
                req: {
                    url: 'https://gmail.googleapis.com/gmail/v1/users/me/watch',
                    clientId: '1234-abcd.apps.googleusercontent.com',
                    googleProjectId: 'customer-prod-project',
                    serviceClientEmail: 'ee@customer-prod-project.iam.gserviceaccount.com',
                    response: { error: { message: 'Error sending test message to Cloud PubSub projects/customer-prod-project/topics/ee' } }
                }
            }
        });

        assert.deepEqual(Object.keys(watch).sort(), ['expires', 'lastCheck', 'state'], 'every field is derived, none is quoted');
        assert.doesNotMatch(JSON.stringify(watch), /customer-prod-project/, 'the operator project must not reach the API');
        assert.doesNotMatch(JSON.stringify(watch), /apps\.googleusercontent\.com/);
        assert.equal(watch.state, 'error', 'the failure is still reported, just not quoted');
    });
});
