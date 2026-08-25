'use strict';

// End-to-end coverage for an account the auth-failure safety net has switched off.
//
// After a run of authentication failures past EENGINE_MAX_IMAP_AUTH_FAILURE_TIME, setErrorState()
// parks an account by setting `imap.disabled` and recording AUTH_FAILURE_DISABLED_FIELD beside it.
// That flag is also the operator's own send-only switch, so the marker is the only thing that tells
// the two apart - and every surface an operator or an integration reaches for has to agree about
// which one happened.
//
// The park is set up by the real writer (BaseClient.setErrorState), but grafted onto a stand-in
// receiver in THIS process rather than driven through the imap worker - reaching it for real would
// mean a mock server rejecting AUTH for three days of aged counters. So what is proven here is that
// every reader agrees with the writer's stored shape, not that the worker parks accounts;
// test/set-error-state-test.js covers the writer's own decisions.
//
// Hermetic: a mock IMAP server on localhost stands in for the mail host (only so the account has an
// `imap` blob to park and nothing storms a closed port), and no external service or credential is
// involved. A failure here is never an external flake.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');

const { ACCESS_TOKEN, startMockImapServer, extractCrumbFromHtml } = require('./helpers');
const { redis } = require('../../lib/db');
const registerRedisTeardown = require('../helpers/redis-teardown');
const { createErrorStateClient, seedExpiredErrorRun, accountKeyFor, drainSetImmediate } = require('../helpers/auth-failure');
const { AUTH_FAILURE_DISABLED_FIELD } = require('../../lib/consts');

const baseUrl = `http://127.0.0.1:${config.api.port}`;
const server = supertest.agent(baseUrl).auth(ACCESS_TOKEN, { type: 'bearer' });

// The reconnect button, whichever attributes it carries
const reconnectButtonOf = html => (/<button[^>]*id="request-reconnect"[^>]*>/.exec(html) || [])[0];

registerRedisTeardown(redis);

async function parkAccount(account) {
    await seedExpiredErrorRun(redis, account);

    const client = createErrorStateClient({ redis, account });
    const notified = await client.setErrorState('authenticationError', { serverResponseCode: 'AUTH', response: 'auth failed' });

    // Keeps the aged counters above honest: a seed that no longer trips the threshold would
    // otherwise leave every assertion below testing an account that was never switched off.
    assert.strictEqual(notified, true, 'the safety net reports switching an account off');

    await drainSetImmediate();
}

test('An account switched off after authentication failures', async t => {
    const account = `park-${crypto.randomBytes(4).toString('hex')}`;
    const mock = await startMockImapServer();

    t.after(async () => {
        try {
            await server.delete(`/v1/account/${account}`);
        } catch (err) {
            // the account may not exist if the test failed early
        }
        await mock.close();
    });

    await server
        .post('/v1/account')
        .send({
            account,
            name: `Auth failure park test (${account})`,
            email: `${account}@example.com`,
            imap: {
                host: '127.0.0.1',
                port: mock.port,
                secure: false,
                auth: { user: 'testuser', pass: 'pass' },
                resyncDelay: 3600
            }
        })
        .expect(200);

    await parkAccount(account);

    // Minted once per run and reused from the cookie the agent carries, so it is read from the
    // first page that renders it rather than re-fetched per subtest.
    let crumb;

    await t.test('the API states the park rather than leaving it to be inferred', async () => {
        const response = await server.get(`/v1/account/${account}`).expect(200);

        assert.ok(response.body.authFailureDisabledAt, 'authFailureDisabledAt must be reported');
        assert.ok(!Number.isNaN(Date.parse(response.body.authFailureDisabledAt)), 'and must be a timestamp');
        assert.strictEqual(response.body.imap.disabled, true, 'the account is switched off');
    });

    await t.test('the listing carries it too, so a fleet-wide park can be found without opening each account', async () => {
        const response = await server.get(`/v1/accounts?query=${account}`).expect(200);

        const entry = response.body.accounts.find(item => item.account === account);
        assert.ok(entry, 'the account must be listed');
        assert.ok(entry.authFailureDisabledAt, 'the listing entry must carry authFailureDisabledAt');
    });

    await t.test('a reconnect is refused rather than reported as done', async () => {
        // init() checks the disable flag before it dials out, so the dispatch cannot resume a
        // parked account. Answering "reconnecting" to a caller whose account then stays offline is
        // the defect the disabled button is only the cosmetic half of.
        const response = await server.put(`/v1/account/${account}/reconnect`).send({ reconnect: true }).expect(200);
        assert.strictEqual(response.body.reconnect, false, 'the API must not claim a reconnect it did not perform');
    });

    await t.test('the admin page offers Resume syncing and withholds Reconnect', async () => {
        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        crumb = extractCrumbFromHtml(response.text);
        assert.ok(crumb, 'the admin page must carry a CSRF crumb');

        assert.match(response.text, /Syncing was switched off/, 'the page says why the account stopped');
        assert.match(response.text, /id="request-resume"/, 'and offers the control that can fix it');

        const reconnectButton = reconnectButtonOf(response.text);
        assert.ok(reconnectButton, 'the reconnect button must still be rendered');
        assert.match(reconnectButton, /\bdisabled\b/, 'but disabled while the account is switched off');
    });

    await t.test('the admin reconnect route refuses too, so the disabled button is not the only guard', async () => {
        const response = await server.post(`/admin/accounts/${account}/reconnect`).send({ crumb }).expect(200);

        assert.strictEqual(response.body.success, false, 'a posted reconnect must be refused while the account is switched off');
        assert.match(response.body.error, /Resume syncing/, 'and must name the control that does work');
    });

    await t.test('resuming lifts the disable and the marker with it', async () => {
        const response = await server.post(`/admin/accounts/${account}/resume`).send({ crumb }).expect(200);
        assert.strictEqual(response.body.success, true, `resume failed: ${JSON.stringify(response.body)}`);

        const accountData = await server.get(`/v1/account/${account}`).expect(200);
        assert.strictEqual(accountData.body.authFailureDisabledAt, null, 'the account is no longer reported as switched off');
        assert.strictEqual(accountData.body.imap.disabled, false, 'and syncing is enabled again');
        assert.strictEqual(await redis.hget(accountKeyFor(account), AUTH_FAILURE_DISABLED_FIELD), null, 'the marker is retired');
    });

    await t.test('resuming an account that was not switched off by EmailEngine is refused', async () => {
        const response = await server.post(`/admin/accounts/${account}/resume`).send({ crumb }).expect(200);
        assert.strictEqual(response.body.success, false, 'nothing left to resume');
    });

    await t.test('the admin page offers Reconnect again once the account is back', async () => {
        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        assert.doesNotMatch(response.text, /Syncing was switched off/, 'the alert is gone');
        const reconnectButton = reconnectButtonOf(response.text);
        assert.ok(reconnectButton, 'the reconnect button is still there');
        assert.doesNotMatch(reconnectButton, /\bdisabled\b/, 'and usable again');
    });
});
