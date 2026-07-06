'use strict';

// Proves that a Gmail API account with NO linked Pub/Sub app still detects new mail through the
// fallback poller. The client OAuth2 app is created WITHOUT pubSubApp, so no topic or subscription
// is ever provisioned - a messageNew for account1 can therefore ONLY come from the periodic history
// poll, never from push. The poll interval is shortened for the test run via
// EENGINE_GMAIL_FALLBACK_POLL_INTERVAL (set on the live server in Gruntfile.js).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');

const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

const account1 = 'gmail-poll-1';
const account2 = 'gmail-poll-2';

async function waitForCondition(checkFn, { interval = 1000, timeout = 120000, message = 'timeout' } = {}) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        const r = await checkFn();
        if (r) {
            return r;
        }
        await new Promise(res => setTimeout(res, interval));
    }
    throw new Error(`Timeout: ${message}`);
}

test('Gmail polling without Pub/Sub detects new mail', async t => {
    let appId;

    t.before(async () => {
        await webhooksServer.init();
    });

    t.after(async () => {
        // Remove the accounts and app so the shared live server is left clean for other test files.
        for (let account of [account1, account2]) {
            await server.delete(`/v1/account/${account}`).catch(() => {});
        }
        if (appId) {
            await server.delete(`/v1/oauth2/${appId}`).catch(() => {});
        }
        await webhooksServer.quit();
    });

    await t.test('create Gmail OAuth2 client app WITHOUT a Pub/Sub app', { timeout: 30000 }, async () => {
        const res = await server
            .post('/v1/oauth2')
            .send({
                name: 'Gmail API Client (no pubsub)',
                provider: 'gmail',
                baseScopes: 'api',
                googleProjectId: process.env.GMAIL_API_PROJECT_ID,
                clientId: process.env.GMAIL_API_CLIENT_ID,
                clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
                redirectUrl: 'http://127.0.0.1:7077/oauth'
                // deliberately no pubSubApp
            })
            .expect(200);
        appId = res.body.id;
        assert.ok(appId);

        // Confirm the app really has no Pub/Sub wiring - this is what forces polling-only mode.
        const app = await server.get(`/v1/oauth2/${appId}`).expect(200);
        assert.ok(!app.body.pubSubApp, 'app must have no linked Pub/Sub app');
        assert.ok(!app.body.pubSubTopic, 'app must have no Pub/Sub topic');
        assert.ok(!app.body.pubSubSubscription, 'app must have no Pub/Sub subscription');
    });

    await t.test('register both Gmail accounts (no push)', { timeout: 30000 }, async () => {
        await server
            .post('/v1/account')
            .send({
                account: account1,
                name: 'Poll Account 1',
                email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
                oauth2: {
                    provider: appId,
                    auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_1 },
                    refreshToken: process.env.GMAIL_API_ACCOUNT_REFRESH_1
                }
            })
            .expect(200);

        await server
            .post('/v1/account')
            .send({
                account: account2,
                name: 'Poll Account 2',
                email: process.env.GMAIL_API_ACCOUNT_EMAIL_2,
                oauth2: {
                    provider: appId,
                    auth: { user: process.env.GMAIL_API_ACCOUNT_EMAIL_2 },
                    refreshToken: process.env.GMAIL_API_ACCOUNT_REFRESH_2
                }
            })
            .expect(200);
    });

    await t.test('wait until both accounts connect', { timeout: testConfig.GMAIL_TIMEOUT }, async () => {
        for (let account of [account1, account2]) {
            await waitForCondition(
                async () => {
                    const res = await server.get(`/v1/account/${account}`).expect(200);
                    if (['authenticationError', 'connectError'].includes(res.body.state)) {
                        throw new Error(`account ${account} reached bad state ${res.body.state}`);
                    }
                    return res.body.state === 'connected';
                },
                { timeout: testConfig.GMAIL_TIMEOUT, message: `${account} did not connect` }
            );
        }
    });

    let deliveredMessageId;
    const originalMessageId = `<poll-${Date.now()}@example.com>`;

    await t.test('send a fresh message from account2 to account1', { timeout: testConfig.GMAIL_TIMEOUT }, async () => {
        const res = await server
            .post(`/v1/account/${account2}/submit`)
            .send({
                to: [{ name: 'Poll Account 1', address: process.env.GMAIL_API_ACCOUNT_EMAIL_1 }],
                subject: 'Polling proof',
                text: 'This message must be detected by account1 via the fallback poll.',
                html: '<p>Polling proof</p>',
                messageId: originalMessageId
            })
            .expect(200);
        assert.ok(res.body.messageId);

        const sent = await waitForCondition(
            async () => {
                const whs = webhooksServer.webhooks.get(account2) || [];
                return whs.find(w => w.event === 'messageSent' && w.data.originalMessageId === originalMessageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'messageSent webhook not received for account2' }
        );
        deliveredMessageId = sent.data.messageId;
        assert.ok(deliveredMessageId);
    });

    await t.test('account1 detects the new message via the fallback poll (no push)', { timeout: testConfig.GMAIL_TIMEOUT }, async () => {
        const wh = await waitForCondition(
            async () => {
                const whs = webhooksServer.webhooks.get(account1) || [];
                return whs.find(w => w.event === 'messageNew' && w.data.messageId === deliveredMessageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'messageNew webhook not received for account1 via poll' }
        );
        assert.equal(wh.data.messageId, deliveredMessageId);
        assert.equal(wh.data.subject.trim(), 'Polling proof');
    });
});
