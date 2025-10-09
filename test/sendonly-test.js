'use strict';

require('dotenv').config({ quiet: true });

const config = require('wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');

const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

const gmailSendOnlyAccountId = 'gmail-sendonly-test';

// Helper function for polling with timeout
async function waitForCondition(checkFn, options = {}) {
    const { interval = testConfig.POLL_INTERVAL, timeout = testConfig.DEFAULT_TIMEOUT, message = 'Condition not met within timeout' } = options;

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
        const result = await checkFn();
        if (result) {
            return result;
        }
        await new Promise(r => setTimeout(r, interval));
    }

    throw new Error(`Timeout: ${message}`);
}

test('Gmail send-only account - isolated send test', async t => {
    let oauth2PubsubId;
    let oauth2SendOnlyAppId;

    t.before(async () => {
        await webhooksServer.init();
    });

    t.after(async () => {
        await webhooksServer.quit();
    });

    await t.test('Create Gmail API OAuth2 service project', { timeout: 30000 }, async () => {
        let gmailServiceData = {
            name: 'Gmail API Pub/Sub',
            provider: 'gmailService',
            baseScopes: 'pubsub',
            googleProjectId: process.env.GMAIL_API_PROJECT_ID,
            serviceClient: process.env.GMAIL_API_SERVICE_CLIENT,
            serviceClientEmail: process.env.GMAIL_API_SERVICE_EMAIL,
            serviceKey: process.env.GMAIL_API_SERVICE_KEY
        };

        const response = await server.post(`/v1/oauth2`).send(gmailServiceData).expect(200);

        oauth2PubsubId = response.body.id;
        assert.ok(oauth2PubsubId);
    });

    await t.test('Create Gmail send-only OAuth2 client project', { timeout: 30000 }, async () => {
        let gmailSendOnlyClientData = {
            name: 'Gmail API Send-Only Client',
            provider: 'gmail',
            baseScopes: 'api',
            googleProjectId: process.env.GMAIL_SENDONLY_PROJECT_ID,
            clientId: process.env.GMAIL_SENDONLY_CLIENT_ID,
            clientSecret: process.env.GMAIL_SENDONLY_CLIENT_SECRET,
            extraScopes: ['gmail.send'],
            skipScopes: ['gmail.modify'],
            redirectUrl: 'http://127.0.0.1:3000/oauth'
        };

        const response = await server.post(`/v1/oauth2`).send(gmailSendOnlyClientData).expect(200);

        oauth2SendOnlyAppId = response.body.id;
        assert.ok(oauth2SendOnlyAppId);
    });

    await t.test('Register Gmail send-only account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: gmailSendOnlyAccountId,
                name: 'Gmail Send-Only Test User',
                email: process.env.GMAIL_SENDONLY_ACCOUNT_EMAIL,
                oauth2: {
                    provider: oauth2SendOnlyAppId,
                    auth: {
                        user: process.env.GMAIL_SENDONLY_ACCOUNT_EMAIL
                    },
                    refreshToken: process.env.GMAIL_SENDONLY_ACCOUNT_REFRESH
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('Wait until Gmail send-only account is connected', { timeout: 180000 }, async () => {
        await waitForCondition(
            async () => {
                const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}`).expect(200);
                switch (response.body.state) {
                    case 'authenticationError':
                    case 'connectError':
                        throw new Error('Invalid account state ' + response.body.state);
                    case 'connected':
                        return true;
                }
                return false;
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: `Gmail send-only account connection timeout` }
        );

        // Verify account type is 'sending'
        const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}`).expect(200);
        assert.strictEqual(response.body.sendOnly, true, 'Account should be detected as send-only');
    });

    await t.test('Submit email from send-only account (no receive check)', { timeout: 60000 }, async () => {
        let messageId = `<sendonly-isolated-test-${Date.now()}@example.com>`;

        const response = await server
            .post(`/v1/account/${gmailSendOnlyAccountId}/submit`)
            .send({
                to: [
                    {
                        name: 'Test Recipient',
                        address: process.env.GMAIL_API_ACCOUNT_EMAIL_2 || 'test@example.com'
                    }
                ],
                subject: 'Isolated send-only test',
                text: 'This is a test message from send-only account - isolated test',
                html: '<p>This is a test message from <strong>send-only</strong> account - isolated test</p>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId, 'Should have messageId in response');
        assert.ok(response.body.queueId, 'Should have queueId in response');

        // Wait for messageSent webhook only - don't check for receive
        const messageSentWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailSendOnlyAccountId);
                return webhooks?.find(wh => wh.event === 'messageSent' && wh.data.originalMessageId === messageId);
            },
            { timeout: 30000, message: 'Gmail send-only message sent webhook timeout' }
        );

        assert.ok(messageSentWebhook, 'Should receive messageSent webhook');
    });

    await t.test('Cleanup - delete send-only account', { timeout: 10000 }, async () => {
        await server.delete(`/v1/account/${gmailSendOnlyAccountId}`).expect(200);
    });
});
