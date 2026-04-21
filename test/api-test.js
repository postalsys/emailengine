'use strict';

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const nodemailer = require('nodemailer');
const Redis = require('ioredis');
const redis = new Redis(config.dbs.redis);
const webhooksServer = require('./webhooks-server');

const { fetch: fetchCmd } = require('undici');

const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

let testAccount;
const defaultAccountId = 'main-account';
const gmailAccountId1 = 'gmail-account1';
const gmailAccountId2 = 'gmail-account2';
const gmailSendOnlyAccountId = 'gmail-sendonly-account';
const outlookServiceAccountId = 'outlook-service-account';
const gmailServiceAccountId = 'gmail-service-account';

// Helper: acquire MS Graph token using client_credentials flow
async function getGraphToken() {
    let tokenRes = await fetchCmd(`https://login.microsoftonline.com/${process.env.OUTLOOK_SERVICE_TENANT_ID}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: process.env.OUTLOOK_SERVICE_CLIENT_ID,
            client_secret: process.env.OUTLOOK_SERVICE_CLIENT_SECRET,
            scope: 'https://graph.microsoft.com/.default',
            grant_type: 'client_credentials'
        })
    });
    let tokenData = await tokenRes.json();
    return tokenData.access_token;
}

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

test('API tests', async t => {
    let message2;
    let oauth2PubsubId;
    let oauth2AppId;

    let gmailReceivedEmailId;
    let gmailReceivedMessageId;

    let oauth2SendOnlyAppId;

    let outlookServiceAppId;
    let outlookReceivedEmailId;

    let gmailServiceAppId;

    t.before(async () => {
        testAccount = await nodemailer.createTestAccount();
        await webhooksServer.init();
    });

    t.after(async () => {
        redis.quit();
        await webhooksServer.quit();
    });

    await t.test('list existing users (empty list)', async () => {
        const response = await server.get(`/v1/accounts`).expect(200);

        assert.strictEqual(response.body.accounts.length, 0);
    });

    await t.test('Verify IMAP account', async () => {
        const response = await server
            .post(`/v1/verifyAccount`)
            .send({
                mailboxes: true,
                imap: {
                    host: testAccount.imap.host,
                    port: testAccount.imap.port,
                    secure: testAccount.imap.secure,
                    auth: {
                        user: testAccount.user,
                        pass: testAccount.pass
                    }
                },
                smtp: {
                    host: testAccount.smtp.host,
                    port: testAccount.smtp.port,
                    secure: testAccount.smtp.secure,
                    auth: {
                        user: testAccount.user,
                        pass: testAccount.pass
                    }
                }
            })
            .expect(200);

        assert.strictEqual(response.body.imap.success, true);
        assert.strictEqual(response.body.smtp.success, true);
        // Check if Inbox folder exists
        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('Register new IMAP account', async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: defaultAccountId,
                name: 'Test User 🫥',
                email: testAccount.user,
                imap: {
                    host: testAccount.imap.host,
                    port: testAccount.imap.port,
                    secure: testAccount.imap.secure,
                    auth: {
                        user: testAccount.user,
                        pass: testAccount.pass
                    },
                    resyncDelay: 60 * 1000
                },
                smtp: {
                    host: testAccount.smtp.host,
                    port: testAccount.smtp.port,
                    secure: testAccount.smtp.secure,
                    auth: {
                        user: testAccount.user,
                        pass: testAccount.pass
                    }
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('wait until added account is available', { timeout: 60000 }, async () => {
        // wait until connected with timeout

        await waitForCondition(
            async () => {
                const response = await server.get(`/v1/account/${defaultAccountId}`).expect(200);
                switch (response.body.state) {
                    case 'authenticationError':
                    case 'connectError':
                        throw new Error('Invalid account state ' + response.body.state);
                    case 'connected':
                        return true;
                }
                return false;
            },
            { timeout: testConfig.CONNECTION_TIMEOUT, message: 'Account connection timeout' }
        );

        // check if we have all expected webhooks
        let webhooks = webhooksServer.webhooks.get(defaultAccountId);

        for (let event of ['accountAdded', 'authenticationSuccess', 'accountInitialized']) {
            assert.ok(webhooks.some(wh => wh.event === event));
        }
    });

    await t.test('list existing users (1 account)', async () => {
        const response = await server.get(`/v1/accounts`).expect(200);

        assert.strictEqual(response.body.accounts.length, 1);
    });

    await t.test('check if account credentials are encrypted', async () => {
        let accountData = await redis.hgetall(`iad:${defaultAccountId}`);
        let imapData = JSON.parse(accountData.imap);
        let smtpData = JSON.parse(accountData.smtp);

        assert.ok(imapData.auth.pass.indexOf('$wd01$') === 0);
        assert.ok(smtpData.auth.pass.indexOf('$wd01$') === 0);
    });

    await t.test('list mailboxes for an account', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/mailboxes`).expect(200);

        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('list inbox messages (empty)', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/messages?path=INBOX`).expect(200);

        assert.strictEqual(response.body.total, 0);
    });

    await t.test('upload email to Inbox and wait for a messageNew webhook', { timeout: 60000 }, async () => {
        const response1 = await server
            .post(`/v1/account/${defaultAccountId}/message`)
            .send({
                path: 'Inbox',
                flags: ['\\Seen'],
                from: {
                    name: 'Test Sender',
                    address: 'test.sender@example.com'
                },
                to: [
                    {
                        name: 'Test Received',
                        address: 'test.received@example.com'
                    }
                ],
                subject: 'Test message 🤣',
                text: 'Hello world! 🙃',
                html: '<b>Hello world! 🙃</b>',
                messageId: '<test1@example.com>'
            })
            .expect(200);
        assert.ok(response1.body.id);

        const response2 = await server
            .post(`/v1/account/${defaultAccountId}/message`)
            .send({
                path: 'Inbox',
                flags: [],
                from: {
                    name: 'Test Sender',
                    address: 'test.sender@example.com'
                },
                to: [
                    {
                        name: 'Test Received',
                        address: 'test.received@example.com'
                    }
                ],
                subject: 'Test message 🤣',
                text: 'Hello world! 🙃',
                html: '<b>Hello world! 🙃</b>',
                messageId: '<test2@example.com>',
                attachments: [
                    {
                        filename: 'transparent.gif',
                        content: 'R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=',
                        contentType: 'image/gif',
                        contentDisposition: 'inline',
                        encoding: 'base64'
                    }
                ]
            })
            .expect(200);

        assert.ok(response2.body.id);

        const { messageNewWebhook1, messageNewWebhook2 } = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(defaultAccountId);
                const webhook1 = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test1@example.com>');
                const webhook2 = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test2@example.com>');
                if (webhook1 && webhook2) {
                    return { messageNewWebhook1: webhook1, messageNewWebhook2: webhook2 };
                }
                return false;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'Webhook notification timeout' }
        );

        message2 = messageNewWebhook2.data;

        assert.equal(messageNewWebhook1.data.subject, 'Test message 🤣');
    });

    await t.test('list inbox messages (2 messages)', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/messages?path=INBOX`).expect(200);

        assert.strictEqual(response.body.total, 2);
        assert.equal(response.body.messages[0].messageId, '<test2@example.com>');
    });

    await t.test('list mailboxes with counters', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/mailboxes?counters=true`).expect(200);
        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox' && mb.status.messages === 2 && mb.status.unseen === 1));
    });

    await t.test('retrieve message text', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/text/${message2.text.id}?textType=*`).expect(200);
        assert.deepEqual(response.body, { plain: 'Hello world! 🙃', html: '<b>Hello world! 🙃</b>', hasMore: false });
    });

    await t.test('download attachment', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/attachment/${message2.attachments[0].id}`).expect(200);

        assert.strictEqual(response.headers['content-type'], `image/gif`);
        assert.strictEqual(response.headers['content-disposition'], `attachment; filename="transparent.gif"; filename*=utf-8''transparent.gif`);

        let attachment = response._body.toString('base64');

        assert.strictEqual(attachment, 'R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=');
    });

    await t.test('get message information', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/message/${message2.id}?textType=*`).expect(200);

        let message = response.body;

        assert.strictEqual(message.id, message2.id);
        assert.strictEqual(message.subject, 'Test message 🤣');
        assert.strictEqual(message.messageSpecialUse, '\\Inbox');
        assert.strictEqual(message.text.plain, 'Hello world! 🙃');
        assert.strictEqual(message.text.html, '<b>Hello world! 🙃</b>');
        assert.ok(!message.text.webSafe);
    });

    await t.test('get message information, websafe', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/message/${message2.id}?webSafeHtml=true`).expect(200);

        let message = response.body;

        assert.strictEqual(message.id, message2.id);
        assert.strictEqual(message.subject, 'Test message 🤣');
        assert.strictEqual(message.messageSpecialUse, '\\Inbox');
        assert.strictEqual(message.text.plain, 'Hello world! 🙃');
        assert.strictEqual(message.text.html, '<div style="overflow: auto;"><b>Hello world! 🙃</b></div>');
        assert.strictEqual(message.text.webSafe, true);
    });

    await t.test('download raw message', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/message/${message2.id}/source`).expect(200);

        assert.strictEqual(response.headers['content-type'], `message/rfc822`);
        assert.strictEqual(response.headers['content-disposition'], `attachment; filename=message.eml`);

        let eml = response.text;

        assert.ok(/^Message-ID:/im.test(eml));
    });

    await t.test('search unseen messages', async () => {
        const response = await server
            .post(`/v1/account/${defaultAccountId}/search?path=INBOX`)
            .send({
                search: {
                    unseen: true
                }
            })
            .expect(200);

        assert.strictEqual(response.body.total, 1);
        assert.strictEqual(response.body.messages[0].messageId, '<test2@example.com>');
    });

    await t.test('mark message as seen', { timeout: 60000 }, async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/message/${message2.id}`)
            .send({
                flags: {
                    add: ['\\Seen']
                }
            })
            .expect(200);

        assert.ok(response.body.flags.add);

        const messageUpdatedWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(defaultAccountId);
                return webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageUpdated' && wh.data.id === message2.id);
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'Message update webhook timeout' }
        );

        assert.deepEqual(messageUpdatedWebhook.data.changes.flags.added, ['\\Seen']);
    });

    await t.test('upload by reference', { timeout: 60000 }, async () => {
        await server
            .post(`/v1/account/${defaultAccountId}/message`)
            .send({
                path: 'Inbox',
                reference: {
                    message: message2.id,
                    action: 'forward',
                    inline: true,
                    forwardAttachments: true,
                    messageId: '<invalid@value>'
                },
                to: [
                    {
                        name: 'Test Received',
                        address: 'test.received@example.com'
                    }
                ],
                text: 'Hallo hallo! 🙃',
                html: '<b>Hallo hallo! 🙃</b>',
                messageId: '<test3@example.com>'
            })
            // fails message-id test
            .expect(404);

        const response = await server
            .post(`/v1/account/${defaultAccountId}/message`)
            .send({
                path: 'Inbox',
                reference: {
                    message: message2.id,
                    action: 'forward',
                    inline: true,
                    forwardAttachments: true,
                    messageId: '<test2@example.com>'
                },
                to: [
                    {
                        name: 'Test Received',
                        address: 'test.received@example.com'
                    }
                ],
                text: 'Hallo hallo! 🙃',
                html: '<b>Hallo hallo! 🙃</b>',
                messageId: '<test3@example.com>'
            })
            .expect(200);

        assert.ok(response.body.id);

        const messageNewWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(defaultAccountId);
                return webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test3@example.com>');
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'Message upload webhook timeout' }
        );

        assert.ok(/Begin forwarded message/.test(messageNewWebhook.data.text.plain));
        assert.strictEqual(messageNewWebhook.data.attachments[0].filename, 'transparent.gif');
        assert.strictEqual(messageNewWebhook.data.subject, 'Fwd: Test message 🤣');
    });

    await t.test('submit by reference', { timeout: 60000 }, async () => {
        const response = await server
            .post(`/v1/account/${defaultAccountId}/submit`)
            .send({
                reference: {
                    message: message2.id,
                    action: 'forward',
                    inline: true,
                    forwardAttachments: true,
                    messageId: '<test2@example.com>'
                },
                to: [
                    {
                        name: 'Test Received',
                        address: 'test.received@example.com'
                    }
                ],
                text: 'Hallo hallo! 🙃',
                html: '<b>Hallo hallo! 🙃</b>',
                messageId: '<test4@example.com>'
            })
            .expect(200);

        assert.ok(response.body.messageId);
        assert.ok(response.body.queueId);

        const messageNewWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(defaultAccountId);
                return webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test4@example.com>');
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'Submit webhook timeout' }
        );

        assert.ok(/Begin forwarded message/.test(messageNewWebhook.data.text.plain));
        assert.strictEqual(messageNewWebhook.data.attachments[0].filename, 'transparent.gif');
        assert.strictEqual(messageNewWebhook.data.subject, 'Fwd: Test message 🤣');
    });

    await t.test('create a mailbox', { timeout: 60000 }, async () => {
        const response = await server
            .post(`/v1/account/${defaultAccountId}/mailbox`)
            .send({
                path: ['My Target Folder 😇']
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Target Folder 😇');
        assert.ok(response.body.created);

        const mailboxNewWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(defaultAccountId);
                return webhooks.find(wh => wh.path === 'My Target Folder 😇' && wh.event === 'mailboxNew');
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'Mailbox creation webhook timeout' }
        );

        assert.ok(mailboxNewWebhook);
    });

    await t.test('modify mailbox - rename only', { timeout: 60000 }, async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/mailbox`)
            .send({
                path: 'My Target Folder 😇',
                newPath: 'My Renamed Folder'
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Target Folder 😇');
        assert.strictEqual(response.body.newPath, 'My Renamed Folder');
        assert.strictEqual(response.body.renamed, true);

        const mailboxListResponse = await server.get(`/v1/account/${defaultAccountId}/mailboxes`).expect(200);
        const renamedMailbox = mailboxListResponse.body.mailboxes.find(mb => mb.path === 'My Renamed Folder');
        assert.ok(renamedMailbox, 'Renamed mailbox should exist');
    });

    await t.test('modify mailbox - subscription only', { timeout: 60000 }, async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/mailbox`)
            .send({
                path: 'My Renamed Folder',
                subscribed: false
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Renamed Folder');
        assert.strictEqual(response.body.subscribed, false);
    });

    await t.test('modify mailbox - both rename and subscription', { timeout: 60000 }, async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/mailbox`)
            .send({
                path: 'My Renamed Folder',
                newPath: 'My Final Folder',
                subscribed: true
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Renamed Folder');
        assert.strictEqual(response.body.newPath, 'My Final Folder');
        assert.strictEqual(response.body.renamed, true);
        assert.strictEqual(response.body.subscribed, true);

        const mailboxListResponse = await server.get(`/v1/account/${defaultAccountId}/mailboxes`).expect(200);
        const finalMailbox = mailboxListResponse.body.mailboxes.find(mb => mb.path === 'My Final Folder');
        assert.ok(finalMailbox, 'Final mailbox should exist');
    });

    await t.test('move message to another folder', { timeout: 60000 }, async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/message/${message2.id}/move`)
            .send({
                path: 'My Final Folder'
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Final Folder');

        assert.strictEqual(response.body.uid, 1);

        const responseSearchTarget = await server
            .post(`/v1/account/${defaultAccountId}/search?path=${encodeURIComponent('My Final Folder')}`)
            .send({
                search: {
                    uid: '1'
                }
            })
            .expect(200);

        assert.strictEqual(responseSearchTarget.body.total, 1);
        assert.strictEqual(responseSearchTarget.body.messages[0].messageId, '<test2@example.com>');
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

    await t.test('Create Gmail API OAuth2 client project', { timeout: 30000 }, async () => {
        let gmailClientData = {
            name: 'Gmail API Client',
            provider: 'gmail',
            baseScopes: 'api',
            googleProjectId: process.env.GMAIL_API_PROJECT_ID,
            clientId: process.env.GMAIL_API_CLIENT_ID,
            clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
            pubSubApp: oauth2PubsubId,
            redirectUrl: 'http://127.0.0.1:7003/oauth'
        };

        const response = await server.post(`/v1/oauth2`).send(gmailClientData).expect(200);

        oauth2AppId = response.body.id;
        assert.ok(oauth2AppId);
    });

    await t.test('Register Gmail account 1', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: gmailAccountId1,
                name: 'Gmail User 1 🫥',
                email: process.env.GMAIL_API_ACCOUNT_EMAIL_1,
                oauth2: {
                    provider: oauth2AppId,
                    auth: {
                        user: process.env.GMAIL_API_ACCOUNT_EMAIL_1
                    },
                    refreshToken: process.env.GMAIL_API_ACCOUNT_REFRESH_1
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('Register Gmail account 2', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: gmailAccountId2,
                name: 'Gmail User 2 🫥',
                email: process.env.GMAIL_API_ACCOUNT_EMAIL_2,
                oauth2: {
                    provider: oauth2AppId,
                    auth: {
                        user: process.env.GMAIL_API_ACCOUNT_EMAIL_2
                    },
                    refreshToken: process.env.GMAIL_API_ACCOUNT_REFRESH_2
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('wait until Gmail accounts are available', { timeout: 120000 }, async () => {
        for (let account of [gmailAccountId1, gmailAccountId2]) {
            // wait until connected with longer timeout for Gmail
            await waitForCondition(
                async () => {
                    const response = await server.get(`/v1/account/${account}`).expect(200);
                    switch (response.body.state) {
                        case 'authenticationError':
                        case 'connectError':
                            throw new Error('Invalid account state ' + response.body.state);
                        case 'connected':
                            return true;
                    }
                    return false;
                },
                { timeout: testConfig.GMAIL_TIMEOUT, message: `Gmail account ${account} connection timeout` }
            );

            // check if we have all expected webhooks
            let webhooks = webhooksServer.webhooks.get(account);
            for (let event of ['accountAdded', 'authenticationSuccess', 'accountInitialized']) {
                assert.ok(webhooks.some(wh => wh.event === event));
            }
        }
    });

    await t.test('list mailboxes for Gmail account 1', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${gmailAccountId1}/mailboxes`).expect(200);

        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('list inbox messages for Gmail account 1 (greeting emails)', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${gmailAccountId1}/messages?path=INBOX`).expect(200);

        assert.ok(response.body.total > 0);
    });

    await t.test('submit by API', { timeout: 120000 }, async () => {
        let messageId = `<test-${Date.now()}@example.com>`;

        const response = await server
            .post(`/v1/account/${gmailAccountId2}/submit`)
            .send({
                to: [
                    {
                        name: 'Test Account 1',
                        address: process.env.GMAIL_API_ACCOUNT_EMAIL_1
                    }
                ],
                subject: 'Hallo hallo 🤣',
                text: 'Hallo hallo! 🙃',
                html: '<b>Hallo hallo! 🙃</b>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId);
        assert.ok(response.body.queueId);

        const messageSentWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailAccountId2);
                return webhooks.find(wh => wh.event === 'messageSent' && wh.data.originalMessageId === messageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'Gmail message sent webhook timeout' }
        );

        gmailReceivedMessageId = messageSentWebhook.data.messageId;

        const messageNewWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailAccountId1);
                return webhooks.find(wh => wh.event === 'messageNew' && wh.data.messageId === gmailReceivedMessageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'Gmail message receive webhook timeout' }
        );

        // * is added by gmail
        assert.strictEqual(messageNewWebhook.data.text.plain.trim(), '*Hallo hallo! 🙃*');
        assert.strictEqual(messageNewWebhook.data.messageId, gmailReceivedMessageId);
        assert.strictEqual(messageNewWebhook.data.subject.trim(), 'Hallo hallo 🤣');

        gmailReceivedEmailId = messageNewWebhook.data.id;
        assert.ok(gmailReceivedEmailId);
    });

    await t.test('reply by reference by API', { timeout: 120000 }, async () => {
        let messageId = `<test-${Date.now()}@example.com>`;

        const response = await server
            .post(`/v1/account/${gmailAccountId1}/submit`)
            .send({
                reference: {
                    message: gmailReceivedEmailId,
                    action: 'reply',
                    inline: true
                },
                text: 'Keedu kartul! 🍟',
                html: '<b>Keedu kartul! 🍟</b>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId);
        assert.ok(response.body.queueId);

        let finalMessageId;

        const messageSentWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailAccountId1);
                return webhooks.find(wh => wh.event === 'messageSent' && wh.data.originalMessageId === messageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'Gmail reply sent webhook timeout' }
        );

        finalMessageId = messageSentWebhook.data.messageId;

        const messageNewWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailAccountId2);
                return webhooks.find(wh => wh.event === 'messageNew' && wh.data.messageId === finalMessageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'Gmail reply receive webhook timeout' }
        );

        assert.strictEqual(messageNewWebhook.data.subject.trim(), 'Re: Hallo hallo 🤣');
        assert.strictEqual(messageNewWebhook.data.inReplyTo, gmailReceivedMessageId);

        assert.ok(messageNewWebhook);
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
                name: 'Gmail Send-Only User',
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

    await t.test('wait until Gmail send-only account is available', { timeout: 180000 }, async () => {
        // wait until connected with longer timeout for Gmail
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

        // check account type
        const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}`).expect(200);
        assert.strictEqual(response.body.sendOnly, true, 'Account should be detected as send-only');

        // check if we have expected webhooks
        let webhooks = webhooksServer.webhooks.get(gmailSendOnlyAccountId);
        for (let event of ['accountAdded', 'authenticationSuccess', 'accountInitialized']) {
            assert.ok(webhooks.some(wh => wh.event === event));
        }
    });

    await t.test('send-only account - list mailboxes should fail', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}/mailboxes`).expect(403);

        // Gmail API will reject the request due to insufficient scopes
        assert.ok(response.body.error);
    });

    await t.test('send-only account - list messages should fail', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}/messages?path=INBOX`).expect(403);

        // Gmail API will reject the request due to insufficient scopes
        assert.ok(response.body.error);
    });

    await t.test('send-only account - get message should fail', { timeout: 30000 }, async () => {
        // Use a message ID from gmailAccountId2 to try to access it
        if (!gmailReceivedEmailId) {
            throw new Error('No message ID available for testing');
        }

        const response = await server.get(`/v1/account/${gmailSendOnlyAccountId}/message/${gmailReceivedEmailId}`).expect(403);

        // Gmail API will reject the request due to insufficient scopes
        assert.ok(response.body.error);
    });

    await t.test('send-only account - submit email successfully', { timeout: 180000 }, async () => {
        let messageId = `<sendonly-test-${Date.now()}@example.com>`;

        const response = await server
            .post(`/v1/account/${gmailSendOnlyAccountId}/submit`)
            .send({
                to: [
                    {
                        name: 'Test Account 2',
                        address: process.env.GMAIL_API_ACCOUNT_EMAIL_2
                    }
                ],
                subject: 'Send-only test message',
                text: 'This message was sent from a send-only account',
                html: '<p>This message was sent from a <strong>send-only</strong> account</p>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId);
        assert.ok(response.body.queueId);

        // Wait for messageSent webhook on send-only account
        const messageSentWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(gmailSendOnlyAccountId);
                return webhooks.find(wh => wh.event === 'messageSent' && wh.data.originalMessageId === messageId);
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: 'Gmail send-only message sent webhook timeout' }
        );
        assert.ok(messageSentWebhook);

        // Cannot verify the final Gmail-assigned message ID because send-only accounts
        // lack read permissions for the Sent Mail folder. Gmail assigns a new message ID
        // that differs from the original messageId sent in the request.
    });

    // --- Outlook Service (client_credentials) tests ---

    await t.test('Create Outlook Service OAuth2 app', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/oauth2`)
            .send({
                name: 'Outlook Service Test App',
                provider: 'outlookService',
                baseScopes: 'api',
                clientId: process.env.OUTLOOK_SERVICE_CLIENT_ID,
                clientSecret: process.env.OUTLOOK_SERVICE_CLIENT_SECRET,
                authority: process.env.OUTLOOK_SERVICE_TENANT_ID
            })
            .expect(200);

        outlookServiceAppId = response.body.id;
        assert.ok(outlookServiceAppId);
    });

    await t.test('Register Outlook Service account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: outlookServiceAccountId,
                name: 'Outlook Service Test',
                email: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL,
                oauth2: {
                    provider: outlookServiceAppId,
                    auth: {
                        user: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL
                    }
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('wait until Outlook Service account is connected', { timeout: 120000 }, async () => {
        await waitForCondition(
            async () => {
                const response = await server.get(`/v1/account/${outlookServiceAccountId}`).expect(200);
                switch (response.body.state) {
                    case 'authenticationError':
                    case 'connectError':
                        throw new Error('Invalid account state ' + response.body.state);
                    case 'connected':
                        return true;
                }
                return false;
            },
            { timeout: testConfig.OUTLOOK_TIMEOUT, message: 'Outlook Service account connection timeout' }
        );
    });

    await t.test('list mailboxes for Outlook Service account', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${outlookServiceAccountId}/mailboxes`).expect(200);

        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('list inbox messages for Outlook Service account', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${outlookServiceAccountId}/messages?path=INBOX`).expect(200);

        assert.ok(typeof response.body.total === 'number');
    });

    await t.test('send email via Outlook Service account', { timeout: 120000 }, async () => {
        let messageId = `<outlook-test-${Date.now()}@example.com>`;

        const response = await server
            .post(`/v1/account/${outlookServiceAccountId}/submit`)
            .send({
                to: [
                    {
                        name: 'Outlook Service Test',
                        address: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL
                    }
                ],
                subject: 'Outlook Service test message',
                text: 'This is a test from Outlook Service account',
                html: '<p>This is a test from <strong>Outlook Service</strong> account</p>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId);
        assert.ok(response.body.queueId);

        // Wait for messageSent webhook (internal EmailEngine webhook, always works)
        const messageSentWebhook = await waitForCondition(
            async () => {
                let webhooks = webhooksServer.webhooks.get(outlookServiceAccountId);
                return webhooks.find(wh => wh.event === 'messageSent' && wh.data.originalMessageId === messageId);
            },
            { timeout: testConfig.OUTLOOK_TIMEOUT, message: 'Outlook Service message sent webhook timeout' }
        );

        assert.ok(messageSentWebhook);

        // MS Graph push notifications require HTTPS and a publicly reachable URL,
        // so messageNew webhooks won't arrive in the test environment.
        // Instead, poll the inbox API directly until the sent message appears.
        const receivedMessage = await waitForCondition(
            async () => {
                const messagesRes = await server.get(`/v1/account/${outlookServiceAccountId}/messages?path=INBOX`).expect(200);
                return messagesRes.body.messages.find(msg => msg.subject === 'Outlook Service test message');
            },
            { timeout: testConfig.OUTLOOK_TIMEOUT, message: 'Outlook Service message receive timeout' }
        );

        assert.ok(receivedMessage);
        outlookReceivedEmailId = receivedMessage.id;
        assert.ok(outlookReceivedEmailId);
    });

    await t.test('get Outlook Service message details', { timeout: 30000 }, async () => {
        assert.ok(outlookReceivedEmailId, 'Need received email ID from previous test');

        const response = await server.get(`/v1/account/${outlookServiceAccountId}/message/${outlookReceivedEmailId}`).expect(200);

        assert.strictEqual(response.body.subject, 'Outlook Service test message');
        assert.ok(response.body.from);
    });

    await t.test('get Outlook Service message text', { timeout: 30000 }, async () => {
        assert.ok(outlookReceivedEmailId, 'Need received email ID from previous test');

        const response = await server.get(`/v1/account/${outlookServiceAccountId}/text/${outlookReceivedEmailId}`).expect(200);

        assert.ok(response.body.plain || response.body.html);
    });

    await t.test('download Outlook Service raw message', { timeout: 30000 }, async () => {
        assert.ok(outlookReceivedEmailId, 'Need received email ID from previous test');

        const response = await server.get(`/v1/account/${outlookServiceAccountId}/message/${outlookReceivedEmailId}/source`).expect(200);

        assert.ok(response.text.length > 0);
    });

    await t.test('search messages in Outlook Service account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account/${outlookServiceAccountId}/search?path=INBOX`)
            .send({
                search: {
                    unseen: true
                }
            })
            .expect(200);

        assert.ok(Array.isArray(response.body.messages));
    });

    await t.test('update message flags in Outlook Service account', { timeout: 60000 }, async () => {
        assert.ok(outlookReceivedEmailId, 'Need received email ID from previous test');

        const response = await server
            .put(`/v1/account/${outlookServiceAccountId}/message/${outlookReceivedEmailId}`)
            .send({
                flags: {
                    add: ['\\Seen']
                }
            })
            .expect(200);

        assert.ok(response.body.flags);
    });

    await t.test('delete message in Outlook Service account', { timeout: 30000 }, async () => {
        assert.ok(outlookReceivedEmailId, 'Need received email ID from previous test');

        const response = await server.delete(`/v1/account/${outlookServiceAccountId}/message/${outlookReceivedEmailId}`).expect(200);

        assert.ok(response.body.deleted);
    });

    // --- Outlook Graph API behavior tests (verify syncMissedMessages assumptions) ---

    await t.test('Graph API message query returns messages from all folders with parentFolderId', { timeout: testConfig.OUTLOOK_TIMEOUT }, async () => {
        let graphToken = await getGraphToken();
        assert.ok(graphToken, 'Should receive access token');
        let email = process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL;

        // Query recent messages with parentFolderId - same pattern as syncMissedMessages
        let sinceTime = new Date(Date.now() - 30 * 60 * 1000).toISOString();
        let queryParams = new URLSearchParams({
            $filter: `receivedDateTime gt ${sinceTime}`,
            $select: 'id,parentFolderId',
            $top: '10',
            $orderby: 'receivedDateTime desc'
        });

        let messagesRes = await fetchCmd(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}/messages?${queryParams}`, {
            headers: {
                Authorization: `Bearer ${graphToken}`,
                Prefer: 'IdType="ImmutableId"'
            }
        });
        assert.equal(messagesRes.status, 200, 'Should return 200');

        let messagesData = await messagesRes.json();
        assert.ok(Array.isArray(messagesData.value), 'Should return value array');
        assert.ok(messagesData.value.length > 0, 'Should have at least one recent message');

        // Every message should have both id and parentFolderId
        for (let msg of messagesData.value) {
            assert.ok(msg.id, 'Message should have id');
            assert.ok(msg.parentFolderId, 'Message should have parentFolderId');
        }

        // Messages should come from multiple folders (Inbox, Sent Items, etc.)
        let distinctFolders = new Set(messagesData.value.map(m => m.parentFolderId));
        assert.ok(distinctFolders.size > 1, `Should have messages from multiple folders, got ${distinctFolders.size}`);
    });

    await t.test('Graph API pagination returns @odata.nextLink', { timeout: testConfig.OUTLOOK_TIMEOUT }, async () => {
        let graphToken = await getGraphToken();
        let email = process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL;

        // Query with $top=1 to force pagination
        let sinceTime = new Date(Date.now() - 30 * 60 * 1000).toISOString();
        let queryParams = new URLSearchParams({
            $filter: `receivedDateTime gt ${sinceTime}`,
            $select: 'id',
            $top: '1',
            $orderby: 'receivedDateTime desc'
        });

        let page1Res = await fetchCmd(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}/messages?${queryParams}`, {
            headers: {
                Authorization: `Bearer ${graphToken}`,
                Prefer: 'IdType="ImmutableId"'
            }
        });
        assert.equal(page1Res.status, 200);

        let page1Data = await page1Res.json();
        assert.ok(Array.isArray(page1Data.value), 'First page should have value array');
        assert.equal(page1Data.value.length, 1, 'First page should have exactly 1 message');
        assert.ok(page1Data['@odata.nextLink'], 'Should have @odata.nextLink for more results');

        // Follow the nextLink
        let page2Res = await fetchCmd(page1Data['@odata.nextLink'], {
            headers: {
                Authorization: `Bearer ${graphToken}`,
                Prefer: 'IdType="ImmutableId"'
            }
        });
        assert.equal(page2Res.status, 200);

        let page2Data = await page2Res.json();
        assert.ok(Array.isArray(page2Data.value), 'Second page should have value array');
        assert.ok(page2Data.value.length > 0, 'Second page should have at least one message');

        // First page and second page should have different message IDs
        assert.notEqual(page1Data.value[0].id, page2Data.value[0].id, 'Pages should return different messages');
    });

    // --- Gmail Service Account (IMAP XOAUTH2) tests ---

    await t.test('Create gmailService OAuth2 app', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/oauth2`)
            .send({
                name: 'Gmail Service Account (IMAP XOAUTH2)',
                provider: 'gmailService',
                serviceClient: process.env.GMAIL_SERVICE_POSTALSYS_CLIENT,
                serviceClientEmail: process.env.GMAIL_SERVICE_POSTALSYS_SERVICE_EMAIL,
                serviceKey: process.env.GMAIL_SERVICE_POSTALSYS_KEY
            })
            .expect(200);

        gmailServiceAppId = response.body.id;
        assert.ok(gmailServiceAppId);
    });

    await t.test('Register gmailService account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: gmailServiceAccountId,
                name: 'Gmail Service User',
                email: process.env.GMAIL_SERVICE_POSTALSYS_ACCOUNT_EMAIL,
                oauth2: {
                    provider: gmailServiceAppId,
                    auth: {
                        user: process.env.GMAIL_SERVICE_POSTALSYS_ACCOUNT_EMAIL
                    }
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('wait until gmailService account connects via IMAP XOAUTH2', { timeout: 120000 }, async () => {
        let lastResponse;
        await waitForCondition(
            async () => {
                lastResponse = await server.get(`/v1/account/${gmailServiceAccountId}`).expect(200);
                switch (lastResponse.body.state) {
                    case 'authenticationError':
                    case 'connectError':
                        throw new Error('Invalid account state ' + lastResponse.body.state);
                    case 'connected':
                        return true;
                }
                return false;
            },
            { timeout: testConfig.GMAIL_TIMEOUT, message: `Gmail Service account connection timeout` }
        );

        assert.notStrictEqual(lastResponse.body.isApi, true, 'gmailService should use IMAP XOAUTH2, not the API path');
    });

    await t.test('list mailboxes for gmailService account', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${gmailServiceAccountId}/mailboxes`).expect(200);

        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('delete gmailService account', { timeout: 30000 }, async () => {
        const response = await server.delete(`/v1/account/${gmailServiceAccountId}`).expect(200);

        assert.ok(response.body.deleted);
    });

    await t.test('delete gmailService OAuth2 app', { timeout: 30000 }, async () => {
        const response = await server.delete(`/v1/oauth2/${gmailServiceAppId}`).expect(200);

        assert.ok(response.body.deleted);
    });
});
