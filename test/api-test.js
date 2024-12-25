'use strict';

const config = require('wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const nodemailer = require('nodemailer');
const Redis = require('ioredis');
const redis = new Redis(config.dbs.redis);
const webhooksServer = require('./webhooks-server');

const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

let testAccount;
const defaultAccountId = 'main-account';

test('API tests', async t => {
    let message2;

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

    await t.test('wait until added account is available', async () => {
        // wait until connected
        let available = false;
        while (!available) {
            await new Promise(r => setTimeout(r, 1000));
            const response = await server.get(`/v1/account/${defaultAccountId}`).expect(200);
            switch (response.body.state) {
                case 'authenticationError':
                case 'connectError':
                    throw new Error('Invalid account state ' + response.body.state);
                case 'connected':
                    available = true;
                    break;
            }
        }

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

    await t.test('upload email to Inbox and wait for a messageNew webhook', async () => {
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

        let received = false;
        let messageNewWebhook1 = false;
        let messageNewWebhook2 = false;
        while (!received) {
            await new Promise(r => setTimeout(r, 1000));
            let webhooks = webhooksServer.webhooks.get(defaultAccountId);
            messageNewWebhook1 = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test1@example.com>');
            messageNewWebhook2 = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test2@example.com>');
            if (messageNewWebhook1 && messageNewWebhook2) {
                received = true;
            }
        }

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

    await t.test('mark message as seen', async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/message/${message2.id}`)
            .send({
                flags: {
                    add: ['\\Seen']
                }
            })
            .expect(200);

        assert.ok(response.body.flags.add);

        let received = false;
        let messageUpdatedWebhook = false;
        while (!received) {
            await new Promise(r => setTimeout(r, 1000));
            let webhooks = webhooksServer.webhooks.get(defaultAccountId);
            messageUpdatedWebhook = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageUpdated' && wh.data.id === message2.id);
            if (messageUpdatedWebhook) {
                received = true;
            }
        }

        assert.deepEqual(messageUpdatedWebhook.data.changes.flags.added, ['\\Seen']);
    });

    await t.test('upload by reference', async () => {
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

        let received = false;
        let messageNewWebhook = false;
        while (!received) {
            await new Promise(r => setTimeout(r, 1000));
            let webhooks = webhooksServer.webhooks.get(defaultAccountId);
            messageNewWebhook = webhooks.find(wh => wh.path === 'INBOX' && wh.event === 'messageNew' && wh.data.messageId === '<test3@example.com>');
            if (messageNewWebhook) {
                received = true;
            }
        }

        assert.ok(/Begin forwarded message/.test(messageNewWebhook.data.text.plain));
        assert.strictEqual(messageNewWebhook.data.attachments[0].filename, 'transparent.gif');
        assert.strictEqual(messageNewWebhook.data.subject, 'Fwd: Test message 🤣');
    });

    await t.test('create a mailbox', async () => {
        const response = await server
            .post(`/v1/account/${defaultAccountId}/mailbox`)
            .send({
                path: ['My Target Folder 😇']
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Target Folder 😇');
        assert.ok(response.body.created);

        let received = false;
        let mailboxNewWebhook = false;
        while (!received) {
            await new Promise(r => setTimeout(r, 1000));
            let webhooks = webhooksServer.webhooks.get(defaultAccountId);
            mailboxNewWebhook = webhooks.find(wh => wh.path === 'My Target Folder 😇' && wh.event === 'mailboxNew');
            if (mailboxNewWebhook) {
                received = true;
            }
        }

        assert.ok(mailboxNewWebhook);
    });

    await t.test('move message to another folder', async () => {
        const response = await server
            .put(`/v1/account/${defaultAccountId}/message/${message2.id}/move`)
            .send({
                path: 'My Target Folder 😇'
            })
            .expect(200);

        assert.strictEqual(response.body.path, 'My Target Folder 😇');

        assert.strictEqual(response.body.uid, 1);

        const responseSearchTarget = await server
            .post(`/v1/account/${defaultAccountId}/search?path=${encodeURIComponent('My Target Folder 😇')}`)
            .send({
                search: {
                    uid: '1'
                }
            })
            .expect(200);

        assert.strictEqual(responseSearchTarget.body.total, 1);
        assert.strictEqual(responseSearchTarget.body.messages[0].messageId, '<test2@example.com>');
    });
});
