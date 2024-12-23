'use strict';

const config = require('wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const nodemailer = require('nodemailer');

const accessToken = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

let testAccount;
const defaultAccountId = 'main-account';

test('API tests', async t => {
    t.before(async () => {
        testAccount = await nodemailer.createTestAccount();
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

        assert.strictEqual(response.body.state, 'new');

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
    });

    await t.test('list existing users (1 account)', async () => {
        const response = await server.get(`/v1/accounts`).expect(200);

        assert.strictEqual(response.body.accounts.length, 1);
    });

    await t.test('list mailboxes for an account', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/mailboxes`).expect(200);

        assert.ok(response.body.mailboxes.some(mb => mb.specialUse === '\\Inbox'));
    });

    await t.test('list inbox messages (empty)', async () => {
        const response = await server.get(`/v1/account/${defaultAccountId}/messages?path=INBOX`).expect(200);

        assert.strictEqual(response.body.total, 0);
    });
});
