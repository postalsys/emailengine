'use strict';

// Integration test for POST /v1/account/{account}/message/{message}/submit on the IMAP/SMTP
// path, against a live Ethereal account: upload a draft, submit it by id, and verify the full
// contract - the message is delivered (Ethereal loops sent mail back into INBOX), a messageSent
// webhook fires, a copy lands in the Sent Mail folder, and the draft disappears from Drafts.
// Also covers the failure contract (unknown message, non-draft message) and idempotency.
//
// Runs against the shared live test server (config/test.toml); global webhooks deliver to the
// shared webhooks-server on 7078.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');
const {
    createUsableTestAccount,
    waitForAccountConnected,
    waitForMessageSent,
    waitForListing,
    etherealAccountPayload,
    ACCESS_TOKEN: accessToken
} = require('./helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

const accountId = 'draft-submit-account';

test('Draft submit - IMAP/SMTP path', async t => {
    let testAccount;
    const messageId = `<draft-submit-${Date.now()}@example.com>`;
    const subject = `Draft submit e2e ${Date.now()}`;
    let draftsPath;
    let draftMessageId; // EmailEngine message id of the uploaded draft
    let queueId;

    t.before(async () => {
        testAccount = await createUsableTestAccount();
        await webhooksServer.init();
    });

    t.after(async () => {
        await webhooksServer.quit();
    });

    await t.test('Register the Ethereal account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send(Object.assign({ account: accountId, name: 'Draft Submit' }, etherealAccountPayload(testAccount)))
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('Wait until the account is connected', { timeout: 120000 }, async () => {
        await waitForAccountConnected(server, accountId, testConfig.CONNECTION_TIMEOUT);
    });

    await t.test('Locate the Drafts folder', { timeout: 30000 }, async () => {
        const response = await server.get(`/v1/account/${accountId}/mailboxes`).expect(200);
        const drafts = (response.body.mailboxes || []).find(mailbox => mailbox.specialUse === '\\Drafts');

        if (drafts) {
            draftsPath = drafts.path;
        } else {
            // No Drafts folder on this Ethereal account - create one. The \Draft flag set on
            // upload keeps the message submittable even if the new folder gains no special-use.
            await server
                .post(`/v1/account/${accountId}/mailbox`)
                .send({ path: ['Drafts'] })
                .expect(200);
            draftsPath = 'Drafts';
        }
    });

    await t.test('Upload a draft message', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account/${accountId}/message`)
            .send({
                path: draftsPath,
                flags: ['\\Draft'],
                from: { name: 'Draft Author', address: testAccount.user },
                to: [{ name: 'Draft Recipient', address: testAccount.user }],
                subject,
                text: 'Draft body',
                html: '<p>Draft body</p>',
                messageId
            })
            .expect(200);

        assert.ok(response.body.id, 'Upload must return the message id');
        draftMessageId = response.body.id;
    });

    await t.test('Submitting an unknown message fails with a 404', { timeout: 30000 }, async () => {
        // mailbox id 99 does not exist for this account
        const bogusId = Buffer.from([0, 0, 0, 99, 0, 0, 0, 1]).toString('base64url');
        const response = await server.post(`/v1/account/${accountId}/message/${bogusId}/submit`).send({}).expect(404);

        assert.strictEqual(response.body.code, 'MessageNotFound');
    });

    await t.test('Submit the draft', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account/${accountId}/message/${draftMessageId}/submit`)
            .set('Idempotency-Key', `draft-submit-${Date.now()}`)
            .send({})
            .expect(200);

        assert.strictEqual(response.body.response, 'Queued for delivery');
        assert.strictEqual(response.body.messageId, messageId, 'The queued message must keep the Message-ID of the draft');
        assert.ok(response.body.queueId, 'Should have queueId in response');
        assert.strictEqual(response.body.idempotency?.status, 'MISS');

        queueId = response.body.queueId;
    });

    await t.test('Wait for the messageSent webhook', { timeout: 60000 }, async () => {
        const messageSentWebhook = await waitForMessageSent(accountId, queueId, testConfig.WEBHOOK_TIMEOUT, 'messageSent webhook timeout');

        assert.ok(messageSentWebhook, 'Should receive the messageSent webhook');
        assert.strictEqual(messageSentWebhook.data.envelope.to[0], testAccount.user);
    });

    await t.test('The sent draft is delivered to INBOX', { timeout: 180000 }, async () => {
        // Ethereal loops the sent message back into the account's own INBOX
        const found = await waitForListing(
            server,
            accountId,
            'INBOX',
            messages => messages.find(msg => msg.messageId === messageId) || false,
            120000,
            'sent draft did not appear in INBOX'
        );

        assert.strictEqual(found.subject, subject);
    });

    await t.test('The draft is removed from the Drafts folder', { timeout: 60000 }, async () => {
        await waitForListing(
            server,
            accountId,
            draftsPath,
            messages => !messages.some(msg => msg.messageId === messageId),
            30000,
            'draft was not removed from the Drafts folder'
        );
    });

    await t.test('A copy is stored in the Sent Mail folder', { timeout: 60000 }, async () => {
        const mailboxResponse = await server.get(`/v1/account/${accountId}/mailboxes`).expect(200);
        const sentMailbox = (mailboxResponse.body.mailboxes || []).find(mailbox => mailbox.specialUse === '\\Sent');

        if (!sentMailbox) {
            // No Sent folder detected on this Ethereal account - the copy step was skipped by design
            return;
        }

        await waitForListing(
            server,
            accountId,
            sentMailbox.path,
            messages => messages.some(msg => msg.messageId === messageId),
            30000,
            'sent copy did not appear in the Sent Mail folder'
        );
    });

    await t.test('Submitting a non-draft message fails with a 400', { timeout: 60000 }, async () => {
        // The message delivered to INBOX above is not a draft
        const inboxMessage = await waitForListing(
            server,
            accountId,
            'INBOX',
            messages => messages.find(msg => msg.messageId === messageId) || false,
            30000,
            'INBOX message lookup timeout'
        );

        const response = await server.post(`/v1/account/${accountId}/message/${inboxMessage.id}/submit`).send({}).expect(400);

        assert.strictEqual(response.body.code, 'MessageNotDraft');
    });
});
