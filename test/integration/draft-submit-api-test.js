'use strict';

// Integration tests for POST /v1/account/{account}/message/{message}/submit on the API-backed
// account types, against live providers (same credentials as api-test.js):
//
//  - Gmail: every DRAFT-labeled Gmail message is wrapped in a draft resource (even
//    messages.insert uploads get one, and Gmail backfills a Message-ID when the raw has none),
//    which EmailEngine resolves via an rfc822msgid drafts.list search and submits through the
//    single drafts.send call. Gmail itself moves the message from Drafts to Sent. The raw-send
//    fallback (draft resource unresolvable: search-index lag or a drafts.list error) can not
//    be forced deterministically against live Gmail, so that branch is covered by the unit
//    tests in test/draft-submit-test.js instead.
//  - MS Graph: the upload API creates a real Graph draft; the submit uses the single
//    /messages/{id}/send call and Graph itself files the message into Sent Items and removes
//    the draft.
//
// Standalone on purpose: api-test.js runs its whole suite inside one 180s parent-test budget,
// so these provider round-trips live in their own file (the sendonly-test.js pattern). All
// messages are self-addressed; Gmail delivery is verified against the Sent Mail listing because
// Gmail dedupes a self-addressed delivery that reuses the Message-ID of the already-stored sent
// copy, so the message may never surface in INBOX. Message listings for API accounts query the
// provider live, so no Gmail push/Graph push is needed. Subtests are skipped when the
// credentials are not present in the environment.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');
const { waitForAccountConnected, waitForMessageSent, waitForListing, ACCESS_TOKEN: accessToken } = require('./helpers');

const { fetch: fetchCmd } = require('undici');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(accessToken, { type: 'bearer' });

const gmailAccountId = 'draft-api-gmail';
const outlookAccountId = 'draft-api-outlook';

const gmailSkip =
    process.env.GMAIL_API_CLIENT_ID && process.env.GMAIL_API_CLIENT_SECRET && process.env.GMAIL_API_ACCOUNT_EMAIL_2 && process.env.GMAIL_API_ACCOUNT_REFRESH_2
        ? false
        : 'GMAIL_API_* environment variables are not set';

const outlookSkip =
    process.env.OUTLOOK_SERVICE_CLIENT_ID &&
    process.env.OUTLOOK_SERVICE_CLIENT_SECRET &&
    process.env.OUTLOOK_SERVICE_TENANT_ID &&
    process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL
        ? false
        : 'OUTLOOK_SERVICE_* environment variables are not set';

// Mint a Gmail access token for direct Gmail API calls (drafts.create/drafts.get have no
// EmailEngine API equivalent)
async function getGmailAccessToken() {
    const tokenRes = await fetchCmd('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: process.env.GMAIL_API_CLIENT_ID,
            client_secret: process.env.GMAIL_API_CLIENT_SECRET,
            refresh_token: process.env.GMAIL_API_ACCOUNT_REFRESH_2,
            grant_type: 'refresh_token'
        })
    });
    const tokenData = await tokenRes.json();
    assert.ok(tokenData.access_token, 'Gmail token exchange must succeed');
    return tokenData.access_token;
}

test('Draft submit - Gmail API', { skip: gmailSkip, timeout: 600000 }, async t => {
    let oauth2AppId;

    t.before(async () => {
        await webhooksServer.init();
    });

    t.after(async () => {
        await webhooksServer.quit();
    });

    await t.test('Create Gmail OAuth2 app', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/oauth2`)
            .send({
                name: 'Draft Submit Gmail Client',
                provider: 'gmail',
                baseScopes: 'api',
                googleProjectId: process.env.GMAIL_API_PROJECT_ID,
                clientId: process.env.GMAIL_API_CLIENT_ID,
                clientSecret: process.env.GMAIL_API_CLIENT_SECRET,
                redirectUrl: 'http://127.0.0.1:7003/oauth'
            })
            .expect(200);

        oauth2AppId = response.body.id;
        assert.ok(oauth2AppId);
    });

    await t.test('Register Gmail account', { timeout: 120000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: gmailAccountId,
                name: 'Draft Submit Gmail',
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

        await waitForAccountConnected(server, gmailAccountId, testConfig.GMAIL_TIMEOUT);
    });

    await t.test('submit an uploaded Gmail draft by id', { timeout: 180000 }, async () => {
        const messageId = `<draft-gmail-${Date.now()}@example.com>`;
        const subject = `Gmail draft submit ${Date.now()}`;

        // Uploaded drafts carry a Message-ID, so the submit normally resolves the wrapping
        // draft resource and sends through drafts.send (raw fallback if the search index lags -
        // the assertions below hold for both paths)
        const uploadResponse = await server
            .post(`/v1/account/${gmailAccountId}/message`)
            .send({
                path: '\\Drafts',
                flags: ['\\Draft'],
                from: { name: 'Draft Submit', address: process.env.GMAIL_API_ACCOUNT_EMAIL_2 },
                to: [{ name: 'Draft Submit', address: process.env.GMAIL_API_ACCOUNT_EMAIL_2 }],
                subject,
                text: 'Draft submit body',
                html: '<p>Draft submit body</p>',
                messageId
            })
            .expect(200);

        assert.ok(uploadResponse.body.id);

        const submitResponse = await server.post(`/v1/account/${gmailAccountId}/message/${uploadResponse.body.id}/submit`).send({}).expect(200);

        assert.strictEqual(submitResponse.body.response, 'Queued for delivery');
        assert.strictEqual(submitResponse.body.messageId, messageId, 'The queued message must keep the Message-ID of the draft');
        assert.ok(submitResponse.body.queueId);

        await waitForMessageSent(gmailAccountId, submitResponse.body.queueId, testConfig.GMAIL_TIMEOUT, 'Gmail draft sent webhook timeout');

        // The sent message is filed into Sent Mail (by Gmail itself on the drafts.send path,
        // by the raw send on the fallback path)
        await waitForListing(
            server,
            gmailAccountId,
            '\\Sent',
            messages => messages.some(msg => msg.subject === subject),
            testConfig.GMAIL_TIMEOUT,
            'sent Gmail draft did not appear in Sent Mail'
        );

        // The draft is gone from the Drafts folder
        await waitForListing(
            server,
            gmailAccountId,
            '\\Drafts',
            messages => !messages.some(msg => msg.messageId === messageId),
            testConfig.GMAIL_TIMEOUT,
            'Gmail draft was not removed from the Drafts folder'
        );
    });

    await t.test('submit a native Gmail draft by id (drafts.send path)', { timeout: 180000 }, async () => {
        const subject = `Gmail native draft ${Date.now()}`;

        // Create a real draft resource with drafts.create straight against the Gmail API.
        // Note that Gmail rewrites the Message-ID of drafts created this way
        const gmailAccessToken = await getGmailAccessToken();

        const rawMessage = [
            `From: ${process.env.GMAIL_API_ACCOUNT_EMAIL_2}`,
            `To: ${process.env.GMAIL_API_ACCOUNT_EMAIL_2}`,
            `Subject: ${subject}`,
            'Content-Type: text/plain; charset=utf-8',
            '',
            'Native draft body'
        ].join('\r\n');

        const draftCreateRes = await fetchCmd('https://gmail.googleapis.com/gmail/v1/users/me/drafts', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${gmailAccessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: { raw: Buffer.from(rawMessage).toString('base64url') } })
        });
        assert.ok(draftCreateRes.ok, 'drafts.create must succeed');
        const draftData = await draftCreateRes.json();
        assert.ok(draftData.id, 'draft resource id expected');
        assert.ok(draftData.message?.id, 'draft message id expected');

        const submitResponse = await server.post(`/v1/account/${gmailAccountId}/message/${draftData.message.id}/submit`).send({}).expect(200);

        assert.ok(submitResponse.body.messageId, 'The queued message must carry the Message-ID of the draft');
        assert.ok(submitResponse.body.queueId);

        const messageSentWebhook = await waitForMessageSent(
            gmailAccountId,
            submitResponse.body.queueId,
            testConfig.GMAIL_TIMEOUT,
            'Gmail native draft sent webhook timeout'
        );
        assert.strictEqual(messageSentWebhook.data.originalMessageId, submitResponse.body.messageId);

        // Gmail moved the sent draft into Sent Mail
        await waitForListing(
            server,
            gmailAccountId,
            '\\Sent',
            messages => messages.some(msg => msg.subject === subject),
            testConfig.GMAIL_TIMEOUT,
            'sent native Gmail draft did not appear in Sent Mail'
        );

        // drafts.send consumed the draft resource
        const draftGetRes = await fetchCmd(`https://gmail.googleapis.com/gmail/v1/users/me/drafts/${draftData.id}`, {
            headers: { Authorization: `Bearer ${gmailAccessToken}` }
        });
        assert.strictEqual(draftGetRes.status, 404, 'the draft resource must be gone after sending');
    });

    await t.test('submitting a non-draft Gmail message fails with a 400', { timeout: 60000 }, async () => {
        // Any non-draft message works here; Sent Mail is guaranteed non-empty by the previous tests
        const sentMessages = await waitForListing(
            server,
            gmailAccountId,
            '\\Sent',
            messages => (messages.length ? messages : false),
            30000,
            'Sent Mail listing timeout'
        );

        const response = await server.post(`/v1/account/${gmailAccountId}/message/${sentMessages[0].id}/submit`).send({}).expect(400);

        assert.strictEqual(response.body.code, 'MessageNotDraft');
    });
});

test('Draft submit - MS Graph', { skip: outlookSkip, timeout: 600000 }, async t => {
    let outlookAppId;

    t.before(async () => {
        await webhooksServer.init();
    });

    t.after(async () => {
        await webhooksServer.quit();
    });

    await t.test('Create Outlook Service OAuth2 app', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/oauth2`)
            .send({
                name: 'Draft Submit Outlook App',
                provider: 'outlookService',
                baseScopes: 'api',
                clientId: process.env.OUTLOOK_SERVICE_CLIENT_ID,
                clientSecret: process.env.OUTLOOK_SERVICE_CLIENT_SECRET,
                authority: process.env.OUTLOOK_SERVICE_TENANT_ID
            })
            .expect(200);

        outlookAppId = response.body.id;
        assert.ok(outlookAppId);
    });

    await t.test('Register Outlook Service account', { timeout: 120000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send({
                account: outlookAccountId,
                name: 'Draft Submit Outlook',
                email: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL,
                oauth2: {
                    provider: outlookAppId,
                    auth: {
                        user: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL
                    }
                }
            })
            .expect(200);

        assert.strictEqual(response.body.state, 'new');

        await waitForAccountConnected(server, outlookAccountId, testConfig.OUTLOOK_TIMEOUT);
    });

    await t.test('submit an uploaded Outlook draft by id', { timeout: 180000 }, async () => {
        const subject = `Outlook draft submit ${Date.now()}`;

        // The upload API creates a real Graph draft, so submitting it exercises the native
        // /messages/{id}/send call. Graph files the sent message into Sent Items and removes
        // it from Drafts itself
        const uploadResponse = await server
            .post(`/v1/account/${outlookAccountId}/message`)
            .send({
                path: '\\Drafts',
                // Without the \Draft flag the upload clears the MAPI mfUnsent bit and the
                // created message would not be a Graph draft (isDraft: false)
                flags: ['\\Draft'],
                from: { name: 'Draft Submit', address: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL },
                to: [{ name: 'Draft Submit', address: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL }],
                subject,
                text: 'Outlook draft body',
                html: '<p>Outlook draft body</p>'
            })
            .expect(200);

        assert.ok(uploadResponse.body.id);
        const draftMessageId = uploadResponse.body.messageId;
        assert.ok(draftMessageId, 'Upload must return the Message-ID of the draft');

        const submitResponse = await server.post(`/v1/account/${outlookAccountId}/message/${uploadResponse.body.id}/submit`).send({}).expect(200);

        assert.strictEqual(submitResponse.body.response, 'Queued for delivery');
        assert.ok(submitResponse.body.queueId);

        const messageSentWebhook = await waitForMessageSent(
            outlookAccountId,
            submitResponse.body.queueId,
            testConfig.OUTLOOK_TIMEOUT,
            'Outlook draft sent webhook timeout'
        );
        assert.ok(messageSentWebhook);

        // Self-addressed: the sent message must arrive back in INBOX
        await waitForListing(
            server,
            outlookAccountId,
            'INBOX',
            messages => messages.some(msg => msg.subject === subject),
            testConfig.OUTLOOK_TIMEOUT,
            'sent Outlook draft did not arrive in INBOX'
        );

        // Graph removed the draft from the Drafts folder on send
        await waitForListing(
            server,
            outlookAccountId,
            '\\Drafts',
            messages => !messages.some(msg => msg.messageId === draftMessageId),
            testConfig.OUTLOOK_TIMEOUT,
            'Outlook draft was not removed from the Drafts folder'
        );
    });

    await t.test('submitting a non-draft Outlook message fails with a 400', { timeout: 60000 }, async () => {
        const inboxMessages = await waitForListing(
            server,
            outlookAccountId,
            'INBOX',
            messages => (messages.length ? messages : false),
            30000,
            'INBOX listing timeout'
        );

        const response = await server.post(`/v1/account/${outlookAccountId}/message/${inboxMessages[0].id}/submit`).send({}).expect(400);

        assert.strictEqual(response.body.code, 'MessageNotDraft');
    });
});
