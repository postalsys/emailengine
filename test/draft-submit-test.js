'use strict';

// Unit coverage for the draft-submit flow (POST /v1/account/{account}/message/{message}/submit).
//
// Covers the pure request builders (Gmail drafts.send, Graph /messages/{id}/send) and the
// backend-specific resolveDraftForSubmit() / submitMessage() draft branches with the network
// collaborators stubbed. The full queue round-trip runs in the integration tier against a live
// server (test/integration/draft-submit-test.js and draft-submit-api-test.js).

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable } = require('stream');

const { buildDraftSendRequest: buildGmailDraftSendRequest } = require('../lib/email-client/gmail/send-request');
const { buildDraftSendRequest: buildGraphDraftSendRequest } = require('../lib/email-client/outlook/send-request');

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { SentMailCopyDecider } = require('../lib/email-client/message-builder');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring the clients pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

const noopLogger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
        return noopLogger;
    }
};

function buildRawDraft(messageIdHeaderName) {
    return Buffer.from(`From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Draft\r\n${messageIdHeaderName}: <draft-1@example.com>\r\n\r\nHello`);
}

const RAW_DRAFT = buildRawDraft('Message-ID');

test('draft send request builders', async t => {
    await t.test('Gmail: drafts.send request carries the draft id as JSON', () => {
        const { targetEndpoint, contentType, payload } = buildGmailDraftSendRequest('r-draft-123');

        assert.strictEqual(targetEndpoint, '/gmail/v1/users/me/drafts/send');
        assert.strictEqual(contentType, 'application/json');
        assert.deepStrictEqual(payload, { id: 'r-draft-123' });
    });

    await t.test('Graph: draft send posts an empty body to /messages/{id}/send', () => {
        const { path, body, options } = buildGraphDraftSendRequest('AAMkAD-msg-1', 'me');

        assert.strictEqual(path, '/me/messages/AAMkAD-msg-1/send');
        assert.ok(Buffer.isBuffer(body), 'body must be a Buffer so the request is not JSON-serialized');
        assert.strictEqual(body.length, 0, 'Graph requires Content-Length: 0');
        assert.strictEqual(options.returnText, true, 'send answers 202 Accepted with an empty body');
    });

    await t.test('Graph: draft send respects the user path of delegated accounts', () => {
        const { path } = buildGraphDraftSendRequest('AAMkAD-msg-1', 'users/shared@example.com');

        assert.strictEqual(path, '/users/shared@example.com/messages/AAMkAD-msg-1/send');
    });
});

// Draft cleanup permanence: after an SMTP send the draft is deleted permanently only when a
// Sent Mail copy exists - uploaded by EmailEngine, or filed by the provider itself. This
// predicate decides the "provider files it itself" half (and doubles as the reason the Sent
// upload is suppressed for these accounts in shouldCopy).
test('SentMailCopyDecider.providerSavesSentCopy', async t => {
    await t.test('Gmail over SMTP stores the sent copy itself', () => {
        assert.strictEqual(SentMailCopyDecider.providerSavesSentCopy({ accountData: {}, isGmail: true, isOutlook: false, gatewayData: null }), true);
    });

    await t.test('non-delegated Outlook over SMTP stores the sent copy itself', () => {
        assert.strictEqual(SentMailCopyDecider.providerSavesSentCopy({ accountData: {}, isGmail: false, isOutlook: true, gatewayData: null }), true);
    });

    await t.test('delegated Outlook does not - the sender is different', () => {
        const accountData = { oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        assert.strictEqual(SentMailCopyDecider.providerSavesSentCopy({ accountData, isGmail: false, isOutlook: true, gatewayData: null }), false);
    });

    await t.test('a gateway send bypasses the provider, so nothing is stored', () => {
        assert.strictEqual(
            SentMailCopyDecider.providerSavesSentCopy({ accountData: {}, isGmail: true, isOutlook: false, gatewayData: { gateway: 'gw1' } }),
            false
        );
    });

    await t.test('a plain IMAP server does not store SMTP-sent messages', () => {
        assert.strictEqual(SentMailCopyDecider.providerSavesSentCopy({ accountData: {}, isGmail: false, isOutlook: false, gatewayData: null }), false);
    });

    await t.test('shouldCopy still suppresses the upload exactly when the provider files the copy', () => {
        const accountData = { imap: {} };
        const suppressed = SentMailCopyDecider.shouldCopy({ accountData, data: {}, isGmail: true, isOutlook: false, gatewayData: null });
        const uploaded = SentMailCopyDecider.shouldCopy({ accountData, data: {}, isGmail: false, isOutlook: false, gatewayData: null });
        assert.strictEqual(suppressed, false);
        assert.strictEqual(uploaded, true);
    });
});

// Stub the network layer of a client. The `responses` list is [urlSubstring, response] pairs
// matched in order; a response may be a value, an Error to throw, or a function of the request.
// Returns the recorded calls.
function stubRequests(client, responses) {
    const calls = [];
    client.logger = noopLogger;
    client.prepare = async () => {};
    client.request = async (url, method, payload, options) => {
        calls.push({ url, method, payload, options });
        for (let [match, response] of responses) {
            if (url.includes(match)) {
                if (response instanceof Error) {
                    throw response;
                }
                return typeof response === 'function' ? response({ url, method, payload }) : response;
            }
        }
        throw new Error(`Unexpected request: ${method} ${url}`);
    };
    return calls;
}

function makeGmailClient(responses) {
    const gmail = new GmailClient('test-account', {});
    const calls = stubRequests(gmail, responses);
    return { gmail, calls };
}

function makeOutlookClient(responses) {
    const outlook = new OutlookClient('test-account', {});
    outlook.oauth2UserPath = 'me';
    const calls = stubRequests(outlook, responses);
    return { outlook, calls };
}

function oauthApiError(status, code = status) {
    let err = new Error('OAuth2 request failed');
    err.oauthRequest = { status, response: { error: { code, message: `HTTP ${status}` } } };
    return err;
}

// The format=raw messages.get response Gmail serves for a draft
function gmailRawDraftResponse(raw) {
    return {
        id: 'msg-1',
        threadId: 'thread-1',
        labelIds: ['DRAFT'],
        raw: raw.toString('base64url')
    };
}

test('GmailClient.resolveDraftForSubmit', async t => {
    await t.test('resolves the draft resource id for a real draft', async () => {
        const { gmail, calls } = makeGmailClient([
            [
                '/drafts',
                {
                    drafts: [
                        { id: 'r-other', message: { id: 'msg-other' } },
                        { id: 'r-draft-1', message: { id: 'msg-1' } }
                    ]
                }
            ],
            ['/messages/msg-1', gmailRawDraftResponse(RAW_DRAFT)]
        ]);

        const result = await gmail.resolveDraftForSubmit('msg-1');

        assert.deepStrictEqual(result.draft, { message: 'msg-1', draftId: 'r-draft-1' });
        assert.strictEqual(result.threadId, 'thread-1');
        assert.deepStrictEqual(result.raw, RAW_DRAFT);

        const draftsListCall = calls.find(call => call.url.includes('/drafts'));
        assert.strictEqual(draftsListCall.payload.q, 'rfc822msgid:<draft-1@example.com>');
    });

    await t.test('finds the Message-ID header case-insensitively', async () => {
        const rawVariant = buildRawDraft('Message-Id');
        const { gmail } = makeGmailClient([
            ['/drafts', { drafts: [{ id: 'r-draft-1', message: { id: 'msg-1' } }] }],
            ['/messages/msg-1', gmailRawDraftResponse(rawVariant)]
        ]);

        const result = await gmail.resolveDraftForSubmit('msg-1');

        assert.strictEqual(result.draft.draftId, 'r-draft-1');
    });

    await t.test('returns a null draft id when no draft resource matches', async () => {
        const { gmail } = makeGmailClient([
            ['/drafts', { drafts: [] }],
            ['/messages/msg-1', gmailRawDraftResponse(RAW_DRAFT)]
        ]);

        const result = await gmail.resolveDraftForSubmit('msg-1');

        assert.strictEqual(result.draft.draftId, null);
        assert.strictEqual(result.threadId, 'thread-1');
    });

    await t.test('rejects a message that does not carry the DRAFT label', async () => {
        const { gmail } = makeGmailClient([['/messages/msg-1', { id: 'msg-1', labelIds: ['INBOX'], raw: RAW_DRAFT.toString('base64url') }]]);

        await assert.rejects(gmail.resolveDraftForSubmit('msg-1'), err => err.code === 'MessageNotDraft' && err.statusCode === 400);
    });

    await t.test('maps an unknown message to a 404', async () => {
        const { gmail } = makeGmailClient([['/messages/msg-x', oauthApiError(404)]]);

        await assert.rejects(gmail.resolveDraftForSubmit('msg-x'), err => err.code === 'MessageNotFound' && err.statusCode === 404);
    });
});

// Stub the submit-side collaborators of a client (queue job, account data, notifications)
function armSubmitStubs(client, accountData) {
    client.accountObject = { loadAccountData: async () => accountData };
    client.submitQueue = { getJob: async () => ({ updateProgress: async () => {} }) };
    const notifications = [];
    client.notify = async (mailbox, event, payload) => {
        notifications.push({ event, payload });
    };
    return notifications;
}

const QUEUE_ENTRY = () => ({
    queueId: 'queue-1',
    messageId: '<draft-1@example.com>',
    envelope: { from: 'sender@example.com', to: ['recipient@example.com'] },
    raw: RAW_DRAFT,
    job: { id: 'queue-1', attemptsMade: 0, attempts: 10 }
});

test('GmailClient.submitMessage draft handling', async t => {
    await t.test('uses drafts.send when a draft resource exists', async () => {
        const { gmail, calls } = makeGmailClient([['/drafts/send', { id: 'msg-sent-1', threadId: 'thread-1', labelIds: ['SENT'] }]]);
        // Send-only scopes: the post-send Message-ID refetch is skipped, keeping the stub minimal
        const notifications = armSubmitStubs(gmail, { oauth2: { accessToken: { scope: ['https://www.googleapis.com/auth/gmail.send'] } } });

        const data = Object.assign(QUEUE_ENTRY(), { draft: { message: 'msg-1', draftId: 'r-draft-1' }, reference: { threadId: 'thread-1' } });
        const result = await gmail.submitMessage(data);

        assert.strictEqual(result.messageId, '<draft-1@example.com>');
        assert.strictEqual(calls.length, 1, 'only the drafts.send call is expected');
        assert.deepStrictEqual(calls[0].payload, { id: 'r-draft-1' });
        assert.strictEqual(notifications.length, 1);
        assert.strictEqual(notifications[0].payload.queueId, 'queue-1');
    });

    await t.test('falls back to a raw send plus trash for an unresolved draft resource', async () => {
        const { gmail, calls } = makeGmailClient([
            ['/messages/send', { id: 'msg-sent-1', threadId: 'thread-1', labelIds: ['SENT'] }],
            ['/messages/msg-1/trash', { id: 'msg-1', labelIds: ['TRASH'] }]
        ]);
        armSubmitStubs(gmail, { oauth2: { accessToken: { scope: ['https://www.googleapis.com/auth/gmail.send'] } } });

        const data = Object.assign(QUEUE_ENTRY(), { draft: { message: 'msg-1', draftId: null }, reference: { threadId: 'thread-1' } });
        await gmail.submitMessage(data);

        const sendCall = calls.find(call => call.url.includes('/messages/send'));
        assert.ok(sendCall, 'raw message send expected');
        assert.strictEqual(sendCall.payload.threadId, 'thread-1', 'the sent copy must stay in the draft thread');
        assert.deepStrictEqual(Buffer.from(sendCall.payload.raw, 'base64url'), RAW_DRAFT);

        assert.ok(
            calls.find(call => call.url.includes('/messages/msg-1/trash')),
            'the origin draft message must be moved to Trash'
        );
    });
});

test('OutlookClient.resolveDraftForSubmit', async t => {
    await t.test('accepts a Graph draft and returns its raw content', async () => {
        const { outlook } = makeOutlookClient([
            ['/$value', RAW_DRAFT],
            ['/messages/msg-1', { id: 'msg-1', isDraft: true }]
        ]);

        const result = await outlook.resolveDraftForSubmit('msg-1');

        assert.deepStrictEqual(result.draft, { message: 'msg-1' });
        assert.deepStrictEqual(result.raw, RAW_DRAFT);
    });

    await t.test('rejects a non-draft message', async () => {
        const { outlook } = makeOutlookClient([
            ['/$value', RAW_DRAFT],
            ['/messages/msg-1', { id: 'msg-1', isDraft: false }]
        ]);

        await assert.rejects(outlook.resolveDraftForSubmit('msg-1'), err => err.code === 'MessageNotDraft' && err.statusCode === 400);
    });

    await t.test('maps an unknown message to a 404', async () => {
        const { outlook } = makeOutlookClient([['/messages/msg-x', oauthApiError(404, 'ErrorItemNotFound')]]);

        await assert.rejects(outlook.resolveDraftForSubmit('msg-x'), err => err.code === 'MessageNotFound' && err.statusCode === 404);
    });
});

test('OutlookClient.submitMessage draft handling', async t => {
    await t.test('posts to /messages/{id}/send and reports the queued Message-ID', async () => {
        const { outlook, calls } = makeOutlookClient([['/messages/msg-1/send', '']]);
        const notifications = armSubmitStubs(outlook, { oauth2: {} });

        const data = Object.assign(QUEUE_ENTRY(), { draft: { message: 'msg-1' } });
        const result = await outlook.submitMessage(data);

        assert.strictEqual(result.messageId, '<draft-1@example.com>');
        assert.strictEqual(calls.length, 1);
        assert.strictEqual(calls[0].url, '/me/messages/msg-1/send');
        assert.strictEqual(calls[0].method, 'post');
        assert.strictEqual(notifications.length, 1);
    });

    await t.test('a vanished draft fails the job without a retryable SMTP verdict', async () => {
        const { outlook } = makeOutlookClient([['/messages/msg-1/send', oauthApiError(404, 'ErrorItemNotFound')]]);
        armSubmitStubs(outlook, { oauth2: {} });

        const data = Object.assign(QUEUE_ENTRY(), { draft: { message: 'msg-1' } });
        await assert.rejects(outlook.submitMessage(data), err => err.message === 'Draft message was not found' && err.responseCode === undefined);
    });
});

// IMAPClient.resolveDraftForSubmit with the mailbox collaborators stubbed
function makeImapClient({ path, flags, specialUse }) {
    const connection = new IMAPClient('test-account', {
        logger: noopLogger,
        accountLogger: { enabled: false, log() {} },
        redis: {}
    });

    connection.checkIMAPConnection = () => true;
    connection.unpackUid = async () => (path ? { path, uidValidity: '1', uid: 100 } : false);
    connection.mailboxes = new Map(path ? [[path, { listingEntry: { path, specialUse } }]] : []);
    connection.getMessage = async () => ({ id: 'id-1', flags });
    connection.getRawMessage = async () => Readable.from([RAW_DRAFT]);

    return connection;
}

test('IMAPClient.resolveDraftForSubmit', async t => {
    // mailbox 1 / uid 100; the stubs above decide the actual behavior
    const id = Buffer.from([0, 0, 0, 1, 0, 0, 0, 100]).toString('base64url');

    await t.test('accepts a message stored in the Drafts folder without checking flags', async () => {
        const connection = makeImapClient({ path: 'Drafts', flags: [], specialUse: '\\Drafts' });
        connection.getMessage = async () => {
            throw new Error('flags must not be fetched for a message in the Drafts folder');
        };

        const result = await connection.resolveDraftForSubmit(id);

        assert.deepStrictEqual(result.draft, { message: id });
        assert.deepStrictEqual(result.raw, RAW_DRAFT);
    });

    await t.test('accepts a \\Draft-flagged message outside the Drafts folder', async () => {
        const connection = makeImapClient({ path: 'Archive', flags: ['\\Draft'], specialUse: '\\Archive' });

        const result = await connection.resolveDraftForSubmit(id);

        assert.deepStrictEqual(result.draft, { message: id });
    });

    await t.test('rejects a non-draft message', async () => {
        const connection = makeImapClient({ path: 'INBOX', flags: ['\\Seen'], specialUse: '\\Inbox' });

        await assert.rejects(connection.resolveDraftForSubmit(id), err => err.code === 'MessageNotDraft' && err.statusCode === 400);
    });

    await t.test('maps an unknown mailbox reference to a 404', async () => {
        const connection = makeImapClient({ path: false, flags: [], specialUse: null });

        await assert.rejects(connection.resolveDraftForSubmit(id), err => err.code === 'MessageNotFound' && err.statusCode === 404);
    });
});
