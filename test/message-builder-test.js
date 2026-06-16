'use strict';

// Unit tests for the send-pipeline decision builders in
// lib/email-client/message-builder.js. These pure helpers decide whether a sent
// message is copied to the Sent folder, extract provider-assigned message IDs
// from SMTP responses, classify SMTP errors, and shape notification payloads -
// the parts of the submit path most prone to silent regressions.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    NetworkRoutingBuilder,
    NotificationBuilder,
    ProviderMessageIdHandler,
    SmtpErrorBuilder,
    SentMailCopyDecider
} = require('../lib/email-client/message-builder');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('SentMailCopyDecider.shouldCopy', async t => {
    const imapAccount = { imap: { host: 'imap.test' } };

    await t.test('defaults to copying for an IMAP account', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: imapAccount, data: {} }), true);
    });

    await t.test('honors the account-level copy=false', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: { imap: { host: 'x' }, copy: false }, data: {} }), false);
    });

    await t.test('suppresses copy for Gmail without a gateway', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: imapAccount, data: {}, isGmail: true }), false);
    });

    await t.test('suppresses copy for non-delegated Outlook without a gateway', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: { oauth2: { auth: {} } }, data: {}, isOutlook: true }), false);
    });

    await t.test('does NOT suppress copy for delegated Outlook', () => {
        const accountData = { oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData, data: {}, isOutlook: true }), true);
    });

    await t.test('does NOT suppress Gmail when a gateway is used', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: imapAccount, data: {}, isGmail: true, gatewayData: { gateway: 'gw' } }), true);
    });

    await t.test('message-level copy overrides the Gmail suppression', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: imapAccount, data: { copy: true }, isGmail: true }), true);
    });

    await t.test('disabled IMAP forces no copy even when requested', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: { imap: { host: 'x', disabled: true } }, data: { copy: true } }), false);
    });

    await t.test('no IMAP and no OAuth2 means no copy', () => {
        assert.strictEqual(SentMailCopyDecider.shouldCopy({ accountData: {}, data: {} }), false);
    });
});

test('ProviderMessageIdHandler', async t => {
    await t.test('rewrites the message ID from a Hotmail/Outlook response', () => {
        const info = { messageId: '<original@local>', response: '250 2.0.0 OK <ABC123.prod.outlook.com>' };
        const original = ProviderMessageIdHandler.handleHotmail(info);
        assert.strictEqual(original, '<original@local>');
        assert.strictEqual(info.messageId, '<ABC123.prod.outlook.com>');
    });

    await t.test('leaves the message ID untouched for a non-Hotmail response', () => {
        const info = { messageId: '<keep@local>', response: '250 OK queued' };
        assert.strictEqual(ProviderMessageIdHandler.handleHotmail(info), undefined);
        assert.strictEqual(info.messageId, '<keep@local>');
    });

    await t.test('builds an AWS SES message ID from the response (us-east-1 -> email)', () => {
        const info = { messageId: '<orig@local>', response: '250 Ok 0123456789abcdef0123456789abcdef' };
        const original = ProviderMessageIdHandler.handleAwsSes(info, 'email-smtp.us-east-1.amazonaws.com');
        assert.strictEqual(original, '<orig@local>');
        assert.strictEqual(info.messageId, '<0123456789abcdef0123456789abcdef@email.amazonses.com>');
    });

    await t.test('builds an AWS SES message ID for a non-us-east region', () => {
        const info = { messageId: '<orig@local>', response: '250 Ok abcdef0123456789' };
        ProviderMessageIdHandler.handleAwsSes(info, 'email-smtp.eu-west-1.amazonaws.com');
        assert.strictEqual(info.messageId, '<abcdef0123456789@eu-west-1.amazonses.com>');
    });

    await t.test('processResponse tries Hotmail then SES', () => {
        const sesInfo = { messageId: '<orig@local>', response: '250 Ok deadbeefdeadbeef' };
        const original = ProviderMessageIdHandler.processResponse(sesInfo, 'email-smtp.us-east-1.amazonaws.com');
        assert.strictEqual(original, '<orig@local>');
        assert.match(sesInfo.messageId, /amazonses\.com>$/);
    });
});

test('SmtpErrorBuilder.buildStatus', async t => {
    const settings = { host: 'mail.test', port: 587 };

    await t.test('builds a status for a known error code with a description', () => {
        const status = SmtpErrorBuilder.buildStatus({ code: 'ETIMEDOUT', response: 'timeout', responseCode: 0 }, settings, null);
        assert.ok(status);
        assert.strictEqual(status.code, 'ETIMEDOUT');
        assert.strictEqual(status.status, 'error');
        assert.match(status.description, /timed out/i);
    });

    await t.test('returns null for an unknown error code', () => {
        assert.strictEqual(SmtpErrorBuilder.buildStatus({ code: 'ESOMETHINGELSE' }, settings, null), null);
    });

    await t.test('returns null when the description builder yields nothing', () => {
        // EMESSAGE maps to a builder that returns null -> no status.
        assert.strictEqual(SmtpErrorBuilder.buildStatus({ code: 'EMESSAGE' }, settings, null), null);
    });

    await t.test('ESOCKET only produces a status when it is a cert failure', () => {
        assert.strictEqual(SmtpErrorBuilder.buildStatus({ code: 'ESOCKET' }, settings, null), null);
        const certStatus = SmtpErrorBuilder.buildStatus({ code: 'ESOCKET', cert: {}, reason: 'self signed' }, settings, null);
        assert.ok(certStatus);
        assert.match(certStatus.description, /Certificate check/);
    });
});

test('NetworkRoutingBuilder.build', async t => {
    await t.test('returns null when there is no routing info', () => {
        assert.strictEqual(NetworkRoutingBuilder.build({}, {}), null);
    });

    await t.test('captures localAddress and proxy', () => {
        const routing = NetworkRoutingBuilder.build({ localAddress: '10.0.0.5', proxy: 'socks5://p', name: 'host1' }, {});
        assert.deepStrictEqual(routing, { localAddress: '10.0.0.5', proxy: 'socks5://p', name: 'host1' });
    });

    await t.test('records a requested localAddress that differs from the effective one', () => {
        const routing = NetworkRoutingBuilder.build({ localAddress: '10.0.0.5' }, { localAddress: '10.0.0.9' });
        assert.strictEqual(routing.requestedLocalAddress, '10.0.0.9');
    });
});

test('NotificationBuilder payloads', async t => {
    await t.test('success payload maps the SMTP info fields', () => {
        const payload = NotificationBuilder.buildSuccessPayload({
            info: { messageId: '<m@x>', response: '250 OK' },
            originalMessageId: '<orig@x>',
            queueId: 'q1',
            envelope: { from: 'a@x', to: ['b@y'] },
            networkRouting: { proxy: 'p' }
        });
        assert.strictEqual(payload.messageId, '<m@x>');
        assert.strictEqual(payload.originalMessageId, '<orig@x>');
        assert.strictEqual(payload.response, '250 OK');
        assert.strictEqual(payload.queueId, 'q1');
    });

    await t.test('error payload maps the error and SMTP fields', () => {
        const payload = NotificationBuilder.buildErrorPayload({
            error: { message: 'boom', code: 'EENVELOPE', response: '550 no', responseCode: 550, command: 'RCPT' },
            queueId: 'q2',
            envelope: { from: 'a@x' },
            messageId: '<m@x>',
            networkRouting: null,
            jobData: { attempt: 1 }
        });
        assert.strictEqual(payload.error, 'boom');
        assert.strictEqual(payload.errorCode, 'EENVELOPE');
        assert.strictEqual(payload.smtpResponse, '550 no');
        assert.strictEqual(payload.smtpResponseCode, 550);
        assert.strictEqual(payload.smtpCommand, 'RCPT');
        assert.deepStrictEqual(payload.job, { attempt: 1 });
    });
});
