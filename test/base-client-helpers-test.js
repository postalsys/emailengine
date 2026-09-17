'use strict';

// Hermetic unit tests for the BaseClient helpers shared by every client type: how a send
// failure is reported (handleSubmitError, now also reached by the API send paths), the
// content-based bounce check behind the isBounce field of the message details response, the
// packed identifier decoder of the API clients, and the two OAuth2 error classifiers used by
// the transports.

const test = require('node:test');
const assert = require('node:assert').strict;

const { BaseClient, markRejectedAccessToken } = require('../lib/email-client/base-client');
const { isTransientNetworkError } = require('../lib/email-client/credential-errors');
const { EMAIL_DELIVERY_ERROR_NOTIFY } = require('../lib/consts');
const msgpack = require('../lib/msgpack');
const fs = require('fs');
const Path = require('path');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

// Records the one hash command handleSubmitError() reaches
function makeRedis() {
    const writes = [];
    return {
        writes,
        async hset(key, field, value) {
            writes.push({ key, field, value });
        }
    };
}

function makeClient() {
    return new BaseClient('acc-1', { logger: noopLogger, accountLogger: { enabled: false, log() {} }, redis: makeRedis() });
}

test('BaseClient.handleSubmitError()', async t => {
    function makeSubmitClient() {
        const client = makeClient();
        const notifications = [];
        const feedback = [];
        client.notify = async (mailbox, event, payload) => notifications.push({ event, payload });
        client.updateFeedbackKey = async (...args) => feedback.push(args);
        return { client, notifications, feedback };
    }
    const context = {
        data: { feedbackKey: 'fb-1', messageId: '<m1@example.com>' },
        jobData: { id: 'job-1' },
        queueId: 'q-1',
        envelope: { from: 'a@example.com' }
    };

    await t.test('keeps the status and details of a provider (API) send failure and webhooks it', async () => {
        const { client, notifications, feedback } = makeSubmitClient();
        const err = Object.assign(new Error('Invalid message format'), { code: 'InvalidMessage', statusCode: 500, info: { response: 'Bad recipients' } });

        await client.handleSubmitError(err, context);

        assert.equal(err.statusCode, 500, 'the API client marks non-retryable sends with 500; the SMTP branch used to null it');
        assert.equal(err.code, 'InvalidMessage');
        assert.equal(err.info.response, 'Bad recipients');
        assert.equal(client.redis.writes.length, 0, 'no SMTP status is faked for an API failure');
        assert.deepEqual(feedback, [['fb-1', false, 'Failed to send email']]);
        assert.equal(notifications.length, 1);
        assert.equal(notifications[0].event, EMAIL_DELIVERY_ERROR_NOTIFY);
        assert.equal(notifications[0].payload.errorCode, 'InvalidMessage');
        assert.equal(notifications[0].payload.smtpResponseCode, undefined);
    });

    await t.test('an SMTP reply still decides the status and is stored as the account SMTP status', async () => {
        const { client, notifications } = makeSubmitClient();
        const err = Object.assign(new Error('Invalid login'), {
            code: 'EAUTH',
            responseCode: 535,
            response: '535 Authentication failed',
            command: 'AUTH PLAIN'
        });

        await client.handleSubmitError(err, Object.assign({ smtpSettings: { host: 'smtp.example.com', port: 587 } }, context));

        assert.equal(err.statusCode, 535);
        assert.ok(
            client.redis.writes.some(write => write.key === client.getAccountKey() && write.field === 'smtpStatus'),
            'the SMTP status is recorded for the account'
        );
        assert.equal(notifications[0].payload.smtpResponseCode, 535);
    });
});

test('BaseClient.detectBounce()', async t => {
    // The message details route asks for this; the messageNew webhook decides the same two fields
    // at arrival. Nothing is stored, so the raw message is downloaded only for a bounce-like message
    const fixture = name => fs.promises.readFile(Path.join(__dirname, 'fixtures', 'bounces', name));
    const bounceLike = () => ({
        id: 'm1',
        messageId: '<6343ae11.050a0220.d9258.3a6c.GMR@mx.google.com>',
        messageSpecialUse: '\\Inbox',
        from: { name: 'Mail Delivery Subsystem', address: 'mailer-daemon@googlemail.com' },
        subject: 'Delivery Status Notification (Failure)'
    });

    function makeFetchClient(raw) {
        const client = makeClient();
        let downloads = 0;
        client.getRawMessage = async () => {
            downloads++;
            return raw;
        };
        return { client, downloads: () => downloads };
    }

    await t.test('a bounce in the Inbox is recognized from its content', async () => {
        const { client, downloads } = makeFetchClient(await fixture('gmail.eml'));
        const message = bounceLike();

        await client.detectBounce(message);

        assert.equal(downloads(), 1);
        assert.equal(message.isBounce, true);
        assert.equal(message.relatedMessageId, '<CAPacwgw3pCyVcmW4nVy8VPX5u5ksn_wZB2jZ_tLUM2es7LaiEA@mail.gmail.com>');
    });

    await t.test('a message outside the Inbox is not checked', async () => {
        const { client, downloads } = makeFetchClient(await fixture('gmail.eml'));

        for (const messageSpecialUse of ['\\Trash', '\\Junk', '\\Sent', undefined]) {
            const message = Object.assign(bounceLike(), { messageSpecialUse });
            await client.detectBounce(message);
            assert.ok(!('isBounce' in message), `${messageSpecialUse} is not checked`);
        }
        assert.equal(downloads(), 0);
    });

    await t.test('the caller can supply the download', async () => {
        const { client, downloads } = makeFetchClient(null);
        const message = bounceLike();

        await client.detectBounce(message, () => fixture('gmail.eml'));

        assert.equal(downloads(), 0);
        assert.equal(message.isBounce, true);
    });

    await t.test('a message that does not look like a bounce is not downloaded', async () => {
        const { client, downloads } = makeFetchClient(Buffer.from('Subject: hello\r\n\r\nhi'));
        const message = { id: 'm2', messageSpecialUse: '\\Inbox', from: { name: 'Alice', address: 'alice@example.com' }, subject: 'Lunch?' };

        await client.detectBounce(message);

        assert.equal(downloads(), 0);
        assert.ok(!('isBounce' in message));
    });

    await t.test('a delay report is not a bounce, as on the arrival path', async () => {
        const { client } = makeFetchClient(await fixture('delayed.eml'));
        const message = Object.assign(bounceLike(), { subject: 'Delayed Mail (still being retried)' });

        await client.detectBounce(message);

        assert.ok(!('isBounce' in message));
        assert.ok(!('relatedMessageId' in message));
    });

    await t.test('a failed download leaves the fields unset instead of failing the fetch', async () => {
        const { client } = makeFetchClient(null);
        client.getRawMessage = async () => {
            throw new Error('Connection lost');
        };
        const message = bounceLike();

        await client.detectBounce(message);

        assert.ok(!('isBounce' in message));

        const { client: empty } = makeFetchClient(false);
        const gone = bounceLike();
        await empty.detectBounce(gone);
        assert.ok(!('isBounce' in gone), 'a message that is no longer there is not a bounce either');
    });
});

test('BaseClient.unpackApiId()', async t => {
    const client = makeClient();

    await t.test('decodes an identifier of the expected shape', () => {
        const encoded = msgpack.encode(['message-1', 'attachment-1']).toString('base64url');
        assert.deepEqual(
            client.unpackApiId(encoded, parts => parts.length >= 2),
            ['message-1', 'attachment-1']
        );
    });

    await t.test('a value that is not an identifier is a coded 400 instead of a RangeError or TypeError', () => {
        const isInvalidId = err => err.code === 'InvalidId' && err.statusCode === 400;
        assert.throws(() => client.unpackApiId('zz', parts => parts.length >= 2), isInvalidId);
        assert.throws(() => client.unpackApiId('', parts => parts.length >= 2), isInvalidId);
        assert.throws(() => client.unpackApiId(msgpack.encode(['only-one']).toString('base64url'), parts => parts.length >= 2), isInvalidId);
        assert.throws(() => client.unpackApiId(msgpack.encode({ a: 1 }).toString('base64url'), () => true), isInvalidId);
    });
});

test('OAuth2 error classifiers', async t => {
    await t.test('isTransientNetworkError() reads the code undici attaches as the cause', () => {
        assert.equal(isTransientNetworkError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } })), true);
        assert.equal(isTransientNetworkError(Object.assign(new Error('x'), { code: 'ECONNRESET' })), true);
        assert.equal(isTransientNetworkError(Object.assign(new Error('OAuth2 request failed'), { oauthRequest: { status: 401 } })), false);
        assert.equal(isTransientNetworkError(null), false);
    });

    await t.test('markRejectedAccessToken() turns a provider 401 into a coded 403 and leaves everything else alone', () => {
        const rejected = markRejectedAccessToken(Object.assign(new Error('OAuth2 request failed'), { statusCode: 401, oauthRequest: { status: 401 } }));
        assert.equal(rejected.code, 'OAuthTokenRejected');
        assert.equal(rejected.statusCode, 403);

        const other = markRejectedAccessToken(Object.assign(new Error('OAuth2 request failed'), { statusCode: 404, oauthRequest: { status: 404 } }));
        assert.equal(other.code, undefined);
        assert.equal(other.statusCode, 404);
    });
});
