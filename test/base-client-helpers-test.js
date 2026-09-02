'use strict';

// Hermetic unit tests for the BaseClient helpers shared by every client type: how a send
// failure is reported (handleSubmitError, now also reached by the API send paths), the bounce
// store behind the `bounces` field of the message details response, the packed identifier
// decoder of the API clients, and the two OAuth2 error classifiers used by the transports.

const test = require('node:test');
const assert = require('node:assert').strict;

const { BaseClient, isTransientNetworkError, markRejectedAccessToken } = require('../lib/email-client/base-client');
const { EMAIL_DELIVERY_ERROR_NOTIFY } = require('../lib/consts');
const msgpack = require('../lib/msgpack');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

// In-memory stand-in for the two hash commands lib/append-list.js uses
function makeAppendRedis() {
    const store = new Map();
    const hashes = new Map();
    return {
        hashes,
        async hPush(list, key, encoded) {
            const id = list + ' ' + key;
            const prev = store.get(id);
            store.set(id, prev ? Buffer.concat([prev, Buffer.from(encoded)]) : Buffer.from(encoded));
            return prev ? 2 : 1;
        },
        async hgetBuffer(list, key) {
            return store.get(list + ' ' + key) || null;
        },
        async hset(key, field, value) {
            hashes.set(key + ':' + field, value);
        }
    };
}

function makeClient() {
    return new BaseClient('acc-1', { logger: noopLogger, accountLogger: { enabled: false, log() {} }, redis: makeAppendRedis() });
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
        assert.equal(client.redis.hashes.size, 0, 'no SMTP status is faked for an API failure');
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
        assert.ok(client.redis.hashes.has(client.getAccountKey() + ':smtpStatus'), 'the SMTP status is recorded for the account');
        assert.equal(notifications[0].payload.smtpResponseCode, 535);
    });
});

test('BaseClient bounce store', async t => {
    await t.test('a stored bounce is listed back in the shape of the bounces field', async () => {
        const client = makeClient();
        const before = Date.now();

        const stored = await client.storeBounce('bounce-msg-id', {
            messageId: '<orig@example.com>',
            recipient: 'bob@example.com',
            action: 'failed',
            response: { message: 'User unknown', status: '5.1.1' }
        });
        assert.equal(stored, 1);

        const bounces = await client.listBounces('<orig@example.com>');
        assert.equal(bounces.length, 1);
        const [bounce] = bounces;
        assert.equal(bounce.message, 'bounce-msg-id');
        assert.equal(bounce.recipient, 'bob@example.com');
        assert.equal(bounce.action, 'failed');
        assert.deepEqual(bounce.response, { message: 'User unknown', status: '5.1.1' });
        assert.ok(new Date(bounce.date).getTime() >= before);
    });

    await t.test('attachBounces() adds the field only when something was recorded', async () => {
        const client = makeClient();
        await client.storeBounce('b1', { messageId: '<x@example.com>', recipient: 'r@example.com', action: 'failed' });

        const hit = { id: 'm1', messageId: '<x@example.com>' };
        await client.attachBounces(hit);
        assert.equal(hit.bounces.length, 1);
        assert.equal(hit.bounces[0].response, undefined);

        const miss = { id: 'm2', messageId: '<y@example.com>' };
        await client.attachBounces(miss);
        assert.ok(!('bounces' in miss));

        // a message without a Message-ID is left alone
        await client.attachBounces({ id: 'm3' });
    });

    await t.test('a lookup failure leaves the message without the field', async () => {
        const client = makeClient();
        client.redis.hgetBuffer = async () => {
            throw new Error('Redis is down');
        };
        const message = { id: 'm1', messageId: '<x@example.com>' };

        await client.attachBounces(message);

        assert.ok(!('bounces' in message));
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
