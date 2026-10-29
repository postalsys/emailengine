'use strict';

// One-time passcodes from the OTP-Token header (lib/otp.js): parsing, whether the receiving
// server vouches for the origin, the messageNew gate on the notifyHeaders setting, the IMAP
// message details, and the outgoing header getRawEmail() builds from the otp option.

const test = require('node:test');
const assert = require('node:assert').strict;

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];
settings.getMulti = async (...keys) => Object.fromEntries(await Promise.all(keys.map(async key => [key, await settings.get(key)])));

const { getMessageOtp, notifyHeadersIncludeOtp } = require('../lib/otp');
const { webhooks: Webhooks } = require('../lib/webhooks');
const { getRawEmail } = require('../lib/get-raw-email');
const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { MESSAGE_NEW_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const OTP_HEADER = '"123456"; origin="https://login.example.com"';
const GOOGLE_PASS = 'mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=abc; spf=pass smtp.mailfrom=example.com';

test('getMessageOtp()', async t => {
    await t.test('reads the code and origin, unauthenticated for a server nobody vouches for', () => {
        const headers = { 'otp-token': [OTP_HEADER], 'authentication-results': [GOOGLE_PASS] };
        assert.deepEqual(getMessageOtp(headers, null), { code: '123456', origin: 'https://login.example.com', authenticated: false });
    });

    await t.test('is authenticated by a trusted header with an aligned passing DKIM signature', () => {
        const headers = { 'otp-token': [OTP_HEADER], 'authentication-results': [GOOGLE_PASS] };
        assert.equal(getMessageOtp(headers, 'gmail').authenticated, true);
        // header.d works the same as header.i, and a subdomain signer aligns with the organizational domain
        headers['authentication-results'] = ['mx.google.com; dkim=pass header.d=mail.example.com'];
        assert.equal(getMessageOtp(headers, 'gmail').authenticated, true);
    });

    await t.test('is not authenticated by a signature from another domain, a failed one or an untrusted server', () => {
        for (const value of [
            'mx.google.com; dkim=pass header.d=evil.example',
            'mx.google.com; dkim=fail header.d=example.com',
            'mx.google.com; dkim=pass (header.d=example.com)',
            'mx.evil.example; dkim=pass header.d=example.com',
            'dkim=pass header.d=example.com'
        ]) {
            const headers = { 'otp-token': [OTP_HEADER], 'authentication-results': [value] };
            assert.equal(getMessageOtp(headers, 'gmail').authenticated, false, value);
        }
    });

    await t.test('reads only the topmost Authentication-Results header', () => {
        const headers = {
            'otp-token': [OTP_HEADER],
            'authentication-results': ['mx.google.com; dkim=fail header.d=example.com', GOOGLE_PASS]
        };
        assert.equal(getMessageOtp(headers, 'gmail').authenticated, false);
    });

    await t.test("accepts Microsoft's unnamed header only below a Microsoft Received line", () => {
        const headers = {
            'otp-token': [OTP_HEADER],
            'authentication-results': ['dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;'],
            received: ['from AM0PR01.prod.outlook.com (2603:10a6::1) by AM0PR02.prod.outlook.com']
        };
        assert.equal(getMessageOtp(headers, 'outlook').authenticated, true);
        headers.received = ['from mail.evil.example by mx.evil.example'];
        assert.equal(getMessageOtp(headers, 'outlook').authenticated, false);
    });

    await t.test('a loopback origin is never authenticated', () => {
        const headers = { 'otp-token': ['"1"; origin="http://localhost:3000"'], 'authentication-results': ['mx.google.com; dkim=pass header.d=localhost'] };
        assert.deepEqual(getMessageOtp(headers, 'gmail'), { code: '1', origin: 'http://localhost:3000', authenticated: false });
    });

    await t.test('returns nothing without a single valid header', () => {
        assert.equal(getMessageOtp(undefined, 'gmail'), undefined);
        assert.equal(getMessageOtp({}, 'gmail'), undefined);
        assert.equal(getMessageOtp({ 'otp-token': [OTP_HEADER, OTP_HEADER] }, 'gmail'), undefined);
        assert.equal(getMessageOtp({ 'otp-token': ['"123456"; origin="http://example.com"'] }, 'gmail'), undefined);
    });
});

test('notifyHeadersIncludeOtp()', () => {
    assert.equal(notifyHeadersIncludeOtp(['list-id', 'OTP-Token']), true);
    assert.equal(notifyHeadersIncludeOtp(['*']), true);
    assert.equal(notifyHeadersIncludeOtp(['list-id']), false);
    assert.equal(notifyHeadersIncludeOtp(undefined), false);
});

test('messageNew carries otp only when notifyHeaders asks for its header', async t => {
    t.after(() => {
        for (const key of Object.keys(settingsValues)) {
            delete settingsValues[key];
        }
    });

    const otp = { code: '123456', origin: 'https://example.com', authenticated: false };

    for (const [notifyHeaders, kept] of [
        [undefined, false],
        [['list-id'], false],
        [['otp-token'], true],
        [['*'], true]
    ]) {
        settingsValues.notifyHeaders = notifyHeaders;
        const payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, { data: { otp } });
        assert.equal('otp' in payload.data, kept, JSON.stringify(notifyHeaders));
    }
});

test('IMAP message details carry otp', async () => {
    const ctx = {
        path: 'INBOX',
        listingEntry: { path: 'INBOX' },
        connection: { account: 'test-account', isGmail: true, packUid: async () => 'AAAAAAAAAAAA', isAutoreply: () => false },
        getAttachmentList: Mailbox.prototype.getAttachmentList
    };
    const messageData = {
        uid: 42,
        envelope: { subject: 'Code' },
        headers: Buffer.from(`Authentication-Results: ${GOOGLE_PASS}\r\nOTP-Token: ${OTP_HEADER}\r\nSubject: Code\r\n\r\n`)
    };

    const details = await Mailbox.prototype.getMessageInfo.call(ctx, messageData, true);
    assert.deepEqual(details.otp, { code: '123456', origin: 'https://login.example.com', authenticated: true });

    // a listing entry is not extended and carries no headers, so no otp either
    const listed = await Mailbox.prototype.getMessageInfo.call(ctx, messageData, false);
    assert.equal(listed.otp, undefined);
});

test('getRawEmail() writes the OTP-Token header from the otp option', async t => {
    await t.test('sets the header', async () => {
        const res = await getRawEmail(
            { from: { address: 'a@example.com' }, text: 'Your code is 123456', otp: { code: '123456', origin: 'https://example.com/x' } },
            null
        );
        const header = res.raw.toString().split('\r\n\r\n')[0];
        assert.ok(header.split('\r\n').includes('OTP-Token: "123456"; origin="https://example.com"'), header);
    });

    await t.test('refuses a value the header can not carry with a 400', async () => {
        await assert.rejects(getRawEmail({ text: 'x', otp: { code: '123456', origin: 'http://example.com' } }, null), { code: 'EOTP', statusCode: 400 });
    });
});

test('Gmail and MS Graph message details carry otp', async t => {
    const { GmailClient } = require('../lib/email-client/gmail-client');
    const { OutlookClient } = require('../lib/email-client/outlook-client');
    const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

    await t.test('Gmail', () => {
        const client = new GmailClient('otp-test', {});
        client.logger = noopLogger;
        const message = client.formatMessage(
            {
                id: 'msg1',
                threadId: 'thread1',
                internalDate: '1787332482000',
                labelIds: ['INBOX'],
                payload: {
                    mimeType: 'text/plain',
                    headers: [
                        { name: 'Authentication-Results', value: GOOGLE_PASS },
                        { name: 'OTP-Token', value: OTP_HEADER },
                        { name: 'Subject', value: 'Code' }
                    ],
                    body: { size: 0 }
                }
            },
            { extended: true }
        );
        assert.deepEqual(message.otp, { code: '123456', origin: 'https://login.example.com', authenticated: true });
    });

    await t.test('MS Graph', () => {
        const client = new OutlookClient('otp-test', {});
        client.logger = noopLogger;
        const message = client.formatMessage(
            {
                id: 'gm1',
                subject: 'Code',
                body: { contentType: 'text', content: 'Your code is 123456' },
                headers: { 'otp-token': [OTP_HEADER] }
            },
            { extended: true }
        );
        assert.deepEqual(message.otp, { code: '123456', origin: 'https://login.example.com', authenticated: false });
    });
});

test('the submit payload takes an otp, per message and per mail merge entry', async t => {
    const { captureApiRoutes } = require('./helpers/capture-api-routes');
    const { assertOtpFormat } = require('../lib/api-routes/submit-routes');
    const { routes } = await captureApiRoutes();
    const submit = routes.find(route => route.route === 'POST /v1/account/{account}/submit').payload;
    const valid = payload => !submit.validate(payload, { abortEarly: false, convert: true, stripUnknown: false }).error;
    const otp = { code: '123456', origin: 'https://example.com' };

    await t.test('accepts a valid value and refuses a malformed one', () => {
        assert.ok(valid({ otp }));
        assert.ok(valid({ mailMerge: [{ to: { address: 'a@example.com' }, otp }] }));
        assert.ok(!valid({ otp: { code: '123456' } }));
        assert.ok(!valid({ otp: { code: '12\n34', origin: 'https://example.com' } }));
        assert.ok(!valid({ otp: { code: '123456', origin: 'ftp://example.com' } }));
        assert.ok(!valid({ otp: '123456' }));
    });

    await t.test('refuses an otp with useStructuredFormat', () => {
        const request = (payload, useStructuredFormat) => ({ payload, query: { useStructuredFormat } });
        assert.throws(
            () => assertOtpFormat(request({ otp }, true)),
            err => err.output.statusCode === 400
        );
        assert.throws(
            () => assertOtpFormat(request({ mailMerge: [{ otp }] }, true)),
            err => err.output.statusCode === 400
        );
        assert.doesNotThrow(() => assertOtpFormat(request({ otp }, false)));
        assert.doesNotThrow(() => assertOtpFormat(request({ text: 'x' }, true)));
    });
});
