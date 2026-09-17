'use strict';

// The checks that decide which newly arrived messages are downloaded for bounce, delivery-report
// and complaint detection, shared by the IMAP and the API clients: a folder gate on
// messageSpecialUse in front of a shape check. test/complaint-test.js runs the complaint shapes
// against real reports, and test/mailbox-process-new-checks-test.js covers how the IMAP path
// decides the folder before running these.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. Nothing here reaches a real one.
require('./helpers/mock-db').installDbMock();

const { BaseClient } = require('../lib/email-client/base-client');

require('./helpers/redis-teardown')();

const client = BaseClient.prototype;
const inbox = shape => Object.assign({ messageSpecialUse: '\\Inbox' }, shape);

// The Exchange rule is the only one this fixture satisfies: the sender matches neither the
// mailer-daemon names nor the postmaster@ address, and there is no report part
const exchangeNdr = () => ({
    from: { name: 'Microsoft Outlook', address: 'postmaster-notice@contoso.example' },
    subject: 'Undeliverable: Quarterly report',
    headers: { 'auto-submitted': ['auto-generated'] }
});
const dsn = () => ({ headers: { 'content-type': ['multipart/report; report-type=delivery-status; boundary="B"'] } });
// A feedback loop that sends no ARF report part: sender and subject are all there is
const fblNotice = () => ({ from: { address: 'fbl@isp.example' }, subject: 'Abuse complaint about your message', attachments: [] });

test('BaseClient.mightBeABounce()', async t => {
    await t.test('an Exchange NDR in the Inbox or Junk is a bounce candidate', async () => {
        assert.equal(client.mightBeABounce(inbox(exchangeNdr())), true);
        assert.equal(client.mightBeABounce({ messageSpecialUse: '\\Junk', ...exchangeNdr() }), true);
        assert.equal(client.mightBeABounce(inbox({ ...exchangeNdr(), headers: {} })), false, 'the header is half of the rule');
    });

    await t.test('a message outside the Inbox and Junk is not checked', async () => {
        assert.equal(client.mightBeABounce({ messageSpecialUse: '\\Trash', ...exchangeNdr() }), false);
        assert.equal(client.mightBeABounce(exchangeNdr()), false);
    });

    await t.test('a message already read as a delivery report is not a bounce', async () => {
        assert.equal(client.mightBeABounce(inbox({ ...exchangeNdr(), deliveryReport: { action: 'delayed' } })), false);
    });

    await t.test('an ordinary message in the Inbox is left alone', async () => {
        assert.equal(client.mightBeABounce(inbox({ from: { name: 'Alice', address: 'alice@example.com' }, subject: 'Lunch?', headers: {} })), false);
    });
});

test('BaseClient.mightBeDSNResponse()', async t => {
    await t.test('a delivery-status report in the Inbox is one', async () => {
        assert.equal(client.mightBeDSNResponse(inbox(dsn())), true);
    });

    await t.test('the Content-Type has to be a delivery-status report', async () => {
        assert.equal(client.mightBeDSNResponse(inbox({ headers: { 'content-type': ['multipart/report; report-type=feedback-report'] } })), false);
        assert.equal(client.mightBeDSNResponse(inbox({ headers: { 'content-type': ['text/plain'] } })), false);
        assert.equal(client.mightBeDSNResponse(inbox({})), false);
    });

    await t.test('a message outside the Inbox is not checked', async () => {
        assert.equal(client.mightBeDSNResponse({ messageSpecialUse: '\\Junk', ...dsn() }), false);
    });
});

test('BaseClient.mightBeAComplaint()', async t => {
    await t.test('a feedback-loop notice in the Inbox is a complaint candidate', async () => {
        assert.equal(client.mightBeAComplaint(inbox(fblNotice())), true);
    });

    await t.test('a message outside the Inbox is not checked', async () => {
        assert.equal(client.mightBeAComplaint({ messageSpecialUse: '\\Junk', ...fblNotice() }), false);
    });
});
