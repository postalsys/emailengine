'use strict';

// The bounce and delivery-report checks that decide which newly arrived IMAP messages are downloaded
// for detection: the folder guards are IMAP's own, the shape checks are the shared BaseClient ones.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the modules under test are required: they pull in lib/db, which opens real Redis
// connections at load time. Nothing here reaches a real one.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { BaseClient } = require('../lib/email-client/base-client');

require('./helpers/redis-teardown')();

const exchangeNdr = () => ({
    from: { name: 'Microsoft Outlook', address: 'postmaster-notice@contoso.example' },
    subject: 'Undeliverable: Quarterly report',
    headers: { 'auto-submitted': ['auto-generated'] }
});

// A mailbox context with the real shape checks, so the two sides agree by construction
function mailboxContext({ specialUse, path, isAllMail } = {}) {
    return {
        path,
        isAllMail,
        listingEntry: { specialUse },
        connection: BaseClient.prototype
    };
}

function mightBeABounce(messageInfo, options) {
    return Mailbox.prototype.mightBeABounce.call(mailboxContext(options), messageInfo);
}

function mightBeDSNResponse(messageInfo, options) {
    return Mailbox.prototype.mightBeDSNResponse.call(mailboxContext(options), messageInfo);
}

const dsn = () => ({ headers: { 'content-type': ['multipart/report; report-type=delivery-status; boundary="B"'] } });

test('Mailbox.mightBeABounce()', async t => {
    await t.test('an Exchange NDR in the Inbox is a bounce candidate, as it is on the API clients', async () => {
        assert.equal(mightBeABounce(exchangeNdr(), { specialUse: '\\Inbox' }), true);
        assert.equal(mightBeABounce(exchangeNdr(), { specialUse: '\\Junk' }), true);
        assert.equal(mightBeABounce(Object.assign(exchangeNdr(), { headers: {} }), { specialUse: '\\Inbox' }), false, 'the header is half of the rule');
    });

    await t.test('a message outside the Inbox and Junk is not checked', async () => {
        assert.equal(mightBeABounce(exchangeNdr(), { specialUse: '\\Sent' }), false);
    });

    await t.test('on Gmail the label decides, since every message lives in All Mail', async () => {
        assert.equal(mightBeABounce(Object.assign(exchangeNdr(), { labels: ['\\Inbox'] }), { specialUse: '\\All' }), true);
        assert.equal(mightBeABounce(Object.assign(exchangeNdr(), { labels: ['\\Important'] }), { specialUse: '\\All' }), false);
    });

    await t.test('a message already read as a delivery report is not a bounce', async () => {
        assert.equal(mightBeABounce(Object.assign(exchangeNdr(), { deliveryReport: { action: 'delayed' } }), { specialUse: '\\Inbox' }), false);
    });

    await t.test('an ordinary message in the Inbox is left alone', async () => {
        const message = { from: { name: 'Alice', address: 'alice@example.com' }, subject: 'Lunch?', headers: {} };
        assert.equal(mightBeABounce(message, { specialUse: '\\Inbox' }), false);
    });
});

test('Mailbox.mightBeDSNResponse()', async t => {
    await t.test('a delivery-status report in the Inbox is one', async () => {
        assert.equal(mightBeDSNResponse(dsn(), { path: 'INBOX' }), true);
        assert.equal(mightBeDSNResponse(dsn(), { path: 'Inbox' }), true, 'the folder name is compared case-insensitively');
    });

    await t.test('the Content-Type has to be a delivery-status report', async () => {
        assert.equal(mightBeDSNResponse({ headers: { 'content-type': ['multipart/report; report-type=feedback-report'] } }, { path: 'INBOX' }), false);
        assert.equal(mightBeDSNResponse({ headers: { 'content-type': ['text/plain'] } }, { path: 'INBOX' }), false);
        assert.equal(mightBeDSNResponse({}, { path: 'INBOX' }), false);
    });

    await t.test('a message outside the Inbox is not checked', async () => {
        assert.equal(mightBeDSNResponse(dsn(), { path: 'Archive' }), false);
    });

    await t.test('on Gmail the label decides, since every message lives in All Mail', async () => {
        assert.equal(mightBeDSNResponse(Object.assign(dsn(), { labels: ['\\Inbox'] }), { path: '[Gmail]/All Mail', isAllMail: true }), true);
        assert.equal(mightBeDSNResponse(Object.assign(dsn(), { labels: ['\\Important'] }), { path: '[Gmail]/All Mail', isAllMail: true }), false);
    });
});
