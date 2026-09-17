'use strict';

// Mailbox.mightBeABounce() decides which newly arrived IMAP messages are downloaded for bounce
// detection: the folder and delivery-report guards are IMAP's own, the shape check is the shared
// BaseClient.looksLikeABounce(), so IMAP and the API clients agree, including on the Exchange rule
// (an "Undeliverable:" subject with an Auto-Submitted header) that the IMAP copy used to lack.

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

function mightBeABounce(messageInfo, { specialUse } = {}) {
    const ctx = {
        listingEntry: { specialUse },
        // The real shape check, so the two agree by construction
        connection: { looksLikeABounce: BaseClient.prototype.looksLikeABounce }
    };
    return Mailbox.prototype.mightBeABounce.call(ctx, messageInfo);
}

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
