'use strict';

// Hermetic unit tests for the search query builders of the API clients (gmail-client.js
// prepareQuery, outlook-client.js prepareSearchQuery/prepareFilterQuery/formatSearchTerm) and
// for the Outlook paging cursor decoder. The builders are pure synchronous methods, so the
// clients are constructed with empty options and the output is asserted directly. The label
// filter half of the builders is covered by test/search-label-filter-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

// Requiring the clients pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

test('Gmail prepareQuery size terms', async t => {
    const gmail = new GmailClient('test-account', {});

    await t.test('larger and smaller compile to the Gmail size operators', () => {
        // Both used to be dropped, so a size filter matched every message
        assert.equal(gmail.prepareQuery({ larger: 1000 }), 'larger:1000');
        assert.equal(gmail.prepareQuery({ smaller: 500 }), 'smaller:500');
        assert.equal(gmail.prepareQuery({ larger: 1000, smaller: 5000 }), 'larger:1000 smaller:5000');
    });
});

test('Outlook prepareSearchQuery (KQL)', async t => {
    const outlook = new OutlookClient('test-account', {});

    await t.test('accepts from and subject, which the builder emits clauses for', () => {
        assert.equal(outlook.prepareSearchQuery({ from: 'alice@example.com', subject: 'Report' }), 'from:alice@example.com subject:Report');
    });

    await t.test('received dates come from before/since, sent dates from sentBefore/sentSince', () => {
        const day = new Date(2026, 0, 2); // local time, as the MM/DD/YYYY formatter reads it
        assert.equal(outlook.prepareSearchQuery({ before: day }), 'received<=01/02/2026');
        assert.equal(outlook.prepareSearchQuery({ since: day }), 'received>=01/02/2026');
        assert.equal(outlook.prepareSearchQuery({ sentBefore: day }), 'sent<=01/02/2026');
        assert.equal(outlook.prepareSearchQuery({ sentSince: day }), 'sent>=01/02/2026');
    });

    await t.test('still rejects terms KQL can not express', () => {
        assert.throws(
            () => outlook.prepareSearchQuery({ flagged: true }),
            err => err.code === 'UnsupportedSearchTerm' && err.statusCode === 400
        );
    });
});

test('Outlook prepareFilterQuery (OData)', async t => {
    const outlook = new OutlookClient('test-account', {});

    await t.test('sentBefore/sentSince filter on sentDateTime, before/since on receivedDateTime', () => {
        const day = new Date('2026-01-02T03:04:05.000Z');
        assert.equal(outlook.prepareFilterQuery({ before: day }), 'receivedDateTime lt 2026-01-02T03:04:05.000Z');
        assert.equal(outlook.prepareFilterQuery({ since: day }), 'receivedDateTime gt 2026-01-02T03:04:05.000Z');
        assert.equal(outlook.prepareFilterQuery({ sentBefore: day }), 'sentDateTime lt 2026-01-02T03:04:05.000Z');
        assert.equal(outlook.prepareFilterQuery({ sentSince: day }), 'sentDateTime gt 2026-01-02T03:04:05.000Z');
    });

    await t.test('formatSearchTerm serializes a Date and quotes a string', () => {
        assert.equal(outlook.formatSearchTerm(new Date('2026-01-02T00:00:00.000Z'), false), '2026-01-02T00:00:00.000Z');
        assert.equal(outlook.formatSearchTerm("O'Brien"), "'O''Brien'");
    });
});

test('Outlook decodeCursorStr', async t => {
    const outlook = new OutlookClient('test-account', {});
    outlook.logger = noopLogger;

    await t.test('round-trips a cursor it issued', () => {
        const cursor = outlook.encodeCursorString(2, 'skip-token');
        assert.deepEqual(outlook.decodeCursorStr(cursor), { cursorPage: 2, skipToken: 'skip-token' });
    });

    await t.test('a cursor from another client type is a 400, not a 500', () => {
        assert.throws(
            () => outlook.decodeCursorStr('gmail_abc'),
            err => err.code === 'InvalidCursorType' && err.statusCode === 400
        );
    });

    await t.test('a well-formed cursor without a page number is a 400 instead of a TypeError downstream', () => {
        const cursor = `ms_${Buffer.from(JSON.stringify({ skipToken: 'x' })).toString('base64url')}`;
        assert.throws(
            () => outlook.decodeCursorStr(cursor),
            err => err.code === 'InvalidCursorValue' && err.statusCode === 400
        );
    });
});
