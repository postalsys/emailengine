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

    await t.test('every term without an OData filter is refused, even when false or empty', () => {
        for (const key of ['seq', 'uid', 'paths', 'answered', 'deleted', 'modseq', 'to', 'cc', 'bcc', 'larger', 'smaller']) {
            for (const value of [true, false, '', 'x']) {
                assert.throws(
                    () => outlook.prepareFilterQuery({ unseen: true, [key]: value }),
                    err => {
                        assert.equal(err.message, `Unsupported search term "${key}"`);
                        assert.equal(err.code, 'UnsupportedSearchTerm');
                        assert.equal(err.statusCode, 400);
                        return true;
                    },
                    `${key}: ${JSON.stringify(value)}`
                );
            }
        }
    });

    await t.test('the first unsupported term in the fixed order is the one reported', () => {
        assert.throws(() => outlook.prepareFilterQuery({ smaller: 1, uid: '1:*', to: 'a' }), /Unsupported search term "uid"/);
    });

    await t.test('flags compile only from booleans', () => {
        assert.equal(outlook.prepareFilterQuery({ unseen: true }), 'isRead eq false');
        assert.equal(outlook.prepareFilterQuery({ unseen: false }), 'isRead eq true');
        assert.equal(outlook.prepareFilterQuery({ seen: true }), 'isRead eq true');
        assert.equal(outlook.prepareFilterQuery({ seen: false }), 'isRead eq false');
        assert.equal(outlook.prepareFilterQuery({ draft: true }), 'isDraft eq true');
        assert.equal(outlook.prepareFilterQuery({ draft: false }), 'isDraft eq false');
        assert.equal(outlook.prepareFilterQuery({ flagged: true }), "flag/flagStatus eq 'flagged'");
        assert.equal(outlook.prepareFilterQuery({ flagged: false }), "flag/flagStatus eq 'notFlagged'");
        assert.equal(outlook.prepareFilterQuery({ unseen: 'true', seen: 1, draft: null, flagged: 'yes' }), '');
    });

    await t.test('from matches the address or the display name', () => {
        assert.equal(
            outlook.prepareFilterQuery({ from: "o'brien@example.com" }),
            "(from/emailAddress/address eq 'o''brien@example.com' or contains(from/emailAddress/name, 'o''brien@example.com'))"
        );
    });

    await t.test('string terms', () => {
        assert.equal(outlook.prepareFilterQuery({ subject: 'Hello  "world"' }), "contains(subject, 'Hello world')");
        assert.equal(outlook.prepareFilterQuery({ body: 'text' }), "contains(body/content, 'text')");
        assert.equal(outlook.prepareFilterQuery({ emailId: 'AAMk' }), "id eq 'AAMk'");
        assert.equal(outlook.prepareFilterQuery({ threadId: 'AAQk' }), "conversationId eq 'AAQk'");
        assert.equal(
            outlook.prepareFilterQuery({ from: '', subject: '', body: 0, emailId: '', threadId: null, before: '', sentBefore: 0, since: null, sentSince: '' }),
            ''
        );
    });

    await t.test('header message-id, in any case, and nothing else', () => {
        assert.equal(outlook.prepareFilterQuery({ header: { 'Message-ID': '<a@b>' } }), "internetMessageId eq '<a@b>'");
        assert.equal(outlook.prepareFilterQuery({ header: { ' message-id ': '<a@b>' } }), "internetMessageId eq '<a@b>'");
        assert.throws(
            () => outlook.prepareFilterQuery({ header: { 'message-id': '<a@b>', 'X-Custom': 'v' } }),
            err => err.message === 'Unsupported search header "X-Custom"' && err.code === 'UnsupportedSearchTerm' && err.statusCode === 400
        );
    });

    await t.test('every part joins in a fixed order', () => {
        const day = new Date('2026-01-02T03:04:05.000Z');
        assert.equal(
            outlook.prepareFilterQuery({
                header: { 'message-id': '<m@x>' },
                labels: { has: ['L'], not: ['N'] },
                sentSince: day,
                since: day,
                sentBefore: day,
                before: day,
                threadId: 't',
                emailId: 'e',
                body: 'b',
                subject: 's',
                from: 'f',
                flagged: true,
                draft: false,
                seen: true,
                unseen: false
            }),
            [
                'isRead eq true',
                'isRead eq true',
                'isDraft eq false',
                "flag/flagStatus eq 'flagged'",
                "(from/emailAddress/address eq 'f' or contains(from/emailAddress/name, 'f'))",
                "contains(subject, 's')",
                "contains(body/content, 'b')",
                "id eq 'e'",
                "conversationId eq 't'",
                'receivedDateTime lt 2026-01-02T03:04:05.000Z',
                'sentDateTime lt 2026-01-02T03:04:05.000Z',
                'receivedDateTime gt 2026-01-02T03:04:05.000Z',
                'sentDateTime gt 2026-01-02T03:04:05.000Z',
                "categories/any(c:c eq 'L')",
                "not (categories/any(c:c eq 'N'))",
                "internetMessageId eq '<m@x>'"
            ].join(' and ')
        );
    });

    await t.test('label lists skip empty entries and accept a single value', () => {
        assert.equal(
            outlook.prepareFilterQuery({ labels: { has: 'One', not: ['', null, 'Two'] } }),
            "categories/any(c:c eq 'One') and not (categories/any(c:c eq 'Two'))"
        );
        assert.equal(outlook.prepareFilterQuery({ labels: 'not-an-object' }), '');
    });

    await t.test('no search compiles to an empty filter', () => {
        assert.equal(outlook.prepareFilterQuery(), '');
        assert.equal(outlook.prepareFilterQuery(null), '');
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
