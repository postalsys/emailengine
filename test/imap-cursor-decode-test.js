'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time. The decoder never reaches Redis.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');

// Mailbox.decodeCursorStr() is the IMAP paging cursor decoder. Its InvalidCursorType error
// carried no statusCode, so a cursor issued for a Gmail API account and sent to an IMAP
// account surfaced as a 500 while the Gmail decoder correctly answered 400.

const ctx = { logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} } };

test('Mailbox.decodeCursorStr', async t => {
    await t.test('decodes the page of a cursor it issued', () => {
        const cursor = `imap_${Buffer.from(JSON.stringify({ page: 3 })).toString('base64url')}`;
        assert.equal(Mailbox.prototype.decodeCursorStr.call(ctx, cursor), 3);
    });

    await t.test('a cursor from another client type is a coded 400', () => {
        assert.throws(
            () => Mailbox.prototype.decodeCursorStr.call(ctx, 'gmail_abc'),
            err => err.code === 'InvalidCursorType' && err.statusCode === 400
        );
    });

    await t.test('a well-formed cursor without a page number is a coded 400', () => {
        const cursor = `imap_${Buffer.from(JSON.stringify({})).toString('base64url')}`;
        assert.throws(
            () => Mailbox.prototype.decodeCursorStr.call(ctx, cursor),
            err => err.code === 'InvalidCursorValue' && err.statusCode === 400
        );
    });
});
