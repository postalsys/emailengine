'use strict';

// Hermetic unit tests for the label/category search filter across providers.
// The query builders are pure synchronous methods, so we can construct the clients
// with empty options and assert their output directly (no network or Redis needed).

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { searchSchema } = require('../lib/schemas');

// Requiring the email clients pulls in lib/db, which opens Redis/BullMQ handles at load time.
// These are pure unit tests that never touch the DB, so mirror the convention in
// test/tokens-test.js: quit Redis and force-exit after cleanup so the runner does not hang.
const { redis } = require('../lib/db');
test.after(async () => {
    try {
        await redis.quit();
    } catch (err) {
        // ignore
    }
    setTimeout(() => process.exit(), 1000).unref();
});

test('Label search filter - Gmail prepareQuery', async t => {
    const gmail = new GmailClient('test-account', {});

    await t.test('"has" compiles to label:', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: ['Horizon'] } }), 'label:Horizon');
    });

    await t.test('"not" compiles to -label:', () => {
        assert.equal(gmail.prepareQuery({ labels: { not: ['Horizon'] } }), '-label:Horizon');
    });

    await t.test('multi-word label name is quoted', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: ['Some Label'] } }), 'label:"Some Label"');
    });

    await t.test('nested path stays unquoted', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: ['Parent/Child'] } }), 'label:Parent/Child');
    });

    await t.test('multiple "has" entries are ANDed', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: ['A', 'B'] } }), 'label:A label:B');
    });

    await t.test('"has" and "not" combine', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: ['Imported'], not: ['Horizon'] } }), 'label:Imported -label:Horizon');
    });

    await t.test('merges with an existing gmailRaw', () => {
        assert.equal(gmail.prepareQuery({ gmailRaw: 'has:attachment', labels: { not: ['X'] } }), 'has:attachment -label:X');
    });

    await t.test('empty labels object is a no-op', () => {
        assert.equal(gmail.prepareQuery({ labels: {} }), '');
    });

    await t.test('empty arrays are a no-op', () => {
        assert.equal(gmail.prepareQuery({ labels: { has: [], not: [] } }), '');
    });
});

test('Label search filter - Outlook prepareFilterQuery', async t => {
    const outlook = new OutlookClient('test-account', {});

    await t.test('"has" compiles to categories/any', () => {
        assert.equal(outlook.prepareFilterQuery({ labels: { has: ['Horizon'] } }), "categories/any(c:c eq 'Horizon')");
    });

    await t.test('"not" compiles to negated categories/any', () => {
        assert.equal(outlook.prepareFilterQuery({ labels: { not: ['Horizon'] } }), "not (categories/any(c:c eq 'Horizon'))");
    });

    await t.test('single quotes in a category name are escaped', () => {
        assert.equal(outlook.prepareFilterQuery({ labels: { has: ["O'Brien"] } }), "categories/any(c:c eq 'O''Brien')");
    });

    await t.test('combines with other filters via "and"', () => {
        assert.equal(outlook.prepareFilterQuery({ unseen: true, labels: { has: ['X'] } }), "isRead eq false and categories/any(c:c eq 'X')");
    });

    await t.test('"has" and "not" combine', () => {
        assert.equal(
            outlook.prepareFilterQuery({ labels: { has: ['Imported'], not: ['Horizon'] } }),
            "categories/any(c:c eq 'Imported') and not (categories/any(c:c eq 'Horizon'))"
        );
    });

    await t.test('empty labels object is a no-op', () => {
        assert.equal(outlook.prepareFilterQuery({ labels: {} }), '');
    });
});

test('Label search filter - Outlook KQL search path rejects labels', async t => {
    const outlook = new OutlookClient('test-account', {});

    await t.test('prepareSearchQuery throws UnsupportedSearchTerm', () => {
        assert.throws(
            () => outlook.prepareSearchQuery({ labels: { has: ['X'] } }),
            err => err.code === 'UnsupportedSearchTerm' && err.statusCode === 400
        );
    });
});

test('Label search filter - schema validation', async t => {
    await t.test('a bare string coerces to a single-element array', () => {
        const { error, value } = searchSchema.validate({ labels: { has: 'Horizon' } });
        assert.ok(!error);
        assert.deepEqual(value.labels.has, ['Horizon']);
    });

    await t.test('arrays of label names are accepted', () => {
        const { error, value } = searchSchema.validate({ labels: { has: ['A', 'B'], not: ['C'] } });
        assert.ok(!error);
        assert.deepEqual(value.labels.has, ['A', 'B']);
        assert.deepEqual(value.labels.not, ['C']);
    });

    await t.test('label names over 128 chars are rejected', () => {
        const { error } = searchSchema.validate({ labels: { not: ['x'.repeat(129)] } });
        assert.ok(error);
    });
});
