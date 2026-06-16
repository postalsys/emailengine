'use strict';

// Unit tests for provider flag/label mapping and Outlook subscription date
// parsing. Gmail represents IMAP flags as labels with inverted semantics
// (\Seen <-> remove UNREAD), so a mapping regression silently corrupts read/flag
// state on every update. These methods are pure (or depend only on other pure
// methods), so they are exercised through the prototype.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { BaseClient } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const flagToLabel = (flag, remove) => GmailClient.prototype.flagToLabel.call(null, flag, remove);

// flagsToLabelIds calls this.flagToLabel and this.normalizeFlagUpdates.
const labelThis = {
    flagToLabel: GmailClient.prototype.flagToLabel,
    normalizeFlagUpdates: BaseClient.prototype.normalizeFlagUpdates
};
const flagsToLabelIds = updates => {
    const { addLabelIds, removeLabelIds } = GmailClient.prototype.flagsToLabelIds.call(labelThis, updates);
    return { add: Array.from(addLabelIds).sort(), remove: Array.from(removeLabelIds).sort() };
};

const parseExpiration = str => OutlookClient.prototype.parseExpirationDate.call(null, str);

test('Gmail flagToLabel', async t => {
    await t.test('marking \\Seen removes the UNREAD label (inverse logic)', () => {
        assert.deepStrictEqual(flagToLabel('\\Seen'), { remove: 'UNREAD' });
    });

    await t.test('removing \\Seen adds the UNREAD label back', () => {
        assert.deepStrictEqual(flagToLabel('\\Seen', true), { add: 'UNREAD' });
    });

    await t.test('\\Flagged maps to the STARRED label', () => {
        assert.deepStrictEqual(flagToLabel('\\Flagged'), { add: 'STARRED' });
        assert.deepStrictEqual(flagToLabel('\\Flagged', true), { remove: 'STARRED' });
    });

    await t.test('unsupported flags map to nothing', () => {
        assert.strictEqual(flagToLabel('\\Draft'), undefined);
        assert.strictEqual(flagToLabel('$Custom'), undefined);
    });
});

test('Gmail flagsToLabelIds', async t => {
    await t.test('adding \\Seen removes UNREAD, adding \\Flagged adds STARRED', () => {
        assert.deepStrictEqual(flagsToLabelIds({ add: ['\\Seen', '\\Flagged'] }), { add: ['STARRED'], remove: ['UNREAD'] });
    });

    await t.test('deleting \\Seen adds UNREAD, deleting \\Flagged removes STARRED', () => {
        assert.deepStrictEqual(flagsToLabelIds({ delete: ['\\Seen', '\\Flagged'] }), { add: ['UNREAD'], remove: ['STARRED'] });
    });

    await t.test('set precedence: set [\\Seen] marks read and unstars', () => {
        // set wins over add/delete; \\Seen present -> add, \\Flagged absent -> delete.
        // add \\Seen -> remove UNREAD; delete \\Flagged -> remove STARRED.
        assert.deepStrictEqual(flagsToLabelIds({ set: ['\\Seen'] }), { add: [], remove: ['STARRED', 'UNREAD'] });
    });

    await t.test('empty update yields no label changes', () => {
        assert.deepStrictEqual(flagsToLabelIds({}), { add: [], remove: [] });
    });
});

test('Outlook parseExpirationDate', async t => {
    await t.test('parses a valid ISO date', () => {
        const d = parseExpiration('2025-01-01T00:00:00.000Z');
        assert.ok(d instanceof Date);
        assert.strictEqual(d.toISOString(), '2025-01-01T00:00:00.000Z');
    });

    await t.test('returns null for an empty value', () => {
        assert.strictEqual(parseExpiration(''), null);
        assert.strictEqual(parseExpiration(null), null);
        assert.strictEqual(parseExpiration(undefined), null);
    });

    await t.test('returns null for an unparseable value', () => {
        assert.strictEqual(parseExpiration('not a date'), null);
    });
});
