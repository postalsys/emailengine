'use strict';

// Coverage for lib/account/imap-data.js, the single reader of an account's stored `imap` blob.
//
// Its whole job is telling three cases apart for the callers that go on to read or set `disabled`
// on what it returns: an absent blob (an OAuth2 account has none), a usable one, and an unreadable
// one that must be left exactly as stored rather than replaced with a bare flag.

const test = require('node:test');
const assert = require('node:assert').strict;

const { readImapData, parseImapData } = require('../lib/account/imap-data');

const silentLogger = { error() {} };

// The helper reads the field itself unless the caller has already got it, which is the path every
// unit here exercises; the round trip is covered where the callers are.
const read = stored => readImapData(null, 'account-key', silentLogger, stored);

test('readImapData', async t => {
    await t.test('returns a stored configuration', async () => {
        const { imapData, invalid } = await read(JSON.stringify({ host: 'imap.test', disabled: true }));
        assert.deepStrictEqual(imapData, { host: 'imap.test', disabled: true });
        assert.strictEqual(invalid, false);
    });

    await t.test('reports an absent field as absent, not unreadable', async () => {
        for (const stored of [null, '']) {
            const { imapData, invalid } = await read(stored);
            assert.strictEqual(imapData, null);
            assert.strictEqual(invalid, false, 'an OAuth2 account simply has no imap blob');
        }
    });

    await t.test('reports a blob that does not parse as unreadable', async () => {
        const { imapData, invalid } = await read('not json');
        assert.strictEqual(imapData, null);
        assert.strictEqual(invalid, true);
    });

    await t.test('reports a blob that parses to something unusable as unreadable', async () => {
        // A scalar would throw on `imapData.disabled = true`, an array would silently lose the flag
        for (const stored of ['true', '42', '"imap.test"', '[]', '[{"disabled":true}]']) {
            const { imapData, invalid } = await read(stored);
            assert.strictEqual(imapData, null, `${stored} is not a usable configuration`);
            assert.strictEqual(invalid, true, `${stored} must be left alone rather than rewritten`);
        }
    });

    await t.test('the sync core stays silent with no logger', () => {
        // How the account scan in auth-failure-backfill.js calls it: one line per bad blob across a
        // whole fleet would be the noisiest thing in the startup log.
        assert.deepStrictEqual(parseImapData('not json'), { imapData: null, invalid: true });
        assert.deepStrictEqual(parseImapData('[]'), { imapData: null, invalid: true });
        assert.deepStrictEqual(parseImapData(JSON.stringify({ disabled: true })), { imapData: { disabled: true }, invalid: false });
    });

    await t.test('treats a stored null as an absent blob', async () => {
        // Nothing writes it, but it parses cleanly and means the same thing as no field at all
        const { imapData, invalid } = await read('null');
        assert.strictEqual(imapData, null);
        assert.strictEqual(invalid, false);
    });

    await t.test('treats a stored false as an absent blob', async () => {
        // What POST and PUT /v1/account store for the documented `imap: false`, the way an OAuth2
        // account without IMAP access is registered. Reading it as unreadable would exempt exactly
        // those accounts from the auth-failure safety net, which is gated on `invalid`, and log an
        // error on every init of a Gmail API or Outlook account.
        const { imapData, invalid } = await read('false');
        assert.strictEqual(imapData, null);
        assert.strictEqual(invalid, false, 'no IMAP access is a configuration, not a broken one');
    });
});
