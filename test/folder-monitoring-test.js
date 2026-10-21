'use strict';

// accountPathList() and folderMonitoring() in lib/email-client/imap/listing-diff.js: which listed
// folders an IMAP account syncs. connect() and processListing() in imap-client.js each carried a
// hand-written copy of this rule; both now ask these helpers, and the guardrail at the end keeps it
// that way.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const path = require('path');

const { accountPathList, folderMonitoring, GMAIL_MONITORED_SPECIAL_USE } = require('../lib/email-client/imap/listing-diff');

const folder = (folderPath, specialUse) => ({ path: folderPath, specialUse });

test('accountPathList', async t => {
    await t.test('defaults to every folder', () => {
        assert.deepStrictEqual(accountPathList({}), ['*']);
        assert.deepStrictEqual(accountPathList({ path: [] }), ['*']);
        assert.deepStrictEqual(accountPathList({ path: '' }), ['*']);
        assert.deepStrictEqual(accountPathList(null), ['*']);
    });

    await t.test('keeps a configured selector or list as stored', () => {
        assert.deepStrictEqual(accountPathList({ path: 'INBOX' }), ['INBOX']);
        assert.deepStrictEqual(accountPathList({ path: ['\\Sent', 'INBOX'] }), ['\\Sent', 'INBOX']);
    });
});

test('folderMonitoring', async t => {
    await t.test('watches every folder of a non-Gmail account configured with *', () => {
        for (const entry of [folder('INBOX', '\\Inbox'), folder('Archive'), folder('Sent', '\\Sent')]) {
            assert.deepStrictEqual(folderMonitoring(['*'], entry, false), { monitored: true, index: -1 });
        }
    });

    await t.test('watches only All Mail, Spam and Trash on Gmail', () => {
        assert.deepStrictEqual(GMAIL_MONITORED_SPECIAL_USE, ['\\All', '\\Junk', '\\Trash']);
        assert.strictEqual(folderMonitoring(['*'], folder('[Gmail]/All Mail', '\\All'), true).monitored, true);
        assert.strictEqual(folderMonitoring(['*'], folder('[Gmail]/Spam', '\\Junk'), true).monitored, true);
        assert.strictEqual(folderMonitoring(['*'], folder('[Gmail]/Trash', '\\Trash'), true).monitored, true);
        assert.strictEqual(folderMonitoring(['*'], folder('INBOX', '\\Inbox'), true).monitored, false);
        assert.strictEqual(folderMonitoring(['*'], folder('Work'), true).monitored, false);
    });

    await t.test('watches only configured folders, in configured order, Gmail or not', () => {
        const paths = ['\\Sent', 'Inbox'];
        for (const isGmail of [false, true]) {
            assert.deepStrictEqual(folderMonitoring(paths, folder('INBOX', '\\Inbox'), isGmail), { monitored: true, index: 1 });
            assert.deepStrictEqual(folderMonitoring(paths, folder('Sent Items', '\\Sent'), isGmail), { monitored: true, index: 0 });
            assert.deepStrictEqual(folderMonitoring(paths, folder('[Gmail]/All Mail', '\\All'), isGmail), { monitored: false, index: -1 });
        }
    });
});

test('imap-client.js decides folder monitoring only through folderMonitoring()', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'email-client', 'imap-client.js'), 'utf8');
    assert.doesNotMatch(source, /\['\\\\\\\\All', '\\\\\\\\Junk', '\\\\\\\\Trash'\]/, 'the Gmail folder list lives in listing-diff.js');
    assert.doesNotMatch(source, /\[\]\.concat\(accountData\.path/, 'use accountPathList()');
    assert.strictEqual((source.match(/folderMonitoring\(/g) || []).length, 2, 'connect() and processListing()');
});
