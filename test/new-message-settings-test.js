'use strict';

// A new message pass used to read each setting it needs with its own HGET, 6 to 9 round trips one
// after another before the webhook was queued. They are read together now; this keeps a later edit
// from adding the separate reads back.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const { NEW_MESSAGE_SETTINGS } = require('../lib/consts');

const FILES = ['lib/email-client/imap/mailbox.js', 'lib/email-client/base-client.js'];

test('new message settings are read in one round trip', async t => {
    for (const file of FILES) {
        await t.test(file, () => {
            const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf-8');
            for (const key of NEW_MESSAGE_SETTINGS.concat(['notifyText', 'notifyTextSize', 'notifyHeaders'])) {
                assert.doesNotMatch(source, new RegExp(`settings\\.get\\('${key}'\\)`), `${key} read on its own in ${file}`);
            }
            assert.match(source, /settings\.getMulti\(\.\.\.NEW_MESSAGE_SETTINGS\)/);
        });
    }
});

test('an IMAP sync pass reads them once for all the messages it announces', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'lib/email-client/imap/mailbox.js'), 'utf-8');
    assert.match(source, /const passSettings = await settings\.getMulti\(\.\.\.NEW_MESSAGE_SETTINGS\);/);
    assert.match(source, /this\.processNew\(messageData, messageFetchOptions, storedStatus, categories, passSettings\)/);
    assert.match(source, /passSettings \|\| \(await settings\.getMulti\(\.\.\.NEW_MESSAGE_SETTINGS\)\)/);
    assert.doesNotMatch(source, /settings\.get\('resolveGmailCategories'\)/);
});
