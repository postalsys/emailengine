'use strict';

// Every account hash field the Gmail API and Graph clients write is classified in
// lib/email-client/sync-state-fields.js, as a sync position a flush clears or as something a flush
// keeps. A field written by a client and listed in neither would silently survive a flush, the way
// googleHistoryId once did.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const { SYNC_STATE_FIELDS, OTHER_CLIENT_FIELDS } = require('../lib/email-client/sync-state-fields');

const CLIENTS = ['lib/email-client/gmail-client.js', 'lib/email-client/outlook-client.js'];
const WRITE = /\.(?:hset|hSetExists|hsetnx|hIncrbyExists)\(\s*this\.getAccountKey\(\),\s*('([A-Za-z]+)'|([A-Z_]+))/g;

test('every account hash field an API client writes is classified', () => {
    const known = new Set(Object.values(SYNC_STATE_FIELDS).flat().concat(OTHER_CLIENT_FIELDS));
    const unknown = [];
    for (const file of CLIENTS) {
        const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf-8');
        for (const match of source.matchAll(WRITE)) {
            let field = match[2];
            if (!field) {
                // a constant: resolve it from its declaration in the same file
                const declared = source.match(new RegExp(`const ${match[3]} = '([A-Za-z]+)'`));
                field = declared ? declared[1] : match[3];
            }
            if (!known.has(field) && !field.startsWith('state') && field !== 'smtpStatus') {
                unknown.push(`${file}: ${field}`);
            }
        }
    }
    assert.deepStrictEqual(unknown, [], 'classify the field in lib/email-client/sync-state-fields.js');
});

test('a flush clears the sync positions of both clients', () => {
    const { FLUSHED_SYNC_FIELDS } = require('../lib/account');
    assert.deepStrictEqual(FLUSHED_SYNC_FIELDS.slice().sort(), [
        'googleHistoryId',
        'googleHistoryProcessing',
        'outlookAnnouncedInSince',
        'outlookRecoveredUntil'
    ]);
});
