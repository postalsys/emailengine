'use strict';

// Integration coverage for the header map GmailClient.formatMessage() builds: the guard itself is
// unit-tested in header-map-test.js, this pins that formatMessage actually uses it and that a
// poisoned header does not take the rest of the message down with it.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring the client pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

// A Gmail `format=full` response carrying the supplied headers on top of a Subject. Header lists
// are arrays of {name, value} - the Gmail API's own shape - because an object literal keyed by
// "__proto__" would set the literal's prototype instead of a key and test nothing.
function formatWithHeaders(headers) {
    const gmail = new GmailClient('test-account', {});
    return gmail.formatMessage(
        {
            id: 'msg-1',
            threadId: 'thread-1',
            internalDate: '1700000000000',
            sizeEstimate: 1024,
            snippet: 'preview text',
            labelIds: ['INBOX'],
            payload: {
                headers: [{ name: 'Subject', value: 'Test subject' }].concat(headers),
                mimeType: 'text/plain',
                body: { size: 1 }
            }
        },
        { extended: true }
    );
}

test('Gmail header map', async t => {
    await t.test('a poisoned header does not throw or drop the rest of the message', () => {
        const result = formatWithHeaders([
            { name: '__proto__', value: 'one' },
            { name: '__proto__', value: 'two' },
            { name: 'constructor', value: 'three' },
            { name: 'From', value: 'sender@example.com' },
            { name: 'Message-ID', value: '<abc@example.com>' }
        ]);

        assert.equal(result.subject, 'Test subject');
        assert.equal(result.from.address, 'sender@example.com');
        assert.equal(result.messageId, '<abc@example.com>');
        // The poisoned names are dropped, the real headers survive
        assert.deepEqual(Object.keys(result.headers), ['subject', 'from', 'message-id']);
    });

    await t.test('still collects ordinary headers, including repeats', () => {
        const result = formatWithHeaders([
            { name: 'X-Custom', value: 'first' },
            { name: 'X-Custom', value: 'second' },
            { name: 'X-Other', value: 'value' }
        ]);

        assert.deepEqual(result.headers['x-custom'], ['first', 'second']);
        assert.deepEqual(result.headers['x-other'], ['value']);
    });
});
