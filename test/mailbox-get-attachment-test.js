'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { PassThrough } = require('node:stream');

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time. The exercised getAttachment() path
// never reaches Redis.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');

// Regression tests for the mailbox lock held across a streaming attachment download.
//
// getAttachment() keeps the lock for the lifetime of the returned stream and gave it
// back on 'end' (transfer finished) or 'error' (transfer failed). A consumer that
// aborts destroys the stream without an error, which emits neither - only 'close'.
// The lock was therefore never released and every later operation on that connection
// blocked behind it. Aborting is the normal path when an HTTP client disconnects
// mid-download, so this is routine traffic rather than an edge case.

function createMockContext() {
    const events = [];

    const connectionClient = {
        download: async () => ({
            meta: { contentType: 'application/pdf', filename: 'report.pdf', disposition: 'attachment' },
            content: new PassThrough()
        })
    };

    const ctx = {
        path: 'INBOX',
        listingEntry: { path: 'INBOX' },
        logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} },
        getMailboxLock: async () => ({
            release() {
                events.push('release');
            }
        }),
        connection: {
            account: 'test-account',
            getImapConnection: async () => connectionClient,
            onTaskCompleted() {
                events.push('onTaskCompleted');
            }
        }
    };

    return { ctx, events };
}

function tick() {
    return new Promise(resolve => setImmediate(resolve));
}

test('Mailbox.getAttachment() lock handling', async t => {
    await t.test('releases the lock when the consumer aborts the download', async () => {
        const { ctx, events } = createMockContext();

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});
        assert.deepEqual(events, [], 'the lock must be held while the stream is open');

        // What lib/message-port-stream.js does when the transfer is aborted.
        content.destroy();
        await tick();

        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'an aborted download must give the mailbox lock back');
    });

    await t.test('releases the lock exactly once on a completed download', async () => {
        const { ctx, events } = createMockContext();

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});

        content.resume();
        content.end('attachment bytes');
        await tick();
        await tick();

        assert.deepEqual(events, ['release'], 'a completed download releases the lock on end, and the close backstop must not double-release');
    });

    await t.test('releases the lock when the download fails without being destroyed', async () => {
        // ImapFlow surfaces a mid-download failure by emitting 'error' on the stream without
        // destroying it, so no 'close' follows. The release must not depend on one arriving.
        const { ctx, events } = createMockContext();

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});
        content.on('error', () => {});

        content.emit('error', new Error('download error forwarded from an earlier stage'));
        await tick();

        assert.strictEqual(content.destroyed, false, 'a bare emit must not destroy the stream, otherwise this asserts nothing');
        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'a forwarded error must still give the mailbox lock back');
    });

    await t.test('releases the lock exactly once on a failed download', async () => {
        const { ctx, events } = createMockContext();

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});
        content.on('error', () => {});

        content.destroy(new Error('IMAP connection dropped mid-download'));
        await tick();

        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'a failed download must not release the lock twice');
    });
});
