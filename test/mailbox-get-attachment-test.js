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

// getAttachment hands the content stream back to its caller, so its tests need one that stays open
// until they end or destroy it. getText buffers the stream to completion, so its tests need one
// that ends on its own.
function createMockContext({
    downloadError,
    meta = { contentType: 'application/pdf', filename: 'report.pdf', disposition: 'attachment' },
    makeContent = () => new PassThrough()
} = {}) {
    const events = [];

    const connectionClient = {
        download: async () => {
            if (downloadError) {
                throw downloadError;
            }
            return {
                meta,
                content: makeContent()
            };
        }
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

    await t.test('returns the connection to its main mailbox after a completed download', async () => {
        // The download SELECTs the attachment's mailbox on this connection. Reporting the task is
        // what arms the re-select back to the monitored mailbox, and getAttachment was the only
        // method here that skipped it on success - leaving the connection parked in the
        // attachment's folder, and so idling on the wrong one, until the next resync 15 minutes
        // later.
        const { ctx, events } = createMockContext();

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});

        content.resume();
        content.end('attachment bytes');
        await tick();
        await tick();

        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'a completed download must release the lock once and report the task');
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

    await t.test('releases the lock when the download resolves without a stream', async () => {
        // finished() is what gives the lock back once the stream is done, and it throws
        // synchronously on anything that is not one. The `streaming` flag that tells the finally
        // block the stream has taken over is therefore set only after finished() returns - set
        // before it, this case would leave the lock held with nothing left to release it.
        const { ctx, events } = createMockContext({ makeContent: () => null });

        const content = await Mailbox.prototype.getAttachment.call(ctx, { uid: 42 }, '2', {}, {});

        assert.strictEqual(content, false, 'a download with no stream is not an attachment');
        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'the lock must not outlive a download that produced nothing');
    });
});

// getText() holds the same per-connection mailbox lock across its FETCHes. It released the lock
// from a finally but reported the task after the try/finally, so a FETCH that threw returned the
// lock and left the connection parked on the message's mailbox - idling on the wrong one until
// the next resync, 15 minutes later.

function endedStream(text) {
    const stream = new PassThrough();
    stream.end(text);
    return stream;
}

test('Mailbox.getText() lock handling', async t => {
    await t.test('reports the task after a successful fetch', async () => {
        const { ctx, events } = createMockContext({ makeContent: () => endedStream('message text') });

        await Mailbox.prototype.getText.call(ctx, { uid: 42 }, ['1'], {}, {});

        assert.deepEqual(events, ['release', 'onTaskCompleted']);
    });

    await t.test('reports the task when the fetch throws', async () => {
        const downloadError = new Error('IMAP connection dropped mid-fetch');
        const { ctx, events } = createMockContext({ downloadError });

        await assert.rejects(() => Mailbox.prototype.getText.call(ctx, { uid: 42 }, ['1'], {}, {}), /dropped mid-fetch/);

        assert.deepEqual(events, ['release', 'onTaskCompleted'], 'a failed fetch must still send the connection back to its mailbox');
    });

    await t.test('groups a prototype-shaped content subtype as plain text', async () => {
        // The subtype comes from the message, so a sender picks it. Keyed straight into the
        // accumulator, "text/__proto__" made the `!result[typeKey]` probe find Object.prototype,
        // skip the initializer and then throw on .reduce() - a crafted message that fails every
        // text fetch of itself.
        for (const subtype of ['__proto__', 'constructor']) {
            const { ctx, events } = createMockContext({
                meta: { contentType: `text/${subtype}` },
                makeContent: () => endedStream('message text')
            });

            const result = await Mailbox.prototype.getText.call(ctx, { uid: 42 }, ['1'], {}, {});

            assert.strictEqual(result.plain, 'message text', `text/${subtype} must still be returned`);
            assert.strictEqual(Object.getPrototypeOf(result), Object.prototype, `text/${subtype} must not swap the result's prototype`);
            assert.ok(!Object.keys(result).includes(subtype), `text/${subtype} must not become a key of its own`);
            assert.deepEqual(events, ['release', 'onTaskCompleted']);
        }
    });

    await t.test('takes no lock and reports nothing when the caller already holds one', async () => {
        const { ctx, events } = createMockContext({ makeContent: () => endedStream('message text') });

        await Mailbox.prototype.getText.call(ctx, { uid: 42 }, ['1'], { skipLock: true }, {});

        assert.deepEqual(events, [], 'skipLock means an outer operation owns the lock and will report the task itself');
    });
});
