'use strict';

// Regression tests for lib/message-port-stream.js used to bridge message/attachment
// downloads from the IMAP worker to the API worker over a MessageChannel.
//
// Commit 2: a mid-download error on the IMAP source stream must NOT become an
// unhandled 'error' that crashes the worker. pipeToMessagePort() wires error
// propagation so the source error tears the transfer down cleanly.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable, PassThrough } = require('node:stream');
const { MessageChannel } = require('node:worker_threads');

const { MessagePortWritable, MessagePortReadable, pipeToMessagePort } = require('../lib/message-port-stream');

function tick() {
    return new Promise(resolve => setImmediate(resolve));
}

test('pipeToMessagePort() handles a source error without throwing', async () => {
    const { port1, port2 } = new MessageChannel();
    // Drain anything the writer posts so the channel does not buffer.
    port1.on('message', () => {});

    try {
        const writable = new MessagePortWritable(port2);
        const source = new Readable({ read() {} });

        let loggedError = null;
        pipeToMessagePort(source, writable, {
            error(entry) {
                loggedError = entry;
            }
        });

        source.push('partial chunk');

        // Mid-download failure on the IMAP side.
        const boom = new Error('IMAP connection dropped mid-download');
        await new Promise(resolve => {
            writable.on('close', resolve);
            source.destroy(boom);
        });

        assert.strictEqual(writable.destroyed, true, 'writable should be destroyed when the source errors');
        assert.ok(loggedError && loggedError.err === boom, 'the source error should be logged, not thrown');
    } finally {
        port1.close();
        port2.close();
    }
});

test('destroying the reader aborts the transfer and releases the source (Commit 3)', async () => {
    const { port1, port2 } = new MessageChannel();

    try {
        const writable = new MessagePortWritable(port2);
        const reader = new MessagePortReadable(port1);
        const source = new PassThrough();

        pipeToMessagePort(source, writable, { error() {}, debug() {} });
        source.write('first chunk');

        // The API consumer (Hapi) aborts mid-download by destroying the reader.
        await new Promise(resolve => {
            writable.on('close', resolve);
            reader.destroy();
        });
        await tick();

        assert.strictEqual(writable.destroyed, true, 'writable should be destroyed when the reader aborts');
        assert.strictEqual(source.destroyed, true, 'source (IMAP stream) must be destroyed so its mailbox lock is released');
        assert.strictEqual(port1.listenerCount('message'), 0, 'reader message listener must be removed');
    } finally {
        port1.close();
        port2.close();
    }
});

test('a producer error reaches the reader as a stream error, not a clean end (Commit 3)', async () => {
    const { port1, port2 } = new MessageChannel();

    try {
        const writable = new MessagePortWritable(port2);
        const reader = new MessagePortReadable(port1);
        const source = new PassThrough();

        pipeToMessagePort(source, writable, { error() {}, debug() {} });

        let readerError = null;
        let endedCleanly = false;
        reader.on('error', err => {
            readerError = err;
        });
        reader.on('end', () => {
            endedCleanly = true;
        });
        reader.resume();

        source.write('partial');
        source.destroy(new Error('upstream exploded'));

        await tick();
        await tick();

        assert.ok(readerError, 'reader should surface an error when the producer fails mid-transfer');
        assert.strictEqual(endedCleanly, false, 'reader must not end cleanly on a truncated transfer');
    } finally {
        port1.close();
        port2.close();
    }
});

test('an error posted before the consumer starts reading is caught by a construction-time guard listener', async () => {
    // Mirrors lib/account.js getRawMessage/getAttachment: the producer error travels one
    // hop (direct MessageChannel) while the setup-call response travels two, so {error}
    // can arrive before Hapi attaches its own 'error' listeners. The guard listener
    // attached synchronously after construction must catch it - otherwise the emission
    // is an uncaught exception that kills the API worker.
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);

        // Attached in the same synchronous block as the constructor, like account.js.
        let guardedError = null;
        reader.on('error', err => {
            guardedError = err;
        });
        let endedCleanly = false;
        reader.on('end', () => {
            endedCleanly = true;
        });

        // Producer fails instantly, before any read()/resume() or further listeners.
        port2.postMessage({ error: 'producer failed before consumer attached' });

        await tick();
        await tick();

        assert.ok(guardedError, 'the guard listener must receive the early producer error');
        assert.strictEqual(guardedError.message, 'producer failed before consumer attached');
        assert.strictEqual(reader.destroyed, true, 'reader should be destroyed by the early error');
        assert.strictEqual(endedCleanly, false, 'reader must not end cleanly on a producer error');
        assert.strictEqual(port1.listenerCount('message'), 0, 'reader message listener must be removed on destroy');
    } finally {
        port1.close();
        port2.close();
    }
});

test('destroying a reader whose producer never attached releases the port (setup-failure cleanup)', async () => {
    // Mirrors lib/account.js: a getRawMessage/getAttachment setup call rejects (timeout,
    // worker gone, 404) before the IMAP worker attaches a writable to the transferred
    // port. The consumer destroys the reader; this must release port1's listener and tell
    // the (possibly future) producer to stop via { cancel: true }.
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);

        const peerMessages = [];
        port2.on('message', message => peerMessages.push(message));

        assert.strictEqual(port1.listenerCount('message'), 1, 'reader should hold a port listener before cleanup');

        reader.destroy();
        await tick();

        assert.strictEqual(port1.listenerCount('message'), 0, 'reader message listener must be removed on destroy');
        assert.ok(
            peerMessages.some(message => message && message.cancel),
            'the producer side must receive a cancel signal'
        );
    } finally {
        port1.close();
        port2.close();
    }
});

test('normal completion closes the reader port and removes its listener (Commit 3)', async () => {
    const { port1, port2 } = new MessageChannel();

    try {
        const writable = new MessagePortWritable(port2);
        const reader = new MessagePortReadable(port1);
        const source = new PassThrough();

        pipeToMessagePort(source, writable, { error() {}, debug() {} });

        const chunks = [];
        reader.on('data', chunk => chunks.push(chunk));
        const ended = new Promise(resolve => reader.on('end', resolve));

        source.end('the whole message');
        await ended;
        await tick();

        assert.strictEqual(Buffer.concat(chunks).toString(), 'the whole message', 'all data should be delivered');
        assert.strictEqual(port1.listenerCount('message'), 0, 'reader message listener must be removed after a clean end');
    } finally {
        port1.close();
        port2.close();
    }
});
