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

const { MessagePortWritable, MessagePortReadable, pipeToMessagePort, sendToMessagePort } = require('../lib/message-port-stream');

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

test('an abort that lands before the transfer starts does not throw', async () => {
    // Reported from production: IMAP workers holding ~700 accounts each died roughly twice a
    // day with an uncaught ERR_STREAM_UNABLE_TO_PIPE. See the comment on pipeToMessagePort()
    // for the mechanism; the sequence below is the one that reached it.
    const { port1, port2 } = new MessageChannel();

    try {
        // The consumer goes away while the IMAP worker is still awaiting its upstream fetch.
        const reader = new MessagePortReadable(port1);
        reader.destroy();

        // The fetch resolves only now, so the writable is built against a port whose peer has
        // already cancelled, and the queued cancel destroys it before the transfer starts.
        const source = new PassThrough();
        const writable = new MessagePortWritable(port2);

        await tick();
        assert.strictEqual(writable.destroyed, true, 'the queued cancel must have destroyed the writable first');

        const debugMessages = [];
        assert.doesNotThrow(() => {
            pipeToMessagePort(source, writable, {
                error() {},
                debug(entry) {
                    debugMessages.push(entry.msg);
                }
            });
        }, 'piping into an already-destroyed destination must not throw ERR_STREAM_UNABLE_TO_PIPE');

        assert.strictEqual(source.destroyed, true, 'the source must be released so its mailbox lock is not held forever');
        assert.deepEqual(debugMessages, ['Message stream transfer aborted by consumer before it started'], 'the abort must leave a trace in the log');

        // The helper is also reachable without a logger.
        const unloggedSource = new PassThrough();
        assert.doesNotThrow(() => pipeToMessagePort(unloggedSource, writable));
        assert.strictEqual(unloggedSource.destroyed, true, 'the source must be released even when nothing is logging');
    } finally {
        port1.close();
        port2.close();
    }
});

test('a producer whose port closes mid-transfer fails the read instead of hanging it', async () => {
    // The { cancel: true } / { error } handshake only works while both sides are alive to speak
    // it. When the producing worker dies, the channel closes with nothing said, and without a
    // reaction to the port's own 'close' the reader would never push null and never error - the
    // HTTP response would hang until its socket timed out.
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);

        let readerError = null;
        let endedCleanly = false;
        reader.on('error', err => {
            readerError = err;
        });
        reader.on('end', () => {
            endedCleanly = true;
        });
        reader.resume();

        // Half a message arrives, then the producing thread goes away.
        port2.postMessage({ value: Buffer.from('half a message'), done: false });
        port2.close();

        await tick();
        await tick();

        assert.ok(readerError, 'a channel that closes before { done: true } must surface as an error');
        assert.strictEqual(endedCleanly, false, 'a truncated body must never be reported as a complete message');
    } finally {
        port1.close();
    }
});

test('a complete transfer is not mistaken for an interrupted one when the port closes', async () => {
    // The producer closes its port immediately after { done: true }, so 'close' arrives on every
    // healthy download too. Queued messages are delivered first, which is what lets the two be
    // told apart - assert it rather than trusting it.
    const { port1, port2 } = new MessageChannel();

    try {
        const writable = new MessagePortWritable(port2);
        const reader = new MessagePortReadable(port1);
        const source = new PassThrough();

        pipeToMessagePort(source, writable, { error() {}, debug() {} });

        let readerError = null;
        reader.on('error', err => {
            readerError = err;
        });
        const chunks = [];
        reader.on('data', chunk => chunks.push(chunk));
        const ended = new Promise(resolve => reader.on('end', resolve));

        source.end('the whole message');
        await ended;
        await tick();
        await tick();

        assert.strictEqual(readerError, null, 'a completed transfer must not be failed by the port closing behind it');
        assert.strictEqual(Buffer.concat(chunks).toString(), 'the whole message');
    } finally {
        port1.close();
        port2.close();
    }
});

test('a consumer whose port closes releases the producer and its mailbox lock', async () => {
    // Mirror image: the API worker dies without sending a cancel. The producer must stop rather
    // than draining the whole attachment into a port nobody is reading.
    const { port1, port2 } = new MessageChannel();

    try {
        const writable = new MessagePortWritable(port2);
        const source = new PassThrough();

        pipeToMessagePort(source, writable, { error() {}, debug() {} });
        source.write('first chunk');

        await new Promise(resolve => {
            writable.on('close', resolve);
            port1.close();
        });
        await tick();

        assert.strictEqual(writable.destroyed, true, 'the writable must be torn down when the channel closes');
        assert.strictEqual(source.destroyed, true, 'the source must be released so its mailbox lock is not held for the whole download');
    } finally {
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

// sendToMessagePort() is the single entry point both workers/imap.js download handlers use. The
// Buffer branch (Gmail and Graph) and the streaming branch (IMAP) have to survive the same
// consumer-abort race, which is why the check lives here rather than at each call site.

test('sendToMessagePort() delivers a Buffer payload', async () => {
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);
        sendToMessagePort(port2, Buffer.from('a Gmail attachment'), { error() {}, debug() {} });

        const chunks = [];
        reader.on('data', chunk => chunks.push(chunk));
        await new Promise(resolve => reader.on('end', resolve));

        assert.strictEqual(Buffer.concat(chunks).toString(), 'a Gmail attachment');
    } finally {
        port1.close();
        port2.close();
    }
});

test('sendToMessagePort() delivers a stream payload', async () => {
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);
        const source = new PassThrough();
        sendToMessagePort(port2, source, { error() {}, debug() {} });
        source.end('an IMAP attachment');

        const chunks = [];
        reader.on('data', chunk => chunks.push(chunk));
        await new Promise(resolve => reader.on('end', resolve));

        assert.strictEqual(Buffer.concat(chunks).toString(), 'an IMAP attachment');
    } finally {
        port1.close();
        port2.close();
    }
});

test('sendToMessagePort() survives a consumer that aborted before the transfer started', async () => {
    // Production ordering: the consumer gives up while the IMAP worker is still awaiting its
    // upstream fetch, so { cancel: true } is already sitting in the port's queue by the time the
    // writable is built. Attaching the writable's listener starts the port, that queued cancel is
    // delivered on the next turn, and the deferred dispatch runs after it.
    for (const payload of ['buffer', 'stream']) {
        const { port1, port2 } = new MessageChannel();

        try {
            const reader = new MessagePortReadable(port1);
            reader.destroy();
            await tick();

            const source = payload === 'buffer' ? Buffer.from('never sent') : new PassThrough();
            const debugMessages = [];

            const writable = sendToMessagePort(port2, source, {
                error() {},
                debug(entry) {
                    debugMessages.push(entry.msg);
                }
            });

            await tick();
            await tick();

            assert.strictEqual(writable.destroyed, true, `${payload}: the queued cancel must destroy the writable`);
            assert.deepEqual(debugMessages, ['Message stream transfer aborted by consumer before it started'], `${payload}: the abort must be logged`);
            if (payload === 'stream') {
                assert.strictEqual(source.destroyed, true, 'the source must be released so its mailbox lock is not held forever');
            }
        } finally {
            port1.close();
            port2.close();
        }
    }
});
