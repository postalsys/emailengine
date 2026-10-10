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
        sendToMessagePort(new MessagePortWritable(port2), Buffer.from('a Gmail attachment'), { error() {}, debug() {} });

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
        sendToMessagePort(new MessagePortWritable(port2), source, { error() {}, debug() {} });
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
    // transfer is dispatched. The writable's listener started the port when it was built, that
    // queued cancel is delivered on the next turn, and the deferred dispatch runs after it.
    for (const payload of ['buffer', 'stream']) {
        const { port1, port2 } = new MessageChannel();

        try {
            const writable = new MessagePortWritable(port2);
            const reader = new MessagePortReadable(port1);
            reader.destroy();
            await tick();

            const source = payload === 'buffer' ? Buffer.from('never sent') : new PassThrough();
            const debugMessages = [];

            sendToMessagePort(writable, source, {
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

// A close event only lands on a macrotask, so setImmediate() is not enough to observe one - and a
// download long enough for the consumer's thread to die is well past either.
function settle() {
    return new Promise(resolve => setTimeout(resolve, 10));
}

test('a destination built when the port arrives catches a consumer whose thread died', async () => {
    // The other half of the abort case above. A consumer that gives up sends { cancel: true }; a
    // consumer whose THREAD dies sends nothing and the channel simply closes - and a port that
    // closes with nothing queued behind it only reports that to a listener already attached. This
    // is why the producer builds the destination when the port arrives rather than once the
    // download has resolved, which for a large attachment is minutes later: built late, the
    // transfer is piped into a dead port that swallows every message, pulling the whole download
    // off the wire while the mailbox lock is held for its duration.
    for (const payload of ['buffer', 'stream']) {
        const { port1, port2 } = new MessageChannel();

        try {
            const writable = new MessagePortWritable(port2);

            // No reader, no cancel message: what a MessagePortReadable in a thread that exited
            // leaves behind.
            port1.close();
            await settle();

            assert.strictEqual(writable.destroyed, true, `${payload}: the destination must see a close nothing else was listening for`);

            const source = payload === 'buffer' ? Buffer.from('never sent') : new PassThrough();
            const debugMessages = [];

            sendToMessagePort(writable, source, {
                error() {},
                debug(entry) {
                    debugMessages.push(entry.msg);
                }
            });

            await tick();
            await tick();

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

test('a destination built only once there is content to send misses that close entirely', async () => {
    // The control for the test above, pinning why the destination cannot be built late: with
    // nothing attached at close time the port is never started, so the event is not queued for a
    // later listener either - it is gone. pipeToMessagePort() then sees a destination that looks
    // alive and pipes the whole download into a port that silently swallows it.
    const { port1, port2 } = new MessageChannel();

    try {
        port1.close();
        await settle();

        const source = new PassThrough();
        const writable = sendToMessagePort(new MessagePortWritable(port2), source, { error() {}, debug() {} });

        await tick();
        await tick();
        await settle();

        assert.strictEqual(writable.destroyed, false, 'built late, a dead channel is indistinguishable from a live one');
        assert.strictEqual(source.destroyed, false, 'which is exactly how the download drains into nothing with the lock held');
    } finally {
        port1.close();
        port2.close();
    }
});

test('releaseListeners() hands a port back without reporting a failed transfer', async () => {
    // What a producer that took the port and then found nothing to send does (a 404). Closing the
    // port instead would reach the consumer as an interrupted transfer rather than as the error it
    // is about to be handed, and leaving the listeners attached would leak them.
    const { port1, port2 } = new MessageChannel();

    try {
        const reader = new MessagePortReadable(port1);
        const errors = [];
        reader.on('error', err => errors.push(err.message));

        const writable = new MessagePortWritable(port2);
        writable.releaseListeners();

        await settle();

        assert.deepEqual(errors, [], 'the consumer must not be told the transfer failed');
        assert.strictEqual(writable.destroyed, false);

        // The port is inert afterwards: a cancel from the consumer no longer reaches the released
        // destination, which is what makes this safe to call before handing the port on
        port1.postMessage({ cancel: true });
        await settle();
        assert.strictEqual(writable.destroyed, false);

        reader.destroy();
    } finally {
        port1.close();
        port2.close();
    }
});

test('a reader that stops consuming stalls the writer once the credit window is spent (WORK-10)', async () => {
    // The writer used to acknowledge every chunk at once, so the source was drained at network
    // speed and a slow HTTP client left the whole payload queued in the API worker.
    const { port1, port2 } = new MessageChannel();
    const window = 64 * 1024;
    const chunkSize = 16 * 1024;

    try {
        const writable = new MessagePortWritable(port2, { creditWindow: window });
        // A tiny highWaterMark, so the reader stops pulling from its queue almost immediately
        const reader = new MessagePortReadable(port1, { creditWindow: window });
        reader._readableState.highWaterMark = chunkSize;

        let produced = 0;
        const total = 64;
        const source = new Readable({
            highWaterMark: chunkSize,
            read() {
                if (produced >= total) {
                    return this.push(null);
                }
                produced++;
                this.push(Buffer.alloc(chunkSize, 1));
            }
        });

        pipeToMessagePort(source, writable, { error() {}, debug() {} });

        // Nobody reads: let the writer run as far as it can
        for (let i = 0; i < 20; i++) {
            await tick();
        }

        const sentBytes = produced * chunkSize;
        assert.ok(sentBytes < total * chunkSize, 'the writer must stop before draining the whole source');
        assert.ok(
            reader.readableQueue.length * chunkSize <= window + chunkSize,
            `the reader queue stays within the credit window (${reader.readableQueue.length} chunks queued)`
        );

        // Once the consumer reads, the rest arrives
        let received = 0;
        await new Promise((resolve, reject) => {
            reader.on('data', chunk => {
                received += chunk.length;
            });
            reader.on('end', resolve);
            reader.on('error', reject);
        });
        assert.strictEqual(received, total * chunkSize, 'every byte is delivered once the consumer catches up');
    } finally {
        port1.close();
        port2.close();
    }
});

test('the reader returns credit in batches rather than one ack per chunk', async () => {
    // Every chunk used to be acknowledged on its own, doubling the messages crossing the thread
    // boundary. Credit is returned once a quarter of the window has been consumed instead.
    const { port1, port2 } = new MessageChannel();
    const window = 64 * 1024;
    const chunkSize = 4 * 1024;
    const total = 32;

    try {
        let acks = 0;
        let acked = 0;
        port2.on('message', message => {
            if (message && typeof message.ack === 'number') {
                acks++;
                acked += message.ack;
            }
        });
        const writable = new MessagePortWritable(port2, { creditWindow: window });
        const reader = new MessagePortReadable(port1, { creditWindow: window });

        let produced = 0;
        const source = new Readable({
            read() {
                if (produced >= total) {
                    return this.push(null);
                }
                produced++;
                this.push(Buffer.alloc(chunkSize, 1));
            }
        });
        pipeToMessagePort(source, writable, { error() {}, debug() {} });

        let received = 0;
        await new Promise((resolve, reject) => {
            reader.on('data', chunk => {
                received += chunk.length;
            });
            reader.on('end', resolve);
            reader.on('error', reject);
        });
        // The acks are posted before 'end' reaches the consumer, but their delivery to port2 is a
        // separate turn of the event loop
        await tick();

        assert.strictEqual(received, total * chunkSize, 'every byte is delivered');
        assert.strictEqual(acked, total * chunkSize, 'all of the credit comes back');
        assert.ok(acks < total, `fewer acks than chunks (${acks} acks for ${total} chunks)`);
        assert.ok(acks >= Math.floor((total * chunkSize) / (window / 4)), `credit is returned as batches fill (${acks} acks)`);
    } finally {
        port1.close();
        port2.close();
    }
});

test('a consumer that stops reading is abandoned once the stall timeout passes', async () => {
    // A client that keeps its HTTP connection open but never reads sends no cancel, so the write
    // waiting for credit used to wait forever - and the IMAP download behind it kept the
    // account's mailbox lock for as long as the socket lived.
    const { port1, port2 } = new MessageChannel();
    const window = 16 * 1024;

    try {
        const writable = new MessagePortWritable(port2, { creditWindow: window, stallTimeout: 50 });
        // A reader that is never consumed: it takes the chunks off the port but returns no credit
        const reader = new MessagePortReadable(port1, { creditWindow: window });
        const readerError = new Promise(resolve => reader.once('error', resolve));

        const source = new Readable({
            read() {
                this.push(Buffer.alloc(4 * 1024, 1));
            }
        });

        let warned = null;
        pipeToMessagePort(source, writable, {
            error() {},
            debug() {},
            warn(entry) {
                warned = entry;
            }
        });

        await new Promise(resolve => source.once('close', resolve));

        assert.strictEqual(writable.destroyed, true, 'the stalled writer is torn down');
        assert.strictEqual(source.destroyed, true, 'the source is released, and with it the mailbox lock');
        assert.ok(warned && warned.err && warned.err.code === 'ConsumerStalled', 'the stall is logged as a warning');
        assert.match((await readerError).message, /stopped reading/, 'the reader learns the transfer was cut short');
    } finally {
        port1.close();
        port2.close();
    }
});

test('a write that gets its credit back in time is not timed out', async () => {
    const { port1, port2 } = new MessageChannel();
    const window = 16 * 1024;
    const chunkSize = 4 * 1024;
    const total = 32;

    try {
        const writable = new MessagePortWritable(port2, { creditWindow: window, stallTimeout: 200 });
        const reader = new MessagePortReadable(port1, { creditWindow: window });

        let produced = 0;
        const source = new Readable({
            read() {
                if (produced >= total) {
                    return this.push(null);
                }
                produced++;
                this.push(Buffer.alloc(chunkSize, 1));
            }
        });
        let warned = false;
        pipeToMessagePort(source, writable, {
            error() {},
            debug() {},
            warn() {
                warned = true;
            }
        });

        // Slow but steady: every chunk is read, each after a pause shorter than the stall timeout
        let received = 0;
        await new Promise((resolve, reject) => {
            reader.on('data', chunk => {
                received += chunk.length;
                reader.pause();
                setTimeout(() => reader.resume(), 10);
            });
            reader.on('end', resolve);
            reader.on('error', reject);
        });

        assert.strictEqual(received, total * chunkSize, 'every byte is delivered');
        assert.strictEqual(warned, false, 'the transfer was never reported as stalled');
    } finally {
        port1.close();
        port2.close();
    }
});

test('a partial ack counts as progress for the stall timeout', async () => {
    // Credit taken back in amounts too small to unblock a large write still means the consumer is
    // reading; only a reader that returns nothing at all is abandoned.
    const { port1, port2 } = new MessageChannel();
    try {
        const writable = new MessagePortWritable(port2, { creditWindow: 1000, stallTimeout: 150 });
        let destroyed = false;
        writable.on('error', () => {
            destroyed = true;
        });
        writable.write(Buffer.alloc(4000, 1));

        // Trickle 100 bytes of credit back every 50 ms: never enough to unblock, always progress
        for (let i = 0; i < 8; i++) {
            await new Promise(r => setTimeout(r, 50));
            port1.postMessage({ ack: 100 });
        }
        assert.equal(destroyed, false, 'the writer is still waiting, not abandoned');
        writable.destroy();
    } finally {
        port1.close();
        port2.close();
    }
});
