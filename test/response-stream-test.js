'use strict';

// Lifecycle tests for the SSE response stream behind /admin/changes and /v1/changes.
//
// This used to carry a hand-maintained copy of the class (it was inline in workers/api.js,
// which boots a Hapi server on require and so can not be imported from a test). The copy
// could not fail when the real implementation regressed, so the class now lives in
// lib/response-stream.js and this file drives the real one.
//
// The properties that matter: a finalized stream never writes again, finalize() is
// idempotent, it always deregisters from the publisher set that publishChangeEvent()
// fans out to, and it survives repeated 'error' events (a second unhandled 'error'
// would take the API worker down).

const test = require('node:test');
const assert = require('node:assert').strict;

const { ResponseStream, registeredPublishers } = require('../lib/response-stream');

test('ResponseStream tests', async t => {
    t.beforeEach(() => {
        registeredPublishers.clear();
    });

    await t.test('a new stream registers itself as a publisher and arms the keep-alive timer', () => {
        let stream = new ResponseStream();

        assert.ok(registeredPublishers.has(stream), 'stream should be in publishers set');
        assert.notStrictEqual(stream.periodicKeepAliveTimer, false, 'timer should be set');

        stream.finalize();
    });

    await t.test('finalize cleans up resources', () => {
        let stream = new ResponseStream();

        stream.finalize();

        assert.ok(!registeredPublishers.has(stream), 'stream should be removed from publishers set');
        assert.ok(stream._finalized, 'stream should be marked as finalized');
        assert.ok(stream.destroyed, 'stream should be destroyed');
    });

    await t.test('sendMessage emits a well-formed SSE frame', async () => {
        let stream = new ResponseStream();

        let chunks = [];
        stream.on('data', chunk => chunks.push(chunk.toString()));

        stream.sendMessage({ account: 'main', type: 'state', key: 'connected' });

        // Transform output is delivered on the next tick
        await new Promise(resolve => setImmediate(resolve));

        assert.equal(chunks.length, 1, 'exactly one frame should be written');
        assert.equal(chunks[0], 'event: message\ndata:{"account":"main","type":"state","key":"connected"}\n\n');

        stream.finalize();
    });

    await t.test('sendMessage flushes the compressor so the frame is not buffered', async () => {
        let stream = new ResponseStream();
        stream.resume();

        let flushes = 0;
        stream.setCompressor({ flush: () => flushes++ });

        stream.sendMessage({ hello: 'world' });
        assert.equal(flushes, 1, 'each frame must flush the compressor, otherwise SSE clients see nothing');

        stream.finalize();
    });

    await t.test('write after finalize is safe', () => {
        let stream = new ResponseStream();
        stream.resume();

        let chunks = [];
        stream.on('data', chunk => chunks.push(chunk.toString()));

        stream.finalize();

        // These must not throw (writing to a destroyed stream would)
        stream.sendMessage({ test: 'data' });
        stream.sendMessage({ another: 'message' });

        assert.equal(chunks.length, 0, 'a finalized stream must not emit any further frames');
    });

    await t.test('finalize is idempotent', () => {
        let stream = new ResponseStream();

        stream.finalize();
        stream.finalize();
        stream.finalize();

        assert.ok(!registeredPublishers.has(stream));
        assert.ok(stream._finalized);
    });

    await t.test('handles error event gracefully', async () => {
        let stream = new ResponseStream();

        // Resume so data is consumed and errors propagate properly
        stream.resume();

        stream.emit('error', new Error('test error'));

        assert.ok(stream._finalized, 'stream should be finalized after error');
        assert.ok(!registeredPublishers.has(stream), 'stream should be removed from publishers set');
    });

    await t.test('handles multiple error events without crashing', () => {
        let stream = new ResponseStream();
        stream.resume();

        // The core bug this guards: once('error') would leave the second error
        // unhandled, and an unhandled 'error' takes the API worker down.
        stream.emit('error', new Error('first error'));
        stream.emit('error', new Error('second error'));
        stream.emit('error', new Error('third error'));

        assert.ok(stream._finalized, 'stream should be finalized');
    });

    await t.test('EPIPE on write triggers finalize', async () => {
        let stream = new ResponseStream();
        stream.resume();

        // Wait for the error event that destroy() emits asynchronously
        await new Promise(resolve => {
            stream.on('error', () => resolve());
            stream.destroy(new Error('write EPIPE'));
        });

        assert.ok(stream._finalized, 'stream should be finalized after EPIPE');
        assert.ok(!registeredPublishers.has(stream), 'stream should be removed from publishers');

        // Further writes should be safe
        stream.sendMessage({ test: 'after-epipe' });
    });

    await t.test('a client disconnect (close) deregisters the stream', async () => {
        let stream = new ResponseStream();
        stream.resume();

        await new Promise(resolve => {
            stream.once('close', () => setImmediate(resolve));
            stream.destroy();
        });

        assert.ok(stream._finalized, 'a closed stream must finalize');
        assert.ok(!registeredPublishers.has(stream), 'a closed stream must not stay in the publisher set');
    });

    await t.test('ending the stream delivers the buffered data and emits end', async () => {
        // _flush() used to destroy the stream before calling its done() callback, which cut the
        // readable side short: end() produced a 'close' and never an 'end', so anything waiting
        // for end-of-data (a consumer, stream.finished, a pipeline) waited forever.
        let stream = new ResponseStream();

        let chunks = [];
        stream.on('data', chunk => chunks.push(chunk.toString()));

        // Raced against a timer rather than awaited outright: the regression is a MISSING event,
        // so a bare await would hang the whole unit tier instead of failing this test.
        let sawEnd = Promise.race([
            new Promise(resolve => stream.once('end', () => resolve(true))),
            new Promise(resolve => setTimeout(() => resolve(false), 1000).unref())
        ]);

        stream.write(': hello\n\n');
        stream.end();

        assert.strictEqual(await sawEnd, true, "end() must emit 'end'");
        assert.strictEqual(chunks.join(''), ': hello\n\n', 'data written before end() must still be delivered');
    });

    await t.test('an ended stream is still deregistered', async () => {
        // The cleanup has to survive the reordering above, including when nobody reads the
        // stream - otherwise the keep-alive timer and the publisher entry leak per connection.
        const closed = stream =>
            Promise.race([
                new Promise(resolve => stream.once('close', () => setImmediate(() => resolve(true)))),
                new Promise(resolve => setTimeout(() => resolve(false), 1000).unref())
            ]);

        let readStream = new ResponseStream();
        readStream.resume();
        readStream.end();
        assert.strictEqual(await closed(readStream), true, 'a consumed stream must close');
        assert.ok(readStream._finalized, 'a consumed stream must finalize');
        assert.ok(!registeredPublishers.has(readStream), 'a consumed stream must leave the publisher set');

        let unreadStream = new ResponseStream();
        unreadStream.end();
        assert.strictEqual(await closed(unreadStream), true, 'an unread stream must close');
        assert.ok(unreadStream._finalized, 'an ended stream that nobody read must finalize too');
        assert.ok(!registeredPublishers.has(unreadStream), 'an unread stream must leave the publisher set');
    });

    await t.test('the keep-alive timer is unref-ed so it can not hold the worker open', () => {
        let stream = new ResponseStream();

        assert.equal(typeof stream.periodicKeepAliveTimer.hasRef, 'function');
        assert.equal(stream.periodicKeepAliveTimer.hasRef(), false, 'keep-alive timer must be unref-ed');

        stream.finalize();
    });
});
