'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { Transform } = require('stream');

// Reproduce the fixed ResponseStream class from workers/api.js
// since it is not exported from the module.

let registeredPublishers = new Set();

class ResponseStream extends Transform {
    constructor() {
        super();
        registeredPublishers.add(this);
        this.periodicKeepAliveTimer = false;
        this.updateTimer();

        this._finalized = false;

        this.on('error', () => this.finalize());
        this.once('close', () => this.finalize());
        this.once('end', () => this.finalize());
    }

    updateTimer() {
        clearTimeout(this.periodicKeepAliveTimer);
        this.periodicKeepAliveTimer = setTimeout(() => {
            if (this._finalized || this.destroyed) return;
            this.write(': still here\n\n');
            if (this._compressor) {
                this._compressor.flush();
            }
            this.updateTimer();
        }, 90 * 1000);
        this.periodicKeepAliveTimer.unref();
    }

    setCompressor(compressor) {
        this._compressor = compressor;
    }

    sendMessage(payload) {
        if (this._finalized || this.destroyed) return;
        let sendData = JSON.stringify(payload);
        this.write('event: message\ndata:' + sendData + '\n\n');
        if (this._compressor) {
            this._compressor.flush();
        }
        this.updateTimer();
    }

    finalize() {
        if (this._finalized) return;
        this._finalized = true;

        clearTimeout(this.periodicKeepAliveTimer);
        registeredPublishers.delete(this);

        if (!this.destroyed) {
            this.destroy();
        }
    }

    _transform(data, encoding, done) {
        this.push(data);
        done();
    }

    _flush(done) {
        this.finalize();
        done();
    }
}

test('ResponseStream tests', async t => {
    await t.test('finalize cleans up resources', () => {
        registeredPublishers.clear();
        let stream = new ResponseStream();

        assert.ok(registeredPublishers.has(stream), 'stream should be in publishers set');
        assert.notStrictEqual(stream.periodicKeepAliveTimer, false, 'timer should be set');

        stream.finalize();

        assert.ok(!registeredPublishers.has(stream), 'stream should be removed from publishers set');
        assert.ok(stream._finalized, 'stream should be marked as finalized');
    });

    await t.test('write after finalize is safe', () => {
        registeredPublishers.clear();
        let stream = new ResponseStream();
        stream.finalize();

        // These should not throw
        stream.sendMessage({ test: 'data' });
        stream.sendMessage({ another: 'message' });
    });

    await t.test('handles error event gracefully', async () => {
        registeredPublishers.clear();
        let stream = new ResponseStream();

        // Resume so data is consumed and errors propagate properly
        stream.resume();

        stream.emit('error', new Error('test error'));

        assert.ok(stream._finalized, 'stream should be finalized after error');
        assert.ok(!registeredPublishers.has(stream), 'stream should be removed from publishers set');
    });

    await t.test('handles multiple error events without crashing', () => {
        registeredPublishers.clear();
        let stream = new ResponseStream();
        stream.resume();

        // Emit multiple errors - the core bug: once('error') would leave
        // the second error unhandled. With on('error'), all are caught.
        stream.emit('error', new Error('first error'));
        stream.emit('error', new Error('second error'));
        stream.emit('error', new Error('third error'));

        assert.ok(stream._finalized, 'stream should be finalized');
    });

    await t.test('EPIPE on write triggers finalize', async () => {
        registeredPublishers.clear();
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
});
