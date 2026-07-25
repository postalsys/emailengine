'use strict';

// Server-Sent Events response stream used by the admin UI change feed (`/admin/changes`)
// and the API `/v1/changes` endpoint.
//
// Lives in its own module (rather than inline in workers/api.js) so the lifecycle
// guarantees below can be unit tested against the real implementation. Importing
// workers/api.js from a test is not an option: it boots a Hapi server on require.
//
// `registeredPublishers` is the set of live streams the API worker fans change events
// out to. Every stream adds itself on construction and removes itself in finalize(),
// so a dropped browser tab can not leak a timer or keep receiving writes.

const { Transform, finished } = require('stream');

const packageData = require('../package.json');

// Every live SSE stream. publishChangeEvent() in workers/api.js iterates this set.
const registeredPublishers = new Set();

// How long a stream may stay silent before a comment frame is written to keep
// intermediate proxies from timing the connection out.
const KEEP_ALIVE_INTERVAL = 90 * 1000;

class ResponseStream extends Transform {
    constructor() {
        super();
        registeredPublishers.add(this);
        this.periodicKeepAliveTimer = false;
        this.updateTimer();

        this._finalized = false;

        // Ensure cleanup on all stream end scenarios. 'error' uses on() rather than once():
        // a destroyed stream can emit more than one error, and a second unhandled 'error'
        // would take the worker down.
        this.on('error', () => this.finalize());
        this.once('close', () => this.finalize());
        this.once('end', () => this.finalize());
    }

    updateTimer() {
        clearTimeout(this.periodicKeepAliveTimer);
        this.periodicKeepAliveTimer = setTimeout(() => {
            if (this._finalized || this.destroyed) {
                return;
            }
            this.write(': still here\n\n');
            if (this._compressor) {
                this._compressor.flush();
            }
            this.updateTimer();
        }, KEEP_ALIVE_INTERVAL);
        this.periodicKeepAliveTimer.unref();
    }

    setCompressor(compressor) {
        this._compressor = compressor;
    }

    sendMessage(payload) {
        if (this._finalized || this.destroyed) {
            return;
        }
        let sendData = JSON.stringify(payload);
        this.write('event: message\ndata:' + sendData + '\n\n');
        if (this._compressor) {
            this._compressor.flush();
        }
        this.updateTimer();
    }

    finalize() {
        if (this._finalized) {
            // Prevent double cleanup
            return;
        }
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
        // done() first: finalize() destroys the stream, and destroying before the flush callback
        // has returned cuts the readable side short - end() then emits 'close' and never 'end',
        // so anything waiting for end-of-data (a consumer, stream.finished, a pipeline) waits
        // forever. Finalizing straight after is still safe: push(null) has already happened, so
        // the queued 'end' is delivered either way, and an ended stream that nobody reads is
        // still cleaned up rather than leaking its keep-alive timer and its publisher entry.
        done();
        this.finalize();
    }
}

/**
 * Opens an SSE change feed on a Hapi request.
 *
 * Both feeds - the admin UI one (/admin/changes) and the API one (/v1/changes) - are the same
 * stream with the same framing, so the wiring lives here next to the stream it wires up rather
 * than being written out twice. The parts that matter and are easy to get subtly different:
 * finalize() has to run when the response is finished (a dropped tab must not keep its stream in
 * registeredPublishers), the greeting has to be deferred so it is written after the response
 * headers, and X-Accel-Buffering: no is what keeps an intermediate proxy from holding events
 * back until the connection closes.
 *
 * @param {Object} request - Hapi request; the stream is parked on request.app.stream
 * @param {Object} h - Hapi response toolkit
 * @returns {Object} Hapi response
 */
function openChangeStream(request, h) {
    request.app.stream = new ResponseStream();
    finished(request.app.stream, err => request.app.stream.finalize(err));
    setImmediate(() => {
        try {
            request.app.stream.write(`: EmailEngine v${packageData.version}\n\n`);
        } catch (err) {
            // ignore
        }
    });
    return h
        .response(request.app.stream)
        .header('X-Accel-Buffering', 'no')
        .header('Connection', 'keep-alive')
        .header('Cache-Control', 'no-cache')
        .type('text/event-stream');
}

module.exports = { ResponseStream, registeredPublishers, openChangeStream };
