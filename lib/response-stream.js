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

// How much unsent output a stream may hold before the client is treated as gone. A consumer that
// keeps the connection open but stops reading (a suspended tab, a stuck proxy, a deliberately
// idle holder of an `events` grant) applies backpressure, and every change event fanned out to it
// used to pile up in this Transform's buffers for as long as the socket stayed open. Dropping the
// stream instead is what an SSE client already knows how to handle: EventSource reconnects.
const MAX_BUFFERED_BYTES = 2 * 1024 * 1024;

class ResponseStream extends Transform {
    /**
     * @param {Object} [options]
     * @param {Set} [options.registry] - the live-stream set this stream registers itself in.
     *        Defaults to the shared change-feed set that publishChangeEvent() fans out to; the
     *        MCP listen streams (lib/mcp/listen.js) pass their own set so the two feeds cannot
     *        receive each other's frames.
     * @param {Number} [options.maxBuffered] - unsent bytes tolerated before the stream is dropped
     */
    constructor(options) {
        super();
        this.maxBuffered = (options && options.maxBuffered) || MAX_BUFFERED_BYTES;
        this.registry = (options && options.registry) || registeredPublishers;
        this.registry.add(this);
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
            // A keep-alive exists to show the connection some traffic; while output is already
            // queued behind a client that is not reading, adding one only grows the queue
            if (!this.writableNeedDrain) {
                this.write(': still here\n\n');
                if (this._compressor) {
                    this._compressor.flush();
                }
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

        // Both halves count: once the readable side is full the Transform stops consuming, and
        // everything after that waits on the writable side
        if (this.writableLength + this.readableLength > this.maxBuffered) {
            this.finalize();
            return;
        }

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
        this.registry.delete(this);

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
 * Opens an SSE response on a Hapi toolkit: the stream, its cleanup, the deferred greeting, and
 * the response headers, in one place for every feed.
 *
 * All three consumers - the admin change feed, /v1/changes, and the MCP subscriptions/listen
 * stream (lib/mcp/listen.js) - share this wiring because the parts that matter are easy to get
 * subtly different: finalize() has to run when the response is finished (a dropped client must
 * not keep its stream in the registry), the greeting and anything else written on open have to
 * be deferred so they land after the response headers, and X-Accel-Buffering: no is what keeps
 * an intermediate proxy from holding events back until the connection closes.
 *
 * @param {Object} h - Hapi response toolkit
 * @param {Object} [options]
 * @param {Set} [options.registry] - passed to the ResponseStream constructor
 * @param {Function} [options.onOpen] - called with the stream after the greeting is written
 * @returns {{stream: ResponseStream, response: Object}}
 */
function openSseStream(h, options) {
    const stream = new ResponseStream({ registry: options && options.registry });

    finished(stream, err => stream.finalize(err));

    setImmediate(() => {
        try {
            stream.write(`: EmailEngine v${packageData.version}\n\n`);
            if (options && options.onOpen) {
                options.onOpen(stream);
            }
        } catch (err) {
            // the stream is already gone; finished() above cleans up
        }
    });

    const response = h
        .response(stream)
        .header('X-Accel-Buffering', 'no')
        .header('Connection', 'keep-alive')
        .header('Cache-Control', 'no-cache')
        .type('text/event-stream');

    return { stream, response };
}

// How often an open change stream re-asks whether the credential that opened it still admits it.
// Revocations announced over lib/revocation-events.js are acted on at once; this catches the rest
// (an expired token, a session ended by a password change).
const CHANGE_STREAM_RECHECK_INTERVAL = 60 * 1000;

let changeStreamRecheckTimer = null;
let changeStreamRecheckInFlight = null;

/**
 * Re-runs the authentication of every open change stream through the strategy that admitted it,
 * against the request that opened it, and closes the streams whose credential is refused now. The
 * feed used to be authorized once, at open, so a revoked or expired token, an ended admin session
 * and an SSO user removed from the allow-list kept receiving every account's change events for as
 * long as the client held the connection. A call made while a pass runs joins it.
 *
 * @returns {Promise<void>}
 */
function recheckChangeStreams() {
    if (!changeStreamRecheckInFlight) {
        changeStreamRecheckInFlight = (async () => {
            const streams = [...registeredPublishers].filter(stream => stream.recheckAuth && !stream._finalized);
            if (!streams.length && changeStreamRecheckTimer) {
                // the last change stream is gone; the next one to open starts the timer again
                clearInterval(changeStreamRecheckTimer);
                changeStreamRecheckTimer = null;
            }
            const answers = await Promise.all(streams.map(stream => stream.recheckAuth()));
            streams.forEach((stream, i) => {
                if (!answers[i] && !stream._finalized) {
                    stream.finalize();
                }
            });
        })().finally(() => {
            changeStreamRecheckInFlight = null;
        });
    }
    return changeStreamRecheckInFlight;
}

/**
 * Whether the credential behind `request` still passes its route's strategy. A refusal is false:
 * a 401 or 403, or the redirect to the login page the admin session strategy answers a refused
 * session with (thrown by auth.test() as a response, not as an error). Anything else (a Redis
 * fault) says nothing about the credential and keeps the stream.
 *
 * @param {Object} request - The hapi request that opened the stream
 * @returns {Promise<boolean>}
 */
async function credentialStillAdmits(request) {
    request.app.authRecheck = true;
    try {
        await request.server.auth.test(request.auth.strategy, request);
        return true;
    } catch (err) {
        const status = (err && ((err.output && err.output.statusCode) || err.statusCode)) || 0;
        return !(status === 401 || status === 403 || (status >= 300 && status < 400));
    } finally {
        request.app.authRecheck = false;
    }
}

/**
 * Opens the SSE change feed shared by /admin/changes and /v1/changes.
 *
 * @param {Object} request - Hapi request; the stream is parked on request.app.stream
 * @param {Object} h - Hapi response toolkit
 * @returns {Object} Hapi response
 */
function openChangeStream(request, h) {
    const { stream, response } = openSseStream(h);
    request.app.stream = stream;
    if (request.auth && request.auth.strategy) {
        stream.recheckAuth = () => credentialStillAdmits(request);
        if (!changeStreamRecheckTimer) {
            changeStreamRecheckTimer = setInterval(recheckChangeStreams, CHANGE_STREAM_RECHECK_INTERVAL);
            changeStreamRecheckTimer.unref();
        }
    }
    return response;
}

module.exports = { ResponseStream, registeredPublishers, openChangeStream, openSseStream, recheckChangeStreams, MAX_BUFFERED_BYTES };
