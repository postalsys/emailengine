'use strict';

const { Writable, Readable, pipeline } = require('stream');

// const { MessageChannel } = require('worker_threads');
// const { port1, port2 } = new MessageChannel();

class MessagePortWritable extends Writable {
    constructor(messagePort) {
        super();
        this.messagePort = messagePort;
        this.portClosed = false;

        // The reader side posts { cancel: true } when it is torn down (e.g. the
        // HTTP client aborted the download). Stop the transfer so the upstream
        // source - and the IMAP lock it holds - is released.
        this.onPortMessage = message => {
            if (message && message.cancel) {
                this.destroy();
            }
        };

        // A cancel message only arrives while the consumer is alive to send one. When its thread
        // dies instead, the channel closes without one, and the transfer would otherwise drain the
        // whole source into a port nobody is reading - holding the mailbox lock for the duration.
        //
        // A port that closes with nothing queued behind it reports it only to a listener that was
        // already attached - the event is emitted when the port is started and drained, and a
        // listener added afterwards never sees it. So the producer has to construct this when the
        // port arrives, not once it has content to send: the wait in between is the whole window in
        // which the consumer's thread can die, and for an attachment that is most of the transfer.
        // releaseListeners() is how a producer that ends up with nothing to send gives the port
        // back.
        this.onPortClose = () => {
            this.destroy();
        };

        this.messagePort.on('message', this.onPortMessage);
        this.messagePort.on('close', this.onPortClose);
    }

    postToPort(message) {
        if (this.portClosed) {
            return;
        }
        try {
            this.messagePort.postMessage(message);
        } catch (err) {
            // ignore - the channel may already be torn down
        }
    }

    // Hands the port back untouched. Used by a producer that took the port but found nothing to
    // send (a 404, say): closing it would reach the consumer as a failed transfer rather than as
    // the error it is about to be handed, and leaving the listeners attached leaks them.
    releaseListeners() {
        this.messagePort.removeListener('message', this.onPortMessage);
        this.messagePort.removeListener('close', this.onPortClose);
    }

    closePort() {
        if (this.portClosed) {
            return;
        }
        this.portClosed = true;
        this.releaseListeners();
        try {
            this.messagePort.close();
        } catch (err) {
            // ignore
        }
    }

    _write(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.postToPort({ value: chunk, done: false });
        done();
    }

    _final(done) {
        this.postToPort({ done: true });
        this.closePort();
        done();
    }

    _destroy(err, done) {
        // Abnormal termination: tell the reader so a truncated transfer is not
        // mistaken for a complete message, then release the port.
        if (err) {
            this.postToPort({ error: err.message || 'Stream error' });
        }
        this.closePort();
        done(err);
    }
}

class MessagePortReadable extends Readable {
    constructor(messagePort) {
        super();
        this.messagePort = messagePort;

        this.canRead = false;
        this.portClosed = false;
        this.transferComplete = false;

        this.readableQueue = [];
        this.onPortMessage = message => {
            if (!message) {
                return;
            }
            if (message.error) {
                // The producer failed mid-transfer - surface it as a stream error
                // rather than letting the consumer believe it received everything.
                this.destroy(new Error(message.error));
                return;
            }
            if (message.done || message.value) {
                if (message.done) {
                    this.transferComplete = true;
                }
                this.readableQueue.push(message);

                if (this.canRead && this.readableQueue.length === 1) {
                    this._processReading();
                }
            }
        };

        // Queued messages are delivered before 'close', so a channel that closes without
        // { done: true } was cut short - most likely the producing worker died mid-download.
        // Fail the read rather than presenting a truncated body or hanging on it forever.
        this.onPortClose = () => {
            if (!this.transferComplete && !this.destroyed) {
                this.destroy(new Error('Message stream transfer interrupted'));
            }
        };

        this.messagePort.on('message', this.onPortMessage);
        this.messagePort.on('close', this.onPortClose);
    }

    _processReading() {
        while (this.canRead && this.readableQueue.length) {
            let message = this.readableQueue.shift();
            if (message.done) {
                return this.push(null);
            }
            this.canRead = this.push(Buffer.from(message.value));
        }
    }

    _read() {
        this.canRead = true;
        this._processReading();
    }

    _destroy(err, done) {
        // Consumer is gone (client aborted, error, or clean end): tell the producer
        // to stop and release the port + listener so nothing leaks across threads.
        if (!this.portClosed) {
            this.portClosed = true;
            try {
                this.messagePort.postMessage({ cancel: true });
            } catch (cancelErr) {
                // ignore - the peer may already be closed
            }
            this.messagePort.removeListener('message', this.onPortMessage);
            this.messagePort.removeListener('close', this.onPortClose);
            try {
                this.messagePort.close();
            } catch (closeErr) {
                // ignore
            }
        }
        done(err);
    }
}

/**
 * Pipes a readable source into a MessagePortWritable so that an error on either
 * side tears the transfer down instead of surfacing as an unhandled 'error'
 * event. A mid-download failure on an IMAP source stream would otherwise crash
 * the worker (and every account assigned to it).
 *
 * @param {Readable} source - Source stream (e.g. an IMAP download stream)
 * @param {MessagePortWritable} writable - Destination bound to a MessagePort
 * @param {Object} [logger] - Optional logger used to report transfer failures
 */
function pipeToMessagePort(source, writable, logger) {
    // pipeline() throws ERR_STREAM_UNABLE_TO_PIPE *synchronously* when the destination is
    // already destroyed. The callback below never runs in that case, so the throw escapes to
    // the global uncaughtException handler and takes the worker - and every account assigned
    // to it - down with it. An aborted consumer destroys the writable through its
    // { cancel: true } message, and on a slow upstream fetch that can easily land before this
    // helper is entered at all, so it is a routine state rather than an edge case.
    if (writable.destroyed) {
        // Nothing will drain the source now, so release it explicitly - otherwise the upstream
        // download keeps running and the mailbox lock it holds is never given back.
        source.destroy();
        logger?.debug?.({ msg: 'Message stream transfer aborted by consumer before it started' });
        return;
    }

    pipeline(source, writable, err => {
        if (!err || !logger) {
            return;
        }
        // A consumer that aborts mid-download closes the destination early; that
        // is expected (not a failure) so it should not be logged at error level.
        if (err.code === 'ERR_STREAM_PREMATURE_CLOSE') {
            if (typeof logger.debug === 'function') {
                logger.debug({ msg: 'Message stream transfer aborted by consumer', err });
            }
            return;
        }
        if (typeof logger.error === 'function') {
            logger.error({ msg: 'Message stream transfer failed', err });
        }
    });
}

/**
 * Sends a finished download to the API worker over a destination bound to the transferred port.
 * IMAP resolves a download to a stream and Gmail and Graph to a Buffer; the Buffer is wrapped so
 * both shapes take the same path, leaving pipeToMessagePort() as the single place that has to get
 * an aborted consumer right.
 *
 * Takes the destination rather than the port, because the producer has to build it when the port
 * arrives - see the MessagePortWritable constructor for why. By the time there is content to send,
 * a consumer that gave up has already destroyed it, and pipeToMessagePort() releases the source
 * instead of transferring into a port nobody reads.
 *
 * @param {MessagePortWritable} writable - Destination built when the port arrived
 * @param {Buffer|Readable} source - Payload to transfer
 * @param {Object} [logger] - Optional logger used to report transfer failures
 * @returns {MessagePortWritable} The same destination (used by tests; callers may ignore it)
 */
function sendToMessagePort(writable, source, logger) {
    const stream = Buffer.isBuffer(source) ? Readable.from([source], { objectMode: false }) : source;

    // A { cancel: true } already queued by a consumer that gave up is delivered on the next turn of
    // the event loop. Dispatching from the check phase puts the guard in pipeToMessagePort() after
    // that delivery rather than racing it.
    setImmediate(() => pipeToMessagePort(stream, writable, logger));

    return writable;
}

module.exports.MessagePortWritable = MessagePortWritable;
module.exports.MessagePortReadable = MessagePortReadable;
module.exports.pipeToMessagePort = pipeToMessagePort;
module.exports.sendToMessagePort = sendToMessagePort;
