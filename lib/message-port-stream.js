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
        this.messagePort.on('message', this.onPortMessage);
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

    closePort() {
        if (this.portClosed) {
            return;
        }
        this.portClosed = true;
        this.messagePort.removeListener('message', this.onPortMessage);
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
                this.readableQueue.push(message);

                if (this.canRead && this.readableQueue.length === 1) {
                    this._processReading();
                }
            }
        };
        this.messagePort.on('message', this.onPortMessage);
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

module.exports.MessagePortWritable = MessagePortWritable;
module.exports.MessagePortReadable = MessagePortReadable;
module.exports.pipeToMessagePort = pipeToMessagePort;
