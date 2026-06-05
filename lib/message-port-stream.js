'use strict';

const { Writable, Readable, pipeline } = require('stream');

// const { MessageChannel } = require('worker_threads');
// const { port1, port2 } = new MessageChannel();

class MessagePortWritable extends Writable {
    constructor(messagePort) {
        super();
        this.messagePort = messagePort;
    }

    _write(chunk, encoding, done) {
        if (!chunk || !chunk.length) {
            return done();
        }

        if (typeof chunk === 'string') {
            chunk = Buffer.from(chunk, encoding);
        }

        this.messagePort.postMessage({
            value: chunk,
            done: false
        });
        done();
    }

    _final(done) {
        this.messagePort.postMessage({
            done: true
        });
        try {
            this.messagePort.close();
        } catch (err) {
            //ignore
        }
        done();
    }
}

class MessagePortReadable extends Readable {
    constructor(messagePort) {
        super();
        this.messagePort = messagePort;

        this.canRead = false;

        this.readableQueue = [];
        this.messagePort.on('message', message => {
            if (message && (message.done || message.value)) {
                this.readableQueue.push(message);

                if (this.canRead && this.readableQueue.length === 1) {
                    this._processReading();
                }
            }
        });
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
        if (err && logger && typeof logger.error === 'function') {
            logger.error({ msg: 'Message stream transfer failed', err });
        }
    });
}

module.exports.MessagePortWritable = MessagePortWritable;
module.exports.MessagePortReadable = MessagePortReadable;
module.exports.pipeToMessagePort = pipeToMessagePort;
