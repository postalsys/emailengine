'use strict';

const { Writable, Readable } = require('stream');

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

module.exports.MessagePortWritable = MessagePortWritable;
module.exports.MessagePortReadable = MessagePortReadable;
