'use strict';

const streams = require('stream');
const Transform = streams.Transform;

// make sure that a stream piped to this transform stream
// always emits a fixed amounts of bytes. Either by truncating
// input or emitting padding characters
class LengthLimiter extends Transform {
    constructor(expectedLength, padding, startFrom, byteCounter) {
        super();
        this.expectedLength = expectedLength;
        this.padding = padding || ' ';
        this.byteCounter = byteCounter || 0;
        this.startFrom = startFrom || 0;
        this.finished = false;
        Transform.call(this);
    }

    _transform(chunk, encoding, done) {
        if (encoding !== 'buffer') {
            chunk = Buffer.from(chunk, encoding);
        }

        if (!chunk || !chunk.length || this.finished) {
            return done();
        }

        // not yet at allowed position
        if (chunk.length + this.byteCounter <= this.startFrom) {
            // ignore
            this.byteCounter += chunk.length;
            return done();
        }

        // start emitting at middle of chunk
        if (this.byteCounter < this.startFrom) {
            // split the chunk and ignore the first part
            chunk = chunk.slice(this.startFrom - this.byteCounter);
            this.byteCounter += this.startFrom - this.byteCounter;
        }

        // can emit full chunk
        if (chunk.length + this.byteCounter <= this.expectedLength) {
            this.byteCounter += chunk.length;
            this.push(chunk);
            if (this.byteCounter >= this.expectedLength) {
                this.finished = true;
                this.emit('done', false);
            }
            return setImmediate(done);
        }

        // stop emitting in the middle of chunk
        let buf = chunk.slice(0, this.expectedLength - this.byteCounter);
        let remaining = chunk.slice(this.expectedLength - this.byteCounter);
        this.push(buf);
        this.finished = true;
        this.emit('done', remaining);
        return setImmediate(done);
    }

    _flush(done) {
        if (!this.finished) {
            // add padding if incoming stream stopped too early
            if (this.expectedLength > this.byteCounter) {
                let buf = Buffer.from(this.padding.repeat(this.expectedLength - this.byteCounter));
                this.push(buf);
            }
            this.finished = true;
        }
        done();
    }
}

module.exports = LengthLimiter;
