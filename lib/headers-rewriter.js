'use strict';

const Transform = require('stream').Transform;

class HeadersRewriter extends Transform {
    constructor(headersCb) {
        let options = {
            readableObjectMode: true,
            writableObjectMode: true
        };
        super(options);
        this.headersCb = headersCb;
    }

    _transform(obj, encoding, callback) {
        if (obj.type !== 'node' || !obj.root || !typeof this.headersCb) {
            this.push(obj);
            return callback();
        }
        this.headersCb(obj.headers)
            .then(() => {
                this.push(obj);
                return callback();
            })
            .catch(err => callback(err));
    }

    _flush(callback) {
        return callback();
    }
}

module.exports.HeadersRewriter = HeadersRewriter;
