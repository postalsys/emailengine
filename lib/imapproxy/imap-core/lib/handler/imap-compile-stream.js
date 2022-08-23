/* eslint new-cap: 0 */

'use strict';

const imapFormalSyntax = require('./imap-formal-syntax');
const streams = require('stream');
const PassThrough = streams.PassThrough;
const LengthLimiter = require('../length-limiter');

const SINGLE_SPACE = Buffer.from(' ');
const LEFT_PARENTHESIS = Buffer.from('(');
const RIGHT_PARENTHESIS = Buffer.from(')');
const NIL = Buffer.from('NIL');
const LEFT_SQUARE_BRACKET = Buffer.from('[');
const RIGHT_SQUARE_BRACKET = Buffer.from(']');

let START_CHAR_LIST = [0x28, 0x3c, 0x5b]; // ['(', '<', '[']

/**
 * Compiles an input object into a streamed IMAP response
 */
module.exports = (response, isLogging) => {
    let output = new PassThrough();

    let processStream = async () => {
        let start = (response.tag || '') + (response.command ? ' ' + response.command : '');
        let resp = [].concat(start ? Buffer.from(start) : []);

        let lr = resp.length && resp[resp.length - 1]; // this value is going to store last known `resp` state for later usage

        let val, lastType;

        // emits data to socket or pushes to queue if previous write is still being processed
        let emit = async (stream, expectedLength, startFrom, maxLength) => {
            if (resp.length) {
                // emit queued response
                output.write(Buffer.concat(resp));
                lr = resp[resp.length - 1];
                resp = [];
            }

            if (!stream || !expectedLength) {
                return;
            }

            if (stream.errored) {
                let err = stream.errored;
                stream.errored = false;
                throw err;
            }

            return new Promise((resolve, reject) => {
                expectedLength = maxLength ? Math.min(expectedLength, startFrom + maxLength) : expectedLength;
                startFrom = startFrom || 0;
                maxLength = maxLength || 0;

                if (stream.isLimited) {
                    // stream is already limited
                    let limiter = new LengthLimiter(expectedLength - startFrom, ' ', 0);
                    stream.pipe(limiter).pipe(
                        output,
                        {
                            end: false
                        }
                    );
                    limiter.once('end', () => resolve());
                } else {
                    // force limites
                    let limiter = new LengthLimiter(expectedLength, ' ', startFrom);
                    stream.pipe(limiter).pipe(
                        output,
                        {
                            end: false
                        }
                    );
                    limiter.once('end', () => resolve());
                }

                // pass errors to output
                stream.once('error', reject);
            });
        };

        let walk = async (node, options) => {
            options = options || {};

            let last = (resp.length && resp[resp.length - 1]) || lr;
            let lastCharOrd = last && last.length && last[last.length - 1]; // ord value of last char

            if (lastType === 'LITERAL' || (lastCharOrd && !START_CHAR_LIST.includes(lastCharOrd))) {
                if (options.isSubArray) {
                    // ignore separator
                } else {
                    resp.push(SINGLE_SPACE);
                }
            }

            if (!node && typeof node !== 'string' && typeof node !== 'number') {
                // null or false or undefined
                return resp.push(NIL);
            }

            if (Array.isArray(node)) {
                lastType = 'LIST';

                // (...)
                resp.push(LEFT_PARENTHESIS);

                // Check if we need to skip separtor WS between two arrays
                let isSubArray = node.length > 1 && Array.isArray(node[0]);

                for (let child of node) {
                    if (isSubArray && !Array.isArray(child)) {
                        isSubArray = false;
                    }
                    await walk(child, { isSubArray });
                }

                resp.push(RIGHT_PARENTHESIS);
                return;
            }

            if (node && node.buffer && !Buffer.isBuffer(node)) {
                // mongodb binary data
                node = node.buffer;
            }

            if (typeof node === 'string' || Buffer.isBuffer(node)) {
                node = {
                    type: 'STRING',
                    value: node
                };
            }

            if (typeof node === 'number') {
                node = {
                    type: 'NUMBER',
                    value: node
                };
            }

            lastType = node.type;

            if (isLogging && node.sensitive) {
                resp.push(Buffer.from('"(* value hidden *)"'));
                return;
            }

            switch (node.type.toUpperCase()) {
                case 'LITERAL': {
                    let nodeValue = node.value;

                    if (typeof nodeValue === 'number') {
                        nodeValue = nodeValue.toString();
                    }

                    let len;

                    // Figure out correct byte length
                    if (nodeValue && typeof nodeValue.pipe === 'function') {
                        len = node.expectedLength || 0;
                        if (node.startFrom) {
                            len -= node.startFrom;
                        }
                        if (node.maxLength) {
                            len = Math.min(len, node.maxLength);
                        }
                    } else {
                        len = (nodeValue || '').toString().length;
                    }

                    if (isLogging) {
                        resp.push(Buffer.from('"(* ' + len + 'B literal *)"'));
                    } else {
                        resp.push(Buffer.from('{' + Math.max(len, 0) + '}\r\n'));

                        if (nodeValue && typeof nodeValue.pipe === 'function') {
                            //value is a stream object
                            // emit existing string before passing the stream
                            await emit(nodeValue, node.expectedLength, node.startFrom, node.maxLength);
                        } else if (Buffer.isBuffer(nodeValue)) {
                            resp.push(nodeValue);
                        } else {
                            resp.push(Buffer.from((nodeValue || '').toString('binary'), 'binary'));
                        }
                    }
                    break;
                }
                case 'STRING':
                    if (isLogging && node.value.length > 20) {
                        resp.push(Buffer.from('"(* ' + node.value.length + 'B string *)"'));
                    } else {
                        // JSON.stringify conveniently adds enclosing quotes and escapes any "\ occurences
                        resp.push(Buffer.from(JSON.stringify((node.value || '').toString('binary')), 'binary'));
                    }
                    break;

                case 'TEXT':
                case 'SEQUENCE':
                    if (Buffer.isBuffer(node.value)) {
                        resp.push(node.value);
                    } else {
                        resp.push(Buffer.from((node.value || '').toString('binary'), 'binary'));
                    }
                    break;

                case 'NUMBER':
                    resp.push(Buffer.from((node.value || 0).toString()));
                    break;

                case 'ATOM':
                case 'SECTION': {
                    val = (node.value || '').toString();

                    if (imapFormalSyntax.verify(val.charAt(0) === '\\' ? val.substr(1) : val, imapFormalSyntax['ATOM-CHAR']()) >= 0) {
                        val = JSON.stringify(val);
                    }

                    resp.push(Buffer.from(val));

                    if (node.section) {
                        resp.push(LEFT_SQUARE_BRACKET);
                        for (let child of node.section) {
                            await walk(child);
                        }
                        resp.push(RIGHT_SQUARE_BRACKET);
                    }

                    if (node.partial) {
                        resp.push(Buffer.from('<' + node.partial[0] + '>'));
                    }
                }
            }
        };

        for (let attrib of [].concat(response.attributes || [])) {
            await walk(attrib);
        }

        // push whatever we have queued to socket
        await emit();
    };

    setImmediate(() => {
        processStream()
            .then(() => {
                output.end();
            })
            .catch(err => {
                output.emit('error', err);
            });
    });

    return output;
};

// expose for testing
module.exports.LengthLimiter = LengthLimiter;
