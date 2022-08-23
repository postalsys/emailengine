'use strict';

const addressparser = require('nodemailer/lib/addressparser');

/**
 * Parses a RFC822 message into a structured object (JSON compatible)
 *
 * @constructor
 * @param {String|Buffer} rfc822 Raw body of the message
 */
class MIMEParser {
    constructor(rfc822) {
        // ensure the input is a binary string
        this.rfc822 = (rfc822 || '').toString('binary');

        this._br = '';
        this._pos = 0;

        this.rawBody = '';

        this.tree = {
            rootNode: true,
            childNodes: []
        };
        this._node = this.createNode(this.tree);
    }

    /**
     * Parses the message, line by line
     */
    parse() {
        let line,
            prevBr = '';

        // keep parsing until the last linebreak is not a string (no linebreaks anymore)
        while (typeof this._br === 'string') {
            line = this.readLine();

            switch (this._node.state) {
                case 'header': // process header section
                    if (this.rawBody) {
                        this.rawBody += prevBr + line;
                    }

                    if (!line) {
                        this.processNodeHeader();
                        this.processContentType();

                        this._node.state = 'body';
                    } else {
                        this._node.header.push(line);
                    }
                    break;

                case 'body': // process body section
                    this.rawBody += prevBr + line;

                    if (this._node.parentBoundary && (line === '--' + this._node.parentBoundary || line === '--' + this._node.parentBoundary + '--')) {
                        if (
                            this._node.parsedHeader['content-type'].value === 'message/rfc822' &&
                            (!this._node.parsedHeader['content-transfer-encoding'] ||
                                ['7bit', '8bit', 'binary'].includes(this._node.parsedHeader['content-transfer-encoding']))
                        ) {
                            this._node.message = parse(this._node.body.join(''));
                        }

                        if (line === '--' + this._node.parentBoundary) {
                            this._node = this.createNode(this._node.parentNode);
                        } else {
                            this._node = this._node.parentNode;
                        }
                    } else if (this._node.boundary && line === '--' + this._node.boundary) {
                        this._node = this.createNode(this._node);
                    } else {
                        // push the line with previous linebreak value
                        // if the array is joined together to a one string,
                        // then the linebreaks in the string are the 'original' ones
                        this._node.body.push((this._node.body.length ? prevBr : '') + line);
                    }
                    break;

                default:
                    // never should be reached
                    throw new Error('Unexpected state');
            }

            // store the linebreak for later usage
            prevBr = this._br;
        }
    }

    /**
     * Reads a line from the message body
     *
     * @return {String|Boolean} A line from the message
     */
    readLine() {
        let match = this.rfc822.substr(this._pos).match(/(.*?)(\r*\n|\r(?!\n)|\r*$)/);
        if (match) {
            this._br = match[2] || false;
            this._pos += match[0].length;

            return match[1];
        }
        return false;
    }

    /**
     * Join body arrays into strings. Removes unnecessary fields
     * from the tree (circular references prohibit conversion to JSON)
     */
    finalizeTree() {
        if (this._node.state === 'header') {
            this.processNodeHeader();
            this.processContentType();
        }

        if (this.tree.parsedHeader && this.tree.parsedHeader['content-type'].value === 'message/rfc822') {
            this.tree.message = parse(this.tree.body.join(''));
        }

        let walker = node => {
            if (node.body) {
                if (node.parentNode === this.tree && node.parsedHeader['content-type'].value === 'message/rfc822') {
                    node.message = parse(node.body.join(''));
                }

                node.lineCount = node.body.length ? node.body.length - 1 : 0;
                node.body = Buffer.from(
                    node.body
                        .join('')
                        // ensure proper line endings
                        .replace(/\r?\n/g, '\r\n'),
                    'binary'
                );
                node.size = node.body.length;
            }
            node.childNodes.forEach(walker);

            // remove unneeded properties
            delete node.parentNode;
            delete node.state;
            if (!node.childNodes.length) {
                delete node.childNodes;
            }
            delete node.parentBoundary;
        };
        walker(this.tree);
    }

    /**
     * Creates a new node with default values for the parse tree
     */
    createNode(parentNode) {
        let node = {
            state: 'header',
            childNodes: [],
            header: [],
            parsedHeader: {},
            body: [],
            multipart: false,
            parentBoundary: parentNode.boundary,
            boundary: false,
            parentNode
        };
        parentNode.childNodes.push(node);
        return node;
    }

    /**
     * Processes header lines. Splits lines to key-value pairs
     * and processes special values
     */
    processNodeHeader() {
        let key, value;

        for (let i = this._node.header.length - 1; i >= 0; i--) {
            if (i && this._node.header[i].match(/^\s/)) {
                this._node.header[i - 1] = this._node.header[i - 1] + '\r\n' + this._node.header[i];
                this._node.header.splice(i, 1);
            } else {
                value = this._node.header[i].split(':');
                key = (value.shift() || '').trim().toLowerCase();
                value = value.join(':').trim();

                // Do not touch headers that have strange looking keys, keep these
                // only in the unparsed array
                if (/[^a-zA-Z0-9\-*]/.test(key) || key.length >= 100) {
                    continue;
                }

                // assume UTF-8 for binary headers
                value = Buffer.from(value, 'binary').toString();

                if (key in this._node.parsedHeader) {
                    if (Array.isArray(this._node.parsedHeader[key])) {
                        this._node.parsedHeader[key].unshift(value);
                    } else {
                        this._node.parsedHeader[key] = [value, this._node.parsedHeader[key]];
                    }
                } else {
                    this._node.parsedHeader[key] = value.replace(/\s*\r?\n\s*/g, ' ');
                }
            }
        }

        // always ensure the presence of Content-Type
        if (!this._node.parsedHeader['content-type']) {
            this._node.parsedHeader['content-type'] = 'text/plain';
        }

        // parse additional params for Content-Type and Content-Disposition
        ['content-type', 'content-disposition'].forEach(key => {
            if (this._node.parsedHeader[key]) {
                this._node.parsedHeader[key] = this.parseValueParams([].concat(this._node.parsedHeader[key] || []).pop());
            }
        });

        // ensure single value for selected fields
        [
            'in-reply-to',
            'message-id',
            'content-transfer-encoding',
            'content-id',
            'content-description',
            'content-language',
            'content-md5',
            'content-location'
        ].forEach(key => {
            if (Array.isArray(this._node.parsedHeader[key])) {
                this._node.parsedHeader[key] = this._node.parsedHeader[key].pop();
            }
        });

        // Parse address fields (join several fields with same key)
        ['from', 'sender', 'reply-to', 'to', 'cc', 'bcc'].forEach(key => {
            let addresses = [];
            if (this._node.parsedHeader[key]) {
                [].concat(this._node.parsedHeader[key] || []).forEach(value => {
                    if (value) {
                        addresses = addresses.concat(addressparser(value) || []);
                    }
                });
                this._node.parsedHeader[key] = addresses;
            }
        });
    }

    /**
     * Splits a value to an object.
     * eg. 'text/plain; charset=utf-8' -> {value: 'text/plain', params:{charset: 'utf-8'}}
     *
     * @param {String} headerValue A string value for a header key
     * @return {Object} Parsed value
     */
    parseValueParams(headerValue) {
        let data = {
            value: '',
            type: '',
            subtype: '',
            params: {}
        };
        let match;
        let processEncodedWords = {};

        (headerValue || '').split(';').forEach((part, i) => {
            let key, value;
            if (!i) {
                data.value = part.trim();
                data.subtype = data.value.split('/');
                data.type = (data.subtype.shift() || '').toLowerCase();
                data.subtype = data.subtype.join('/');
                return;
            }
            value = part.split('=');
            key = (value.shift() || '').trim().toLowerCase();
            value = value.join('=').replace(/^['"\s]*|['"\s]*$/g, '');

            // Do not touch headers that have strange looking keys, keep these
            // only in the unparsed array
            if (/[^a-zA-Z0-9\-*]/.test(key) || key.length >= 100) {
                return;
            }

            // This regex allows for an optional trailing asterisk, for headers
            // which are encoded with lang/charset info as well as a continuation.
            // See https://tools.ietf.org/html/rfc2231 section 4.1.
            if ((match = key.match(/^([^*]+)\*(\d)?\*?$/))) {
                if (!processEncodedWords[match[1]]) {
                    processEncodedWords[match[1]] = [];
                }
                processEncodedWords[match[1]][Number(match[2]) || 0] = value;
            } else {
                data.params[key] = value;
            }
            data.hasParams = true;
        });

        // convert extended mime word into a regular one
        Object.keys(processEncodedWords).forEach(key => {
            let charset = '';
            let value = '';
            processEncodedWords[key].forEach(val => {
                let parts = val.split("'"); // eslint-disable-line quotes
                charset = charset || parts.shift();
                value += (parts.pop() || '').replace(/%/g, '=');
            });
            data.params[key] = '=?' + (charset || 'ISO-8859-1').toUpperCase() + '?Q?' + value + '?=';
        });

        return data;
    }

    /**
     * Checks Content-Type value for the current tree node.
     */
    processContentType() {
        if (!this._node.parsedHeader['content-type']) {
            return;
        }

        if (this._node.parsedHeader['content-type'].type === 'multipart' && this._node.parsedHeader['content-type'].params.boundary) {
            this._node.multipart = this._node.parsedHeader['content-type'].subtype;
            this._node.boundary = this._node.parsedHeader['content-type'].params.boundary;
        }
    }
}

function parse(rfc822) {
    let parser = new MIMEParser(rfc822);
    let response;

    parser.parse();
    parser.finalizeTree();

    response = parser.tree.childNodes[0] || false;
    return response;
}

module.exports = parse;
