/* eslint new-cap: 0 */

'use strict';

const imapFormalSyntax = require('./imap-formal-syntax');

class TokenParser {
    constructor(parent, startPos, str, options) {
        this.str = (str || '').toString();
        this.options = options || {};
        this.parent = parent;

        this.tree = this.currentNode = this.createNode();
        this.pos = startPos || 0;

        this.currentNode.type = 'TREE';

        this.state = 'NORMAL';

        this.processString();
    }

    getAttributes() {
        let attributes = [],
            branch = attributes;

        let walk = function (node) {
            let curBranch = branch;
            let elm;
            let partial;

            if (!node.closed && node.type === 'SEQUENCE' && node.value === '*') {
                node.closed = true;
                node.type = 'ATOM';
            }

            // If the node was never closed, throw it
            if (!node.closed) {
                throw new Error('Unexpected end of input at position ' + (this.pos + this.str.length - 1));
            }

            let type = (node.type || '').toString().toUpperCase();

            switch (type) {
                case 'LITERAL':
                case 'STRING':
                case 'SEQUENCE':
                    elm = {
                        type: node.type.toUpperCase(),
                        value: node.value
                    };
                    branch.push(elm);
                    break;

                case 'ATOM':
                    if (node.value.toUpperCase() === 'NIL') {
                        branch.push(null);
                        break;
                    }
                    elm = {
                        type: node.type.toUpperCase(),
                        value: node.value
                    };
                    branch.push(elm);
                    break;

                case 'SECTION':
                    branch = branch[branch.length - 1].section = [];
                    break;

                case 'LIST':
                    elm = [];
                    branch.push(elm);
                    branch = elm;
                    break;

                case 'PARTIAL':
                    partial = node.value.split('.').map(Number);
                    branch[branch.length - 1].partial = partial;
                    break;
            }

            node.childNodes.forEach(childNode => walk(childNode));
            branch = curBranch;
        }.bind(this);

        walk(this.tree);

        return attributes;
    }

    createNode(parentNode, startPos) {
        let node = {
            childNodes: [],
            type: false,
            value: '',
            closed: true
        };

        if (parentNode) {
            node.parentNode = parentNode;
        }

        if (typeof startPos === 'number') {
            node.startPos = startPos;
        }

        if (parentNode) {
            parentNode.childNodes.push(node);
        }

        return node;
    }

    processString() {
        let chr,
            i,
            len,
            checkSP = function () {
                // jump to the next non whitespace pos
                while (this.str.charAt(i + 1) === ' ') {
                    i++;
                }
            }.bind(this);

        for (i = 0, len = this.str.length; i < len; i++) {
            chr = this.str.charAt(i);

            switch (this.state) {
                case 'NORMAL':
                    switch (chr) {
                        // DQUOTE starts a new string
                        case '"':
                            this.currentNode = this.createNode(this.currentNode, this.pos + i);
                            this.currentNode.type = 'string';
                            this.state = 'STRING';
                            this.currentNode.closed = false;
                            break;

                        // ( starts a new list
                        case '(':
                            this.currentNode = this.createNode(this.currentNode, this.pos + i);
                            this.currentNode.type = 'LIST';
                            this.currentNode.closed = false;
                            break;

                        // ) closes a list
                        case ')':
                            if (this.currentNode.type !== 'LIST') {
                                throw new Error('Unexpected list terminator ) at position ' + (this.pos + i));
                            }

                            this.currentNode.closed = true;
                            this.currentNode.endPos = this.pos + i;
                            this.currentNode = this.currentNode.parentNode;

                            checkSP();
                            break;

                        // ] closes section group
                        case ']':
                            if (this.currentNode.type !== 'SECTION') {
                                throw new Error('Unexpected section terminator ] at position ' + (this.pos + i));
                            }
                            this.currentNode.closed = true;
                            this.currentNode.endPos = this.pos + i;
                            this.currentNode = this.currentNode.parentNode;
                            checkSP();
                            break;

                        // < starts a new partial
                        case '<':
                            if (this.str.charAt(i - 1) !== ']') {
                                this.currentNode = this.createNode(this.currentNode, this.pos + i);
                                this.currentNode.type = 'ATOM';
                                this.currentNode.value = chr;
                                this.state = 'ATOM';
                            } else {
                                this.currentNode = this.createNode(this.currentNode, this.pos + i);
                                this.currentNode.type = 'PARTIAL';
                                this.state = 'PARTIAL';
                                this.currentNode.closed = false;
                            }
                            break;

                        // ~{ starts a new literal8
                        //case '~':
                        // ignore
                        //  break;

                        // { starts a new literal
                        case '{':
                            this.currentNode = this.createNode(this.currentNode, this.pos + i);
                            this.currentNode.type = 'LITERAL';
                            this.state = 'LITERAL';
                            this.currentNode.closed = false;
                            break;

                        // ( starts a new sequence
                        case '*':
                            this.currentNode = this.createNode(this.currentNode, this.pos + i);
                            this.currentNode.type = 'SEQUENCE';
                            this.currentNode.value = chr;
                            this.currentNode.closed = false;
                            this.state = 'SEQUENCE';
                            break;

                        // normally a space should never occur
                        case ' ':
                            // just ignore
                            break;

                        // [ starts section
                        case '[':
                            // If it is the *first* element after response command, then process as a response argument list
                            if (['OK', 'NO', 'BAD', 'BYE', 'PREAUTH'].indexOf(this.parent.command.toUpperCase()) >= 0 && this.currentNode === this.tree) {
                                this.currentNode.endPos = this.pos + i;

                                this.currentNode = this.createNode(this.currentNode, this.pos + i);
                                this.currentNode.type = 'ATOM';

                                this.currentNode = this.createNode(this.currentNode, this.pos + i);
                                this.currentNode.type = 'SECTION';
                                this.currentNode.closed = false;
                                this.state = 'NORMAL';

                                // RFC2221 defines a response code REFERRAL whose payload is an
                                // RFC2192/RFC5092 imapurl that we will try to parse as an ATOM but
                                // fail quite badly at parsing.  Since the imapurl is such a unique
                                // (and crazy) term, we just specialize that case here.
                                if (this.str.substr(i + 1, 9).toUpperCase() === 'REFERRAL ') {
                                    // create the REFERRAL atom
                                    this.currentNode = this.createNode(this.currentNode, this.pos + i + 1);
                                    this.currentNode.type = 'ATOM';
                                    this.currentNode.endPos = this.pos + i + 8;
                                    this.currentNode.value = 'REFERRAL';
                                    this.currentNode = this.currentNode.parentNode;

                                    // eat all the way through the ] to be the  IMAPURL token.
                                    this.currentNode = this.createNode(this.currentNode, this.pos + i + 10);
                                    // just call this an ATOM, even though IMAPURL might be more correct
                                    this.currentNode.type = 'ATOM';
                                    // jump i to the ']'
                                    i = this.str.indexOf(']', i + 10);
                                    this.currentNode.endPos = this.pos + i - 1;
                                    this.currentNode.value = this.str.substring(this.currentNode.startPos - this.pos, this.currentNode.endPos - this.pos + 1);
                                    this.currentNode = this.currentNode.parentNode;

                                    // close out the SECTION
                                    this.currentNode.closed = true;
                                    this.currentNode = this.currentNode.parentNode;
                                    checkSP();
                                }

                                break;
                            }
                        /* falls through */
                        default:
                            // Any ATOM supported char starts a new Atom sequence, otherwise throw an error
                            // Allow \ as the first char for atom to support system flags
                            // Allow % to support LIST '' %
                            if (imapFormalSyntax['ATOM-CHAR']().indexOf(chr) < 0 && chr !== '\\' && chr !== '%') {
                                throw new Error('Unexpected char at position ' + (this.pos + i));
                            }

                            this.currentNode = this.createNode(this.currentNode, this.pos + i);
                            this.currentNode.type = 'ATOM';
                            this.currentNode.value = chr;
                            this.state = 'ATOM';
                            break;
                    }
                    break;

                case 'ATOM':
                    // space finishes an atom
                    if (chr === ' ') {
                        this.currentNode.endPos = this.pos + i - 1;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';
                        break;
                    }

                    // UTF8 (~{bytes}<CR><LF><literal8>)
                    // Seems like literal8
                    if (
                        chr === '{' &&
                        this.currentNode.value === '~' &&
                        this.currentNode.parentNode &&
                        this.currentNode.parentNode.type === 'LIST' &&
                        this.currentNode.parentNode.parentNode &&
                        this.currentNode.parentNode.parentNode.childNodes.length > 1
                    ) {
                        let nbrs = this.currentNode.parentNode.parentNode.childNodes;
                        let leftNbr = nbrs[nbrs.length - 2];
                        if (leftNbr.type === 'ATOM' && /^UTF8$/i.test(leftNbr.value)) {
                            // remove unneeded ATOM that was issued for "~"
                            this.currentNode.parentNode.childNodes.pop();
                            // start over as a literal
                            this.currentNode = this.createNode(this.currentNode.parentNode, this.pos + i);
                            this.currentNode.type = 'LITERAL';
                            this.state = 'LITERAL';
                            this.currentNode.closed = false;
                            break;
                        }
                    }

                    //
                    if (
                        this.currentNode.parentNode &&
                        ((chr === ')' && this.currentNode.parentNode.type === 'LIST') || (chr === ']' && this.currentNode.parentNode.type === 'SECTION'))
                    ) {
                        this.currentNode.endPos = this.pos + i - 1;
                        this.currentNode = this.currentNode.parentNode;

                        this.currentNode.closed = true;
                        this.currentNode.endPos = this.pos + i;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';

                        checkSP();
                        break;
                    }

                    if ((chr === ',' || chr === ':') && this.currentNode.value.match(/^\d+$/)) {
                        this.currentNode.type = 'SEQUENCE';
                        this.currentNode.closed = true;
                        this.state = 'SEQUENCE';
                    }

                    // [ starts a section group for this element
                    if (chr === '[') {
                        // allowed only for selected elements
                        if (['BODY', 'BODY.PEEK'].indexOf(this.currentNode.value.toUpperCase()) < 0) {
                            throw new Error('Unexpected section start char [ at position ' + this.pos);
                        }
                        this.currentNode.endPos = this.pos + i;
                        this.currentNode = this.createNode(this.currentNode.parentNode, this.pos + i);
                        this.currentNode.type = 'SECTION';
                        this.currentNode.closed = false;
                        this.state = 'NORMAL';
                        break;
                    }

                    if (chr === '<') {
                        throw new Error('Unexpected start of partial at position ' + this.pos);
                    }

                    // if the char is not ATOM compatible, throw. Allow \* as an exception
                    if (imapFormalSyntax['ATOM-CHAR']().indexOf(chr) < 0 && chr !== ']' && !(chr === '*' && this.currentNode.value === '\\')) {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    } else if (this.currentNode.value === '\\*') {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    }

                    this.currentNode.value += chr;
                    break;

                case 'STRING':
                    // DQUOTE ends the string sequence
                    if (chr === '"') {
                        this.currentNode.endPos = this.pos + i;
                        this.currentNode.closed = true;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';

                        checkSP();
                        break;
                    }

                    // \ Escapes the following char
                    if (chr === '\\') {
                        i++;
                        if (i >= len) {
                            throw new Error('Unexpected end of input at position ' + (this.pos + i));
                        }
                        chr = this.str.charAt(i);
                    }

                    /* // skip this check, otherwise the parser might explode on binary input
                    if (imapFormalSyntax['TEXT-CHAR']().indexOf(chr) < 0) {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    }
                    */

                    this.currentNode.value += chr;
                    break;

                case 'PARTIAL':
                    if (chr === '>') {
                        if (this.currentNode.value.substr(-1) === '.') {
                            throw new Error('Unexpected end of partial at position ' + this.pos);
                        }
                        this.currentNode.endPos = this.pos + i;
                        this.currentNode.closed = true;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';
                        checkSP();
                        break;
                    }

                    if (chr === '.' && (!this.currentNode.value.length || this.currentNode.value.match(/\./))) {
                        throw new Error('Unexpected partial separator . at position ' + this.pos);
                    }

                    if (imapFormalSyntax.DIGIT().indexOf(chr) < 0 && chr !== '.') {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    }

                    if (this.currentNode.value.match(/^0$|\.0$/) && chr !== '.') {
                        throw new Error('Invalid partial at position ' + (this.pos + i));
                    }

                    this.currentNode.value += chr;
                    break;

                case 'LITERAL':
                    if (this.currentNode.started) {
                        // only relevant if literals are not already parsed out from input

                        //if(imapFormalSyntax['CHAR8']().indexOf(chr) < 0){
                        if (chr === '\u0000') {
                            throw new Error('Unexpected \\x00 at position ' + (this.pos + i));
                        }

                        this.currentNode.chBuffer[this.currentNode.chPos++] = chr.charCodeAt(0);

                        if (this.currentNode.chPos >= this.currentNode.literalLength) {
                            this.currentNode.endPos = this.pos + i;
                            this.currentNode.closed = true;
                            this.currentNode.value = this.currentNode.chBuffer.toString('binary');
                            this.currentNode.chBuffer = Buffer.alloc(0);
                            this.currentNode = this.currentNode.parentNode;
                            this.state = 'NORMAL';
                            checkSP();
                        }
                        break;
                    }

                    if (chr === '+' && !this.currentNode.literalLength && this.options.literalPlus) {
                        this.currentNode.literalPlus = true;
                        break;
                    }

                    if (chr === '}') {
                        if (!('literalLength' in this.currentNode)) {
                            throw new Error('Unexpected literal prefix end char } at position ' + (this.pos + i));
                        }
                        if (this.str.charAt(i + 1) === '\n') {
                            i++;
                        } else if (this.str.charAt(i + 1) === '\r' && this.str.charAt(i + 2) === '\n') {
                            i += 2;
                        } else {
                            throw new Error('Unexpected char at position ' + (this.pos + i));
                        }

                        this.currentNode.literalLength = Number(this.currentNode.literalLength);

                        if (!this.currentNode.literalLength) {
                            // special case where literal content length is 0
                            // close the node right away, do not wait for additional input
                            this.currentNode.endPos = this.pos + i;
                            this.currentNode.closed = true;
                            this.currentNode = this.currentNode.parentNode;
                            this.state = 'NORMAL';
                            checkSP();
                        } else if (this.options.literals) {
                            // use the next precached literal values
                            this.currentNode.value = this.options.literals.shift();

                            // only APPEND arguments are kept as Buffers
                            if ((this.parent.command || '').toString().toUpperCase() !== 'APPEND') {
                                this.currentNode.value = this.currentNode.value.toString('binary');
                            }

                            this.currentNode.endPos = this.pos + i + this.currentNode.value.length;

                            this.currentNode.started = false;
                            this.currentNode.closed = true;
                            this.currentNode = this.currentNode.parentNode;
                            this.state = 'NORMAL';
                            checkSP();
                        } else {
                            this.currentNode.started = true;
                            // Allocate expected size buffer. Max size check is already performed
                            // Maybe should use allocUnsafe instead?
                            this.currentNode.chBuffer = Buffer.alloc(this.currentNode.literalLength);
                            this.currentNode.chPos = 0;
                        }
                        break;
                    }
                    if (imapFormalSyntax.DIGIT().indexOf(chr) < 0) {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    }
                    if (this.currentNode.literalLength === '0') {
                        throw new Error('Invalid literal at position ' + (this.pos + i));
                    }
                    this.currentNode.literalLength = (this.currentNode.literalLength || '') + chr;
                    break;

                case 'SEQUENCE':
                    // space finishes the sequence set
                    if (chr === ' ') {
                        if (!this.currentNode.value.substr(-1).match(/\d/) && this.currentNode.value.substr(-1) !== '*') {
                            throw new Error('Unexpected whitespace at position ' + (this.pos + i));
                        }

                        if (this.currentNode.value !== '*' && this.currentNode.value.substr(-1) === '*' && this.currentNode.value.substr(-2, 1) !== ':') {
                            throw new Error('Unexpected whitespace at position ' + (this.pos + i));
                        }

                        this.currentNode.closed = true;
                        this.currentNode.endPos = this.pos + i - 1;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';
                        break;
                    } else if (this.currentNode.parentNode && chr === ']' && this.currentNode.parentNode.type === 'SECTION') {
                        this.currentNode.endPos = this.pos + i - 1;
                        this.currentNode = this.currentNode.parentNode;

                        this.currentNode.closed = true;
                        this.currentNode.endPos = this.pos + i;
                        this.currentNode = this.currentNode.parentNode;
                        this.state = 'NORMAL';

                        checkSP();
                        break;
                    }

                    if (chr === ':') {
                        if (!this.currentNode.value.substr(-1).match(/\d/) && this.currentNode.value.substr(-1) !== '*') {
                            throw new Error('Unexpected range separator : at position ' + (this.pos + i));
                        }
                    } else if (chr === '*') {
                        if ([',', ':'].indexOf(this.currentNode.value.substr(-1)) < 0) {
                            throw new Error('Unexpected range wildcard at position ' + (this.pos + i));
                        }
                    } else if (chr === ',') {
                        if (!this.currentNode.value.substr(-1).match(/\d/) && this.currentNode.value.substr(-1) !== '*') {
                            throw new Error('Unexpected sequence separator , at position ' + (this.pos + i));
                        }
                        if (this.currentNode.value.substr(-1) === '*' && this.currentNode.value.substr(-2, 1) !== ':') {
                            throw new Error('Unexpected sequence separator , at position ' + (this.pos + i));
                        }
                    } else if (!chr.match(/\d/)) {
                        throw new Error('Unexpected char at position ' + (this.pos + i));
                    }

                    if (chr.match(/\d/) && this.currentNode.value.substr(-1) === '*') {
                        throw new Error('Unexpected number at position ' + (this.pos + i));
                    }

                    this.currentNode.value += chr;
                    break;
            }
        }
    }
}

class ParserInstance {
    constructor(input, options) {
        this.input = (input || '').toString();
        this.options = options || {};
        this.remainder = this.input;
        this.pos = 0;
    }

    getTag() {
        if (!this.tag) {
            this.tag = this.getElement(imapFormalSyntax.tag() + '*+', true);
        }
        return this.tag;
    }

    getCommand() {
        let responseCode;

        if (!this.command) {
            this.command = this.getElement(imapFormalSyntax.command());
        }

        switch ((this.command || '').toString().toUpperCase()) {
            case 'OK':
            case 'NO':
            case 'BAD':
            case 'PREAUTH':
            case 'BYE':
                responseCode = this.remainder.match(/^ \[(?:[^\]]*\])+/);
                if (responseCode) {
                    this.humanReadable = this.remainder.substr(responseCode[0].length).trim();
                    this.remainder = responseCode[0];
                } else {
                    this.humanReadable = this.remainder.trim();
                    this.remainder = '';
                }
                break;
        }

        return this.command;
    }

    getElement(syntax) {
        let match, element, errPos;
        if (this.remainder.match(/^\s/)) {
            throw new Error('Unexpected whitespace at position ' + this.pos);
        }

        if ((match = this.remainder.match(/^[^\s]+(?=\s|$)/))) {
            element = match[0];
            if ((errPos = imapFormalSyntax.verify(element, syntax)) >= 0) {
                throw new Error('Unexpected char at position ' + (this.pos + errPos));
            }
        } else {
            throw new Error('Unexpected end of input at position ' + this.pos);
        }

        this.pos += match[0].length;
        this.remainder = this.remainder.substr(match[0].length);

        return element;
    }

    getSpace() {
        if (!this.remainder.length) {
            throw new Error('Unexpected end of input at position ' + this.pos);
        }

        if (imapFormalSyntax.verify(this.remainder.charAt(0), imapFormalSyntax.SP()) >= 0) {
            throw new Error('Unexpected char at position ' + this.pos);
        }

        this.pos++;
        this.remainder = this.remainder.substr(1);
    }

    getAttributes() {
        if (!this.remainder.length) {
            throw new Error('Unexpected end of input at position ' + this.pos);
        }

        if (this.remainder.match(/^\s/)) {
            throw new Error('Unexpected whitespace at position ' + this.pos);
        }

        return new TokenParser(this, this.pos, this.remainder, this.options).getAttributes();
    }
}

module.exports = function (command, options) {
    let parser,
        response = {};

    options = options || {};

    parser = new ParserInstance(command, options);

    response.tag = parser.getTag();
    parser.getSpace();
    response.command = parser.getCommand();

    if (['UID', 'AUTHENTICATE'].indexOf((response.command || '').toUpperCase()) >= 0) {
        parser.getSpace();
        response.command += ' ' + parser.getElement(imapFormalSyntax.command());
    }

    if (parser.remainder.trim().length) {
        parser.getSpace();
        response.attributes = parser.getAttributes();
    }

    if (parser.humanReadable) {
        response.attributes = (response.attributes || []).concat({
            type: 'TEXT',
            value: parser.humanReadable
        });
    }

    return response;
};
