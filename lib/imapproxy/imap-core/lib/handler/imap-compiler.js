/* eslint no-console: 0, new-cap: 0 */

'use strict';

const imapFormalSyntax = require('./imap-formal-syntax');

/**
 * Compiles an input object into
 */
module.exports = function(response, asArray, isLogging) {
    let respParts = [];
    let resp = (response.tag || '') + (response.command ? ' ' + response.command : '');
    let val;
    let lastType;
    let walk = function(node, options) {
        options = options || {};

        if (lastType === 'LITERAL' || (!['(', '<', '['].includes(resp.substr(-1)) && resp.length)) {
            if (options.subArray) {
                // ignore separator
            } else {
                resp += ' ';
            }
        }

        if (node && node.buffer && !Buffer.isBuffer(node)) {
            // mongodb binary
            node = node.buffer;
        }

        if (Array.isArray(node)) {
            lastType = 'LIST';
            resp += '(';

            // check if we need to skip separtor WS between two arrays
            let subArray = node.length > 1 && Array.isArray(node[0]);

            node.forEach(child => {
                if (subArray && !Array.isArray(child)) {
                    subArray = false;
                }
                walk(child, { subArray });
            });
            resp += ')';
            return;
        }

        if (!node && typeof node !== 'string' && typeof node !== 'number' && !Buffer.isBuffer(node)) {
            resp += 'NIL';
            return;
        }

        if (typeof node === 'string' || Buffer.isBuffer(node)) {
            if (isLogging && node.length > 20) {
                resp += '"(* ' + node.length + 'B string *)"';
            } else {
                resp += JSON.stringify(node.toString('binary'));
            }
            return;
        }

        if (typeof node === 'number') {
            resp += Math.round(node) || 0; // Only integers allowed
            return;
        }

        lastType = node.type;

        if (isLogging && node.sensitive) {
            resp += '"(* value hidden *)"';
            return;
        }

        switch (node.type.toUpperCase()) {
            case 'LITERAL':
                if (isLogging) {
                    resp += '"(* ' + node.value.length + 'B literal *)"';
                } else {
                    if (!node.value) {
                        resp += '{0}\r\n';
                    } else {
                        resp += '{' + Math.max(node.value.length, 0) + '}\r\n';
                    }
                    respParts.push(resp);
                    resp = (node.value || '').toString('binary');
                }
                break;

            case 'STRING':
                if (isLogging && node.value.length > 20) {
                    resp += '"(* ' + node.value.length + 'B string *)"';
                } else {
                    resp += JSON.stringify(node.value || '');
                }
                break;
            case 'TEXT':
            case 'SEQUENCE':
                resp += (node.value || '').toString('binary');
                break;

            case 'NUMBER':
                resp += node.value || 0;
                break;

            case 'ATOM':
            case 'SECTION':
                val = (node.value || '').toString('binary');

                if (imapFormalSyntax.verify(val.charAt(0) === '\\' ? val.substr(1) : val, imapFormalSyntax['ATOM-CHAR']()) >= 0) {
                    val = JSON.stringify(val);
                }

                resp += val;

                if (node.section) {
                    resp += '[';
                    node.section.forEach(child => walk(child));
                    resp += ']';
                }
                if (node.partial) {
                    resp += '<' + node.partial.join('.') + '>';
                }
                break;
        }
    };

    [].concat(response.attributes || []).forEach(child => walk(child));

    if (resp.length) {
        respParts.push(resp);
    }

    return asArray ? respParts : respParts.join('');
};
