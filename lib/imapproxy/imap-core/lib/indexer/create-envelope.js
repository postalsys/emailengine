'use strict';

const libmime = require('libmime');
const punycode = require('punycode/');

// This module converts message structure into an ENVELOPE object

/**
 * Convert a message header object to an ENVELOPE object
 *
 * @param {Object} message A parsed mime tree node
 * @return {Object} ENVELOPE compatible object
 */
module.exports = function (header) {
    let subject = Array.isArray(header.subject) ? header.subject.reverse().filter(line => line.trim()) : header.subject;
    subject = Buffer.from(subject || '', 'binary').toString();

    try {
        subject = Buffer.from(libmime.decodeWords(subject).trim());
    } catch (E) {
        // failed to parse subject, keep as is (most probably an unknown charset is used)
    }

    return [
        header.date || null,
        subject,
        processAddress(header.from),
        processAddress(header.sender, header.from),
        processAddress(header['reply-to'], header.from),
        processAddress(header.to),
        processAddress(header.cc),
        processAddress(header.bcc),
        header['in-reply-to'] || null,
        header['message-id'] || null
    ];
};

/**
 * Converts an address object to a list of arrays
 * [{name: 'User Name', addres:'user@example.com'}] -> [['User Name', null, 'user', 'example.com']]
 *
 * @param {Array} arr An array of address objects
 * @return {Array} A list of addresses
 */
function processAddress(arr, defaults) {
    arr = [].concat(arr || []);
    if (!arr.length) {
        arr = [].concat(defaults || []);
    }
    if (!arr.length) {
        return null;
    }
    let result = [];
    arr.forEach(addr => {
        if (!addr.group) {
            let name = addr.name || null;
            let user = (addr.address || '').split('@').shift() || null;
            let domain = (addr.address || '').split('@').pop() || null;

            if (name) {
                try {
                    name = Buffer.from(libmime.decodeWords(name));
                } catch (E) {
                    // failed to parse
                }
            }

            if (user) {
                try {
                    user = Buffer.from(libmime.decodeWords(user));
                } catch (E) {
                    // failed to parse
                }
            }

            if (domain) {
                try {
                    domain = Buffer.from(punycode.toUnicode(domain));
                } catch (E) {
                    domain = Buffer.from(domain);
                }
            }

            result.push([name, null, user, domain]);
        } else {
            // Handle group syntax
            let name = addr.name || '';
            if (name) {
                try {
                    name = Buffer.from(libmime.decodeWords(name));
                } catch (E) {
                    // failed to parse
                }
            }

            result.push([null, null, name, null]);
            result = result.concat(processAddress(addr.group) || []);
            result.push([null, null, null, null]);
        }
    });

    return result;
}
