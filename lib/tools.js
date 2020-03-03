/* eslint no-bitwise: 0 */

'use strict';

const msgpack = require('msgpack5')();
const enumMessageFlags = require('./enum-message-flags');
const Joi = require('@hapi/joi');
const fetch = require('node-fetch');
const he = require('he');
const packageData = require('../package.json');
const settings = require('./settings');

module.exports = {
    /**
     * Helper function to set specific bit in a buffer
     * @param {Buffer} buffer Buffer to edit
     * @param {Number} bytePos Which byte in buffer to edit
     * @param {Number} bit Which bit to update
     * @param {Boolean} value If true, then sets bit, if false, then clears it
     * @returns {Boolean} If true then bit was updated
     */
    setBit(buffer, bytePos, bit, value) {
        bytePos = Number(bytePos) || 0;
        if (bytePos < 0 || bytePos >= buffer.length) {
            return false;
        }

        if (!value) {
            buffer[bytePos] &= ~(1 << bit);
        } else {
            buffer[bytePos] |= 1 << bit;
        }

        return true;
    },

    /**
     * Helper function to get specific bit from a buffer
     * @param {Buffer} buffer Buffer to check for
     * @param {Number} bytePos Which byte in buffer to check
     * @param {Number} bit Which bit to check
     * @returns {Boolean} If true then bit was set, otherwise bit was not set
     */
    readBit(buffer, bytePos, bit) {
        return !!((buffer[bytePos] >> bit) % 2);
    },

    /**
     * Parses stored message entry
     * @param {Buffer} buffer Stored message entry
     * @ @returns {Object} Message entry object
     */
    unserialize(buffer) {
        // < [4B (UInt32LE) UID] [1B ENUM_FLAGS] [8B (BigUInt64LE) MODSEQ] [nB META (msgpack) [msgid, [flags], [labels]] ] >

        if (buffer.length === 1) {
            switch (buffer.toString()) {
                case 'D': {
                    return { deleted: true };
                }
                case 'N': {
                    return { placeholder: true };
                }
            }
            return {};
        }

        let uid = buffer.readUInt32LE(0);
        let modseq = buffer.readBigUInt64LE(5);

        let formatted = {
            uid,
            flags: new Set()
        };

        if (modseq) {
            formatted.modseq = modseq;
        }

        enumMessageFlags.forEach((flag, i) => {
            if (module.exports.readBit(buffer, 4, i)) {
                formatted.flags.add(flag);
            }
        });

        if (buffer.length > 4 + 1 + 8) {
            let extra = msgpack.decode(buffer.slice(4 + 1 + 8));
            if (Array.isArray(extra)) {
                let emailId = extra[0];
                if (emailId) {
                    formatted.emailId = emailId;
                }

                if (Array.isArray(extra[1])) {
                    extra[1].forEach(flag => {
                        formatted.flags.add(flag);
                    });
                }

                if (Array.isArray(extra[2])) {
                    formatted.labels = new Set(extra[2]);
                }
            }
        }

        return formatted;
    },

    /**
     * Generates message entry for storage
     * @param {Object} messageData Message entry object
     * @ @returns {Buffer} Serialized message entry for storage
     */
    serialize(messageData) {
        let buf = Buffer.alloc(4 + 1 + 8);
        buf.writeUInt32LE(messageData.uid, 0);

        let extra = [
            messageData.emailId || null, //emailId (if exists)
            null, // extra flags not in the default flag set
            null // labels if Gmail All data
        ];

        for (let flag of messageData.flags) {
            let enumFlag = enumMessageFlags.indexOf(flag);
            if (enumFlag >= 0) {
                module.exports.setBit(buf, 4, enumFlag, true);
            } else {
                if (!extra[1]) {
                    extra[1] = [];
                }
                extra[1].push(flag);
            }
        }

        if (messageData.labels && messageData.labels.size) {
            extra[2] = Array.from(messageData.labels);
        }

        if (messageData.modseq) {
            buf.writeBigUInt64LE(messageData.modseq, 5);
        }

        return Buffer.concat([buf, msgpack.encode(extra)]);
    },

    /**
     * Compares two message objects to see if there are any changes
     * @param {*} storedMessageEntry
     * @param {*} messageData
     * @returns {Object | Boolean} Changes or false
     */
    compareExisting(storedMessageEntry, messageData, keys) {
        const changes = {};
        let hasChanges = false;

        // detect deleted flags
        if (!keys || keys.includes('flags')) {
            for (let flag of storedMessageEntry.flags.values()) {
                if (!messageData.flags.has(flag)) {
                    if (!changes.flags) {
                        changes.flags = {};
                    }
                    if (!changes.flags.deleted) {
                        changes.flags.deleted = [];
                    }
                    changes.flags.deleted.push(flag);
                    hasChanges = true;
                }
            }

            // detect added flags
            for (let flag of messageData.flags.values()) {
                if (!storedMessageEntry.flags.has(flag)) {
                    if (!changes.flags) {
                        changes.flags = {};
                    }
                    if (!changes.flags.added) {
                        changes.flags.added = [];
                    }
                    changes.flags.added.push(flag);
                    hasChanges = true;
                }
            }
        }

        if (!keys || keys.includes('labels')) {
            if (storedMessageEntry.labels || messageData.labels) {
                if (storedMessageEntry.labels) {
                    // detect deleted labels
                    for (let flag of storedMessageEntry.labels.values()) {
                        if (!messageData.labels || !messageData.labels.has(flag)) {
                            if (!changes.labels) {
                                changes.labels = {};
                            }
                            if (!changes.labels.deleted) {
                                changes.labels.deleted = [];
                            }
                            changes.labels.deleted.push(flag);
                            hasChanges = true;
                        }
                    }
                }
                if (messageData.labels) {
                    // detect added labels
                    for (let flag of messageData.labels.values()) {
                        if (!storedMessageEntry.labels || !storedMessageEntry.labels.has(flag)) {
                            if (!changes.labels) {
                                changes.labels = {};
                            }
                            if (!changes.labels.added) {
                                changes.labels.added = [];
                            }
                            changes.labels.added.push(flag);
                            hasChanges = true;
                        }
                    }
                }
            }
        }

        return hasChanges ? changes : false;
    },

    normalizePath(path) {
        if (/^INBOX$/i.test(path)) {
            return 'INBOX';
        }
        return path;
    },

    async resolveCredentials(account, proto) {
        let authServer = await settings.get('authServer');
        if (!authServer) {
            let err = new Error('Authentication server requested but not set');
            throw err;
        }

        let headers = { 'User-Agent': `${packageData.name}/${packageData.version} (+https://imapapi.com)` };

        let parsed = new URL(authServer);
        let username, password;

        if (parsed.username) {
            username = he.decode(parsed.username);
            parsed.username = '';
        }

        if (parsed.password) {
            password = he.decode(parsed.password);
            parsed.password = '';
        }

        if (username || password) {
            headers.Authorization = `Basic ${Buffer.from(he.encode(username || '') + ':' + he.encode(password || '')).toString('base64')}`;
        }

        parsed.searchParams.set('account', account);
        parsed.searchParams.set('proto', proto);

        let authResponse = await fetch(parsed.toString(), { method: 'GET', headers });
        if (!authResponse.ok) {
            throw new Error(`Invalid response: ${authResponse.status} ${authResponse.statusText}`);
        }

        let authData = await authResponse.json();

        const schema = Joi.object({
            user: Joi.string()
                .max(256)
                .required(),
            pass: Joi.string()
                .allow('')
                .max(256),
            accessToken: Joi.string().max(2 * 256)
        }).xor('pass', 'accessToken');

        const { error, value } = schema.validate(authData, {
            abortEarly: false,
            stripUnknown: true,
            convert: true
        });

        if (error) {
            throw error;
        }

        return value;
    }
};
