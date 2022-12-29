'use strict';

const Indexer = require('./indexer/indexer');
const indexer = new Indexer();

module.exports.matchSearchQuery = matchSearchQuery;

const queryHandlers = {
    // always matches
    all(message, query, callback) {
        return callback(null, true);
    },

    // matches if the message object includes (exists:true) or does not include (exists:false) specifiec flag
    flag(message, query, callback) {
        let pos = [].concat(message.flags || []).indexOf(query.value);
        return callback(null, query.exists ? pos >= 0 : pos < 0);
    },

    // matches message receive date
    internaldate(message, query, callback) {
        switch (query.operator) {
            case '<':
                return callback(null, getShortDate(message.idate) < getShortDate(query.value));
            case '=':
                return callback(null, getShortDate(message.idate) === getShortDate(query.value));
            case '>=':
                return callback(null, getShortDate(message.idate) >= getShortDate(query.value));
        }
        return callback(null, false);
    },

    // matches message header date
    date(message, query, callback) {
        let date;
        if (message.hdate) {
            date = message.hdate;
        } else {
            let mimeTree = message.mimeTree;
            if (!mimeTree) {
                mimeTree = indexer.parseMimeTree(message.raw);
            }
            date = mimeTree.parsedHeader.date || message.idate;
        }

        switch (query.operator) {
            case '<':
                return callback(null, getShortDate(date) < getShortDate(query.value));
            case '=':
                return callback(null, getShortDate(date) === getShortDate(query.value));
            case '>=':
                return callback(null, getShortDate(date) >= getShortDate(query.value));
        }

        return callback(null, false);
    },

    // matches message body
    body(message, query, callback) {
        let data = indexer.getContents(
            message.mimeTree,
            {
                type: 'text'
            },
            { skipExternal: true }
        );

        let resolveData = next => {
            if (data.type !== 'stream') {
                return next(null, data.value);
            }

            let chunks = [];
            let chunklen = 0;

            data.value.once('error', err => next(err));

            data.value.on('readable', () => {
                let chunk;
                while ((chunk = data.value.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });

            data.value.on('end', () => {
                next(null, Buffer.concat(chunks, chunklen));
            });
        };

        resolveData((err, body) => {
            if (err) {
                return callback(err);
            }
            callback(
                null,
                body
                    .toString()
                    .toLowerCase()
                    .indexOf((query.value || '').toString().toLowerCase()) >= 0
            );
        });
    },

    // matches message source
    text(message, query, callback) {
        let data = indexer.getContents(
            message.mimeTree,
            {
                type: 'content'
            },
            { skipExternal: true }
        );

        let resolveData = next => {
            if (data.type !== 'stream') {
                return next(null, data.value);
            }

            let chunks = [];
            let chunklen = 0;

            data.value.once('error', err => next(err));

            data.value.on('readable', () => {
                let chunk;
                while ((chunk = data.value.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });

            data.value.on('end', () => {
                next(null, Buffer.concat(chunks, chunklen));
            });
        };

        resolveData((err, text) => {
            if (err) {
                return callback(err);
            }
            callback(
                null,
                text
                    .toString()
                    .toLowerCase()
                    .indexOf((query.value || '').toString().toLowerCase()) >= 0
            );
        });
    },

    // matches message UID number. Sequence queries are also converted to UID queries
    uid(message, query, callback) {
        return callback(null, query.value.indexOf(message.uid) >= 0);
    },

    // matches message source size
    size(message, query, callback) {
        let size = message.size;
        if (!size) {
            size = (message.raw || '').length;
        }

        switch (query.operator) {
            case '<':
                return callback(null, size < query.value);
            case '=':
                return callback(null, size === query.value);
            case '>':
                return callback(null, size > query.value);
        }

        return callback(null, false);
    },

    // matches message headers
    header(message, query, callback) {
        let mimeTree = message.mimeTree;
        if (!mimeTree) {
            mimeTree = indexer.parseMimeTree(message.raw || '');
        }

        let headers = mimeTree.header || [];
        let header = query.header;
        let term = (query.value || '').toString().toLowerCase();
        let key, value, parts;

        for (let i = 0, len = headers.length; i < len; i++) {
            parts = headers[i].split(':');
            key = (parts.shift() || '').trim().toLowerCase();

            value = parts.join(':') || '';

            if (key === header && (!term || value.toLowerCase().indexOf(term) >= 0)) {
                return callback(null, true);
            }
        }

        return callback(null, false);
    },

    // matches messages with modifyIndex exual or greater than criteria
    modseq(message, query, callback) {
        return callback(null, message.modseq >= query.value);
    },

    // charset argument is ignored
    charset(message, query, callback) {
        return callback(null, true);
    }
};

/**
 * Returns a date object with time set to 00:00 on UTC timezone
 *
 * @param {String|Date} date Date to convert
 * @returns {Date} Date object without time
 */
function getShortDate(date) {
    date = date || new Date();
    if (typeof date === 'string' || typeof date === 'number') {
        date = new Date(date);
    }
    return date.toISOString().substr(0, 10);
}

/**
 * Checks if a specific search term match the message or not
 *
 * @param {Object} message Stored message object
 * @param {Object} query Query term object
 * @returns {Boolean} Term matched (true) or not (false)
 */
function matchSearchTerm(message, query, callback) {
    if (Array.isArray(query)) {
        // AND, all terms need to match
        return matchSearchQuery(message, query, callback);
    }

    if (!query || typeof query !== 'object') {
        // unknown query term
        return setImmediate(() => callback(null, false));
    }

    switch (query.key) {
        case 'or': {
            // OR, only single match needed
            let checked = 0;
            let checkNext = () => {
                if (checked >= query.value.length) {
                    return callback(null, false);
                }
                let term = query.value[checked++];
                matchSearchTerm(message, term, (err, match) => {
                    if (err) {
                        return callback(err);
                    }
                    if (match) {
                        return callback(null, true);
                    }
                    setImmediate(checkNext);
                });
            };
            return setImmediate(checkNext);
        }
        /*
            // OR, only single match needed
            for (let i = query.value.length - 1; i >= 0; i--) {
                if (matchSearchTerm(message, query.value[i])) {
                    return true;
                }
            }
            return false;
            */
        case 'not':
            // return reverse match
            return matchSearchTerm(message, query.value, (err, match) => {
                if (err) {
                    return callback(err);
                }
                callback(null, !match);
            });
        default:
            // check if there is a handler for the term and use it
            if (queryHandlers.hasOwnProperty(query.key)) {
                return setImmediate(() => queryHandlers[query.key](message, query, callback));
            }
            return setImmediate(() => callback(null, false));
    }
}

/**
 * Traverses query tree and checks if all query terms match or not. Stops on first false match occurence
 *
 * @param {Object} message Stored message object
 * @param {Object} query Query term object
 * @returns {Boolean} Term matched (true) or not (false)
 */
function matchSearchQuery(message, query, callback) {
    if (!Array.isArray(query)) {
        query = [].concat(query || []);
    }

    let checked = 0;
    let checkNext = () => {
        if (checked >= query.length) {
            return callback(null, true);
        }
        let term = query[checked++];
        matchSearchTerm(message, term, (err, match) => {
            if (err) {
                return callback(err);
            }
            if (!match) {
                return callback(null, false);
            }
            setImmediate(checkNext);
        });
    };
    return setImmediate(checkNext);
    /*
        for (let i = 0, len = query.length; i < len; i++) {
            if (!matchSearchTerm(message, query[i])) {
                return false;
            }
        }

        return true;
        */
}
