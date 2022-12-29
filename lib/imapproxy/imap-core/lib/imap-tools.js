'use strict';

const Indexer = require('./indexer/indexer');
const libmime = require('libmime');
const punycode = require('punycode/');
const iconv = require('iconv-lite');

module.exports.systemFlagsFormatted = ['\\Answered', '\\Flagged', '\\Draft', '\\Deleted', '\\Seen'];
module.exports.systemFlags = ['\\answered', '\\flagged', '\\draft', '\\deleted', '\\seen'];

const utf7encode = str => iconv.encode(str, 'utf-7-imap').toString();
const utf7decode = str => iconv.decode(Buffer.from(str), 'utf-7-imap').toString();

module.exports.utf7encode = utf7encode;
module.exports.utf7decode = utf7decode;

module.exports.fetchSchema = {
    body: [
        true,
        {
            type: /^(\d+\.)*(CONTENT|HEADER|HEADER\.FIELDS|HEADER\.FIELDS\.NOT|TEXT|MIME|\d+)$/i,
            headers: /^(\d+\.)*(HEADER\.FIELDS|HEADER\.FIELDS\.NOT)$/i,
            startFrom: 'optional',
            maxLength: 'optional'
        }
    ],
    bodystructure: true,
    envelope: true,
    flags: true,
    internaldate: true,
    rfc822: true,
    'rfc822.header': true,
    'rfc822.size': true,
    'rfc822.text': true,
    modseq: true,
    uid: true
};

module.exports.searchSchema = {
    charset: ['string'],
    all: true,
    answered: true,
    bcc: ['string'],
    before: ['date'],
    body: ['string'],
    cc: ['string'],
    deleted: true,
    draft: true,
    flagged: true,
    from: ['string'],
    header: ['string', 'string'],
    keyword: ['string'],
    larger: ['number'],
    modseq: [['string', 'string', 'number'], ['number']],
    new: true,
    not: ['expression'],
    old: true,
    on: ['date'],
    or: ['expression', 'expression'],
    recent: true,
    seen: true,
    sentbefore: ['date'],
    senton: ['date'],
    sentsince: ['date'],
    since: ['date'],
    smaller: ['number'],
    subject: ['string'],
    text: ['string'],
    to: ['string'],
    uid: ['sequence'],
    unanswered: true,
    undeleted: true,
    undraft: true,
    unflagged: true,
    unkeyword: ['string'],
    unseen: true
};

module.exports.searchMapping = {
    all: {
        key: 'all',
        value: [true]
    },
    answered: {
        key: 'flag',
        value: ['\\Answered', true]
    },
    bcc: {
        key: 'header',
        value: ['bcc', '$1']
    },
    before: {
        key: 'internaldate',
        value: ['<', '$1']
    },
    cc: {
        key: 'header',
        value: ['cc', '$1']
    },
    deleted: {
        key: 'flag',
        value: ['\\Deleted', true]
    },
    draft: {
        key: 'flag',
        value: ['\\Draft', true]
    },
    flagged: {
        key: 'flag',
        value: ['\\Flagged', true]
    },
    from: {
        key: 'header',
        value: ['from', '$1']
    },
    keyword: {
        key: 'flag',
        value: ['$1', true]
    },
    larger: {
        key: 'size',
        value: ['>', '$1']
    },
    new: {
        key: 'flag',
        value: ['\\Recent', true, '\\Seen', false]
    },
    old: {
        key: 'flag',
        value: ['\\Recent', false]
    },
    on: {
        key: 'internaldate',
        value: ['=', '$1']
    },
    recent: {
        key: 'flag',
        value: ['\\Recent', true]
    },
    seen: {
        key: 'flag',
        value: ['\\Seen', true]
    },
    sentbefore: {
        key: 'date',
        value: ['<', '$1']
    },
    senton: {
        key: 'date',
        value: ['=', '$1']
    },
    sentsince: {
        key: 'date',
        value: ['>=', '$1']
    },
    since: {
        key: 'internaldate',
        value: ['>=', '$1']
    },
    smaller: {
        key: 'size',
        value: ['<', '$1']
    },
    subject: {
        key: 'header',
        value: ['subject', '$1']
    },
    to: {
        key: 'header',
        value: ['to', '$1']
    },
    unanswered: {
        key: 'flag',
        value: ['\\Answered', false]
    },
    undeleted: {
        key: 'flag',
        value: ['\\Deleted', false]
    },
    undraft: {
        key: 'flag',
        value: ['\\Draft', false]
    },
    unflagged: {
        key: 'flag',
        value: ['\\Flagged', false]
    },
    unkeyword: {
        key: 'flag',
        value: ['$1', false]
    },
    unseen: {
        key: 'flag',
        value: ['\\Seen', false]
    }
};

/**
 * Checks if a sequence range string is valid or not
 *
 * @param {range} range Sequence range, eg "1,2,3:7"
 * @returns {Boolean} True if the string looks like a sequence range
 */
module.exports.validateSequnce = function (range) {
    return !!(range.length && /^(\d+|\*)(:\d+|:\*)?(,(\d+|\*)(:\d+|:\*)?)*$/.test(range));
};

module.exports.normalizeMailbox = function (mailbox, utf7Encoded) {
    if (!mailbox) {
        return '';
    }

    // trim slashes
    mailbox = mailbox.replace(/^\/|\/$/g, () => '');

    // Normalize case insensitive INBOX to always use uppercase
    let parts = mailbox.split('/');
    if (parts[0].toUpperCase() === 'INBOX') {
        parts[0] = 'INBOX';
    }

    if (utf7Encoded) {
        parts = parts.map(value => utf7decode(value));
    }

    mailbox = parts.join('/');

    return mailbox;
};

module.exports.generateFolderListing = function (folders, skipHierarchy) {
    let items = new Map();
    let parents = [];

    folders.forEach(folder => {
        let item;

        if (typeof folder === 'string') {
            folder = {
                path: folder
            };
        }

        if (!folder || typeof folder !== 'object') {
            return;
        }

        let path = module.exports.normalizeMailbox(folder.path);
        let parent, parentPath;
        if (!path) {
            return;
        }
        parent = path.split('/');
        parent.pop();

        while (parent.length) {
            parentPath = parent.join('/');
            if (parent && parents.indexOf(parentPath) < 0) {
                parents.push(parentPath);
            }
            parent.pop();
        }

        item = {
            // flags array is used to store permanentflags
            //flags: [].concat(folder.flags || []),

            flags: [],
            path
        };

        if (typeof folder.specialUse === 'string' && folder.specialUse) {
            item.specialUse = folder.specialUse;
        }

        items.set(path, item);
    });

    // ensure INBOX
    if (!items.has('INBOX')) {
        items.set('INBOX', {
            path: 'INBOX',
            flags: []
        });
    }

    // Adds \HasChildren flag for parent folders
    parents.forEach(path => {
        if (!items.has(path) && !skipHierarchy) {
            // add virtual hierarchy folders
            items.set(path, {
                flags: ['\\Noselect'],
                path
            });
        }
        let parent = items.get(path);

        if (parent && parent.flags.indexOf('\\HasChildren') < 0) {
            parent.flags.push('\\HasChildren');
        }
    });

    // converts cache Map to a response array
    let result = [];
    items.forEach(folder => {
        // Adds \HasNoChildren flag for leaf folders
        if (folder.flags.indexOf('\\HasChildren') < 0 && folder.flags.indexOf('\\HasNoChildren') < 0) {
            folder.flags.push('\\HasNoChildren');
        }
        result.push(folder);
    });

    // sorts folders
    result.sort((a, b) => {
        let aParts = a.path.split('/');
        let bParts = b.path.split('/');
        for (let i = 0; i < aParts.length; i++) {
            if (!bParts[i]) {
                return 1;
            }
            if (aParts[i] !== bParts[i]) {
                // prefer INBOX when sorting
                if (i === 0 && aParts[i] === 'INBOX') {
                    return -1;
                } else if (i === 0 && bParts[i] === 'INBOX') {
                    return 1;
                }
                return aParts[i].localeCompare(bParts[i]);
            }
        }
        return 0;
    });

    return result;
};

module.exports.filterFolders = function (folders, query) {
    query = query
        // remove excess * and %
        .replace(/\*\*+/g, '*')
        .replace(/%%+/g, '%')
        // escape special characters
        .replace(/([\\^$+?!.():=[\]|,-])/g, '\\$1')
        // setup *
        .replace(/[*]/g, '.*')
        // setup %
        .replace(/[%]/g, '[^/]*');

    let regex = new RegExp('^' + query + '$', '');

    return folders.filter(folder => !!regex.test(folder.path));
};

module.exports.getMessageRange = function (uidList, range, isUid) {
    range = (range || '').toString();

    let result = [];
    let rangeParts = range.split(',');
    let uid, i, len;
    let totalMessages = uidList.length;
    let maxUid = 0;

    let inRange = (nr, ranges, total) => {
        let range, from, to;
        for (let i = 0, len = ranges.length; i < len; i++) {
            range = ranges[i];
            to = range.split(':');
            from = to.shift();
            if (from === '*') {
                from = total;
            }
            from = Number(from) || 1;
            to = to.pop() || from;
            to = Number((to === '*' && total) || to) || from;

            if (nr >= Math.min(from, to) && nr <= Math.max(from, to)) {
                return true;
            }
        }
        return false;
    };

    for (i = 0, len = uidList.length; i < len; i++) {
        if (uidList[i] > maxUid) {
            maxUid = uidList[i];
        }
    }

    for (i = 0, len = uidList.length; i < len; i++) {
        uid = uidList[i] || 1;
        if (inRange(isUid ? uid : i + 1, rangeParts, isUid ? maxUid : totalMessages)) {
            result.push(uidList[i]);
        }
    }

    return result;
};

module.exports.packMessageRange = function (uidList) {
    if (!Array.isArray(uidList)) {
        uidList = [].concat(uidList || []);
    }

    if (!uidList.length) {
        return '';
    }

    uidList.sort((a, b) => a - b);

    let last = uidList[uidList.length - 1];
    let result = [[last]];
    for (let i = uidList.length - 2; i >= 0; i--) {
        if (uidList[i] === uidList[i + 1] - 1) {
            result[0].unshift(uidList[i]);
            continue;
        }
        result.unshift([uidList[i]]);
    }

    result = result.map(item => {
        if (item.length === 1) {
            return item[0];
        }
        return item.shift() + ':' + item.pop();
    });

    return result.join(',');
};

/**
 * Returns a date in GMT timezone
 *
 * @param {Date} date Date object to parse
 * @returns {String} Internaldate formatted date
 */
module.exports.formatInternalDate = function (date) {
    let day = date.getUTCDate(),
        month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][date.getUTCMonth()],
        year = date.getUTCFullYear(),
        hour = date.getUTCHours(),
        minute = date.getUTCMinutes(),
        second = date.getUTCSeconds(),
        tz = 0, //date.getTimezoneOffset(),
        tzHours = Math.abs(Math.floor(tz / 60)),
        tzMins = Math.abs(tz) - tzHours * 60;

    return (
        (day < 10 ? '0' : '') +
        day +
        '-' +
        month +
        '-' +
        year +
        ' ' +
        (hour < 10 ? '0' : '') +
        hour +
        ':' +
        (minute < 10 ? '0' : '') +
        minute +
        ':' +
        (second < 10 ? '0' : '') +
        second +
        ' ' +
        (tz > 0 ? '-' : '+') +
        (tzHours < 10 ? '0' : '') +
        tzHours +
        (tzMins < 10 ? '0' : '') +
        tzMins
    );
};

/**
 * Converts query data and message into an array of query responses.
 *
 * Message object must have the following properties:
 *
 *   * raw – string (binary) or buffer with the rfc822 contents of the message
 *   * uid – message UID
 *   * flags - an array with message flags
 *   * date - internaldate date object
 *
 * Additionally the message object *should* have the following  properties (if not present then generated automatically):
 *
 *   * mimeTree - message MIME tree object
 *   * envelope - message IMAP envelope object
 *   * bodystructure - message bodustructure object
 *   * bodystructureShort - bodyscructure for the BODY query
 *
 * @param {Array} query Query objects
 * @param {Object} message Message object
 * @param {Object} options Options for the indexer
 * @returns {Array} Resolved responses
 */
module.exports.getQueryResponse = function (query, message, options) {
    options = options || {};

    // for optimization purposes try to use cached mimeTree etc. if available
    // If these values are missing then generate these when first time required
    // So if the query is for (UID FLAGS) then mimeTree is never generated
    let mimeTree = message.mimeTree;
    let indexer = new Indexer(options);

    // generate response object
    let values = [];
    query.forEach(item => {
        let value = '';
        switch (item.item) {
            case 'uid':
                value = message.uid;
                break;

            case 'modseq':
                value = message.modseq;
                break;

            case 'flags':
                value = message.flags;
                break;

            case 'internaldate':
                if (!message.idate) {
                    message.idate = new Date();
                }
                value = message.idate;
                break;

            case 'bodystructure': {
                if (message.bodystructure) {
                    value = message.bodystructure;
                } else {
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getBodyStructure(mimeTree);
                }

                let walk = arr => {
                    arr.forEach((entry, i) => {
                        if (Array.isArray(entry)) {
                            return walk(entry);
                        }
                        if (!entry || typeof entry !== 'object') {
                            return;
                        }
                        let val = entry;
                        if (!Buffer.isBuffer(val) && val.buffer) {
                            val = val.buffer;
                        }
                        arr[i] = libmime.encodeWords(val.toString(), false, Infinity);
                    });
                };

                if (!options.acceptUTF8Enabled) {
                    walk(value);
                }

                break;
            }
            case 'envelope':
                if (message.envelope) {
                    value = message.envelope;
                    // cast invalidly stored In-Reply-To (8) and Message-ID (9) to strings
                    for (let index of [9, 10]) {
                        if (value[index] && Array.isArray(value[index])) {
                            value[index] = value[index].pop() || null;
                        }
                    }
                } else {
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getEnvelope(mimeTree);
                }
                if (!options.acceptUTF8Enabled) {
                    // encode unicode values

                    // subject
                    value[1] = libmime.encodeWords(value[1], false, Infinity);

                    for (let i = 2; i < 8; i++) {
                        if (value[i] && Array.isArray(value[i])) {
                            value[i].forEach(addr => {
                                if (addr[0] && typeof addr[0] === 'object') {
                                    // name
                                    let val = addr[0];
                                    if (!Buffer.isBuffer(val) && val.buffer) {
                                        val = val.buffer;
                                    }
                                    addr[0] = libmime.encodeWords(val.toString(), false, Infinity);
                                }

                                if (addr[2] && typeof addr[2] === 'object') {
                                    // username
                                    let val = addr[2];
                                    if (!Buffer.isBuffer(val) && val.buffer) {
                                        val = val.buffer;
                                    }
                                    addr[2] = libmime.encodeWords(val.toString(), false, Infinity);
                                }

                                if (addr[3] && typeof addr[3] === 'object') {
                                    // domain
                                    let val = addr[3];
                                    if (!Buffer.isBuffer(val) && val.buffer) {
                                        val = val.buffer;
                                    }
                                    try {
                                        addr[3] = punycode.toASCII(val.toString());
                                    } catch (E) {
                                        addr[3] = val.toString();
                                    }
                                }
                            });
                        }
                    }

                    // libmime.encodeWords(value, false, Infinity)
                }
                break;

            case 'rfc822':
                if (!mimeTree) {
                    mimeTree = indexer.parseMimeTree(message.raw);
                }
                value = indexer.getContents(mimeTree);
                break;

            case 'rfc822.size':
                if (message.size) {
                    value = message.size;
                } else {
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getSize(mimeTree);
                }
                break;

            case 'rfc822.header':
                // Equivalent to BODY[HEADER]
                if (!mimeTree) {
                    mimeTree = indexer.parseMimeTree(message.raw);
                }
                value = [].concat(mimeTree.header || []).join('\r\n') + '\r\n\r\n';
                break;

            case 'rfc822.text':
                // Equivalent to BODY[TEXT]
                if (!mimeTree) {
                    mimeTree = indexer.parseMimeTree(message.raw);
                }
                value = indexer.getContents(mimeTree, {
                    path: '',
                    type: 'text'
                });
                break;

            case 'body':
                if (!('type' in item)) {
                    // BODY
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getBody(mimeTree);
                } else if (item.path === '' && item.type === 'content') {
                    // BODY[]
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getContents(mimeTree, false, {
                        startFrom: item.partial && item.partial.startFrom,
                        maxLength: item.partial && item.partial.maxLength
                    });
                } else {
                    // BODY[SELECTOR]
                    if (!mimeTree) {
                        mimeTree = indexer.parseMimeTree(message.raw);
                    }
                    value = indexer.getContents(mimeTree, item, {
                        startFrom: item.partial && item.partial.startFrom,
                        maxLength: item.partial && item.partial.maxLength
                    });
                }

                if (item.partial) {
                    let len;

                    if (value && value.type === 'stream') {
                        value.startFrom = item.partial.startFrom;
                        value.maxLength = item.partial.maxLength;
                        len = value.expectedLength;
                    } else {
                        value = value.toString('binary').substr(item.partial.startFrom, item.partial.maxLength);
                        len = value.length;
                    }

                    // If start+length is larger than available value length, then do not return the length value
                    // Instead of BODY[]<10.20> return BODY[]<10> which means that the response is from offset 10 to the end
                    if (item.original.partial.length === 2 && item.partial.maxLength - item.partial.startFrom > len) {
                        item.original.partial.pop();
                    }
                }

                break;
        }
        values.push(value);
    });

    return values;
};

/**
 * Builds and emits an untagged CAPABILITY response depending on current state
 *
 * @param {Object} connection IMAP connection object
 */
module.exports.sendCapabilityResponse = connection => {
    let capabilities = [];

    if (!connection.secure) {
        if (!connection._server.options.disableSTARTTLS) {
            capabilities.push('STARTTLS');
            if (!connection._server.options.ignoreSTARTTLS) {
                capabilities.push('LOGINDISABLED');
            }
        }
    }

    if (connection.state === 'Not Authenticated') {
        capabilities.push('AUTH=PLAIN');
        capabilities.push('AUTH=PLAIN-CLIENTTOKEN');
        capabilities.push('SASL-IR');
        capabilities.push('ID');

        /*
        capabilities.push('ENABLE');
        capabilities.push('UNSELECT');
        capabilities.push('IDLE');
        capabilities.push('NAMESPACE');
        capabilities.push('QUOTA');
        capabilities.push('XLIST');
        capabilities.push('CHILDREN');
        */
    } else if (connection.state === 'Proxy') {
        capabilities = [];
    } else {
        capabilities.push('ID');
        capabilities.push('UNSELECT');
        capabilities.push('IDLE');
        capabilities.push('NAMESPACE');
        capabilities.push('QUOTA');
        capabilities.push('XLIST');
        capabilities.push('CHILDREN');

        capabilities.push('SPECIAL-USE');
        capabilities.push('UIDPLUS');
        capabilities.push('ENABLE');
        capabilities.push('CONDSTORE');
        capabilities.push('UTF8=ACCEPT');

        capabilities.push('MOVE');

        if (connection._server.options.enableCompression) {
            capabilities.push('COMPRESS=DEFLATE');
        }

        if (connection._server.options.maxMessage) {
            capabilities.push('APPENDLIMIT=' + connection._server.options.maxMessage);
        }
    }

    capabilities.sort((a, b) => a.localeCompare(b));

    connection.send('* CAPABILITY ' + ['IMAP4rev1'].concat(capabilities).join(' '));
};

module.exports.validateInternalDate = internaldate => {
    if (!internaldate || typeof internaldate !== 'string') {
        return false;
    }
    return /^([ \d]?\d)-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([-+])(\d{2})(\d{2})$/i.test(internaldate);
};

module.exports.validateSearchDate = internaldate => {
    if (!internaldate || typeof internaldate !== 'string') {
        return false;
    }
    return /^\d{1,2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{4}$/i.test(internaldate);
};
