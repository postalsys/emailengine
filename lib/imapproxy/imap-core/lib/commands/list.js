'use strict';

const imapHandler = require('../handler/imap-handler');
const { normalizeMailbox, utf7encode, filterFolders, generateFolderListing } = require('../imap-tools');

// tag LIST (SPECIAL-USE) "" "%" RETURN (SPECIAL-USE)

//"\\Sent", "\\Trash", "\\Junk", "\\Drafts", "\\Archive"
const XlistTags = new Map([
    ['INBOX', '\\Inbox'],
    ['\\Sent', '\\Sent'],
    ['\\Trash', '\\Trash'],
    ['\\Junk', '\\Spam'],
    ['\\Drafts', '\\Drafts'],
    ['\\Flagged', '\\Starred']
]);

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'selection',
            type: ['array'],
            optional: true
        },
        {
            name: 'reference',
            type: 'string'
        },
        {
            name: 'path',
            type: 'string'
        },
        {
            name: 'return',
            type: 'atom',
            optional: true
        },
        {
            name: 'return',
            type: 'array',
            optional: true
        }
    ],

    handler(command, callback) {
        let filterSpecialUseFolders = false;
        let filterSpecialUseFlags = false;
        let reference;
        let path;

        let arrPos = 0;

        let commandName = (command.command || '').toString().toUpperCase();
        let isXlist = commandName === 'XLIST' ? true : false;

        // (SPECIAL-USE)
        if (Array.isArray(command.attributes[0])) {
            if (command.attributes[0].length) {
                if (
                    command.attributes[0].length === 1 &&
                    command.attributes[0][0].type === 'ATOM' &&
                    command.attributes[0][0].value.toUpperCase() === 'SPECIAL-USE'
                ) {
                    filterSpecialUseFolders = true;
                } else {
                    return callback(new Error('Invalid argument provided for ' + commandName));
                }
            }
            arrPos++;
        }

        // ""
        reference = Buffer.from((command.attributes[arrPos] && command.attributes[arrPos].value) || '', 'binary').toString();
        arrPos++;

        // "%"
        path = Buffer.from((command.attributes[arrPos] && command.attributes[arrPos].value) || '', 'binary').toString();
        arrPos++;

        // RETURN (SPECIAL-USE)
        if (arrPos < command.attributes.length) {
            if (command.attributes[arrPos].type === 'ATOM' && command.attributes[arrPos].value.toUpperCase() === 'RETURN') {
                arrPos++;
                if (
                    Array.isArray(command.attributes[arrPos]) &&
                    command.attributes[arrPos].length === 1 &&
                    command.attributes[arrPos][0].type === 'ATOM' &&
                    command.attributes[arrPos][0].value.toUpperCase() === 'SPECIAL-USE'
                ) {
                    filterSpecialUseFlags = true;
                } else {
                    return callback(new Error('Invalid argument provided for ' + commandName));
                }
            } else {
                return callback(new Error('Invalid argument provided for ' + commandName));
            }
        }

        // Check if LIST method is set
        if (typeof this._server.onList !== 'function') {
            return callback(null, {
                response: 'NO',
                message: commandName + ' not implemented'
            });
        }

        let query = normalizeMailbox(reference + path, !this.acceptUTF8Enabled);

        let logdata = {
            short_message: '[LIST]',
            _mail_action: 'list',
            _query: query,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        let listResponse = (err, list) => {
            if (err) {
                logdata._error = err.message;
                logdata._code = err.code;
                logdata._response = err.response;
                this._server.loggelf(logdata);

                return callback(null, {
                    response: 'NO',
                    code: 'TEMPFAIL'
                });
            }

            filterFolders(generateFolderListing(list), query).forEach(folder => {
                if (!folder) {
                    return;
                }

                if (filterSpecialUseFolders && !folder.specialUse) {
                    return;
                }

                let response = {
                    tag: '*',
                    command: commandName,
                    attributes: []
                };

                let flags = [];

                if (!filterSpecialUseFlags) {
                    flags = flags.concat(folder.flags || []);
                }

                let specialUseFlag = folder.specialUse;
                if (specialUseFlag) {
                    if (isXlist && XlistTags.has(specialUseFlag)) {
                        // rewite flag to XLIST tag which is a bit different
                        specialUseFlag = XlistTags.get(specialUseFlag);
                    }
                    flags.push(specialUseFlag);
                }

                let path = folder.path;
                if (!this.acceptUTF8Enabled) {
                    path = utf7encode(path);
                } else {
                    path = Buffer.from(path);
                }

                if (isXlist && path === 'INBOX') {
                    path = 'Inbox';
                    flags.push(XlistTags.get('INBOX'));
                }

                response.attributes.push(
                    flags.map(flag => ({
                        type: 'atom',
                        value: flag
                    }))
                );

                response.attributes.push('/');
                response.attributes.push(path);

                this.send(imapHandler.compiler(response));
            });

            callback(null, {
                response: 'OK'
            });
        };

        if (!path && !filterSpecialUseFlags) {
            // return delimiter only
            let response = {
                tag: '*',
                command: commandName,
                attributes: [
                    [
                        {
                            type: 'atom',
                            value: '\\Noselect'
                        }
                    ],
                    '/',
                    '/'
                ]
            };
            this.send(imapHandler.compiler(response));
            return callback(null, {
                response: 'OK'
            });
        }

        // Do folder listing
        // Concat reference and mailbox. No special reference handling whatsoever
        this._server.onList(query, this.session, listResponse);
    }
};
