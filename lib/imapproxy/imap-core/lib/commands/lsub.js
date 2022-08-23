'use strict';

const imapHandler = require('../handler/imap-handler');
const { normalizeMailbox, utf7encode, filterFolders, generateFolderListing } = require('../imap-tools');

// tag LSUB "" "%"

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'reference',
            type: 'string'
        },
        {
            name: 'path',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let reference = Buffer.from((command.attributes[0] && command.attributes[0].value) || '', 'binary').toString();
        let path = Buffer.from((command.attributes[1] && command.attributes[1].value) || '', 'binary').toString();

        // Check if LIST method is set
        if (typeof this._server.onLsub !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'LSUB not implemented'
            });
        }

        let query = normalizeMailbox(reference + path, !this.acceptUTF8Enabled);

        let logdata = {
            short_message: '[LSUB]',
            _mail_action: 'lsub',
            _query: query,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        let lsubResponse = (err, list) => {
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

            filterFolders(generateFolderListing(list, true), query).forEach(folder => {
                if (!folder) {
                    return;
                }

                let path = folder.path;
                if (!this.acceptUTF8Enabled) {
                    path = utf7encode(path);
                } else {
                    path = Buffer.from(path);
                }

                let response = {
                    tag: '*',
                    command: 'LSUB',
                    attributes: [
                        [].concat(folder.flags || []).map(flag => ({
                            type: 'atom',
                            value: flag
                        })),
                        '/',
                        path
                    ]
                };

                this.send(imapHandler.compiler(response));
            });

            callback(null, {
                response: 'OK'
            });
        };

        if (!path) {
            // return delimiter only
            return lsubResponse(null, {
                path: '/',
                flags: '\\Noselect'
            });
        }

        // Do folder listing
        // Concat reference and mailbox. No special reference handling whatsoever
        this._server.onLsub(normalizeMailbox(reference + path), this.session, lsubResponse);
    }
};
