'use strict';

const imapHandler = require('../handler/imap-handler');
const { normalizeMailbox, utf7encode } = require('../imap-tools');

// tag GETQUOTAROOT "mailbox"

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'path',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let path = Buffer.from((command.attributes[0] && command.attributes[0].value) || '', 'binary').toString();
        path = normalizeMailbox(path, !this.acceptUTF8Enabled);

        if (typeof this._server.onGetQuota !== 'function') {
            return callback(null, {
                response: 'NO',
                message: command.command + ' not implemented'
            });
        }

        if (!path) {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'NONEXISTENT'
            });
        }

        let logdata = {
            short_message: '[GETQUOTAROOT]',
            _mail_action: 'getquotaroot',
            _path: path,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        this._server.onGetQuotaRoot(path, this.session, (err, data) => {
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

            if (typeof data === 'string') {
                return callback(null, {
                    response: 'NO',
                    code: data.toUpperCase()
                });
            }

            if (!this.acceptUTF8Enabled) {
                path = utf7encode(path);
            } else {
                path = Buffer.from(path);
            }

            // * QUOTAROOT INBOX ""
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'QUOTAROOT',
                    attributes: [path, data.root || '']
                })
            );

            // * QUOTA "" (STORAGE 220676 15728640)
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'QUOTA',
                    attributes: [
                        data.root || '',
                        [
                            {
                                type: 'atom',
                                value: 'STORAGE'
                            },
                            {
                                type: 'atom',
                                value: String(Math.ceil((Number(data.storageUsed) || 0) / 1024))
                            },
                            {
                                type: 'atom',
                                value: String(Math.ceil((Number(data.quota) || 0) / 1024))
                            }
                        ]
                    ]
                })
            );

            callback(null, {
                response: 'OK',
                message: 'Success'
            });
        });
    }
};
