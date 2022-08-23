'use strict';

const imapTools = require('../imap-tools');

// tag DELETE "mailbox"

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
        path = imapTools.normalizeMailbox(path, !this.acceptUTF8Enabled);

        // Check if DELETE method is set
        if (typeof this._server.onDelete !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'DELETE not implemented'
            });
        }

        if (!path) {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'No folder name given'
            });
        }

        if (path === 'INBOX') {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'INBOX can not be deleted'
            });
        }

        let logdata = {
            short_message: '[DELETE]',
            _mail_action: 'create',
            _path: path,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        this._server.onDelete(path, this.session, (err, success, mailbox) => {
            if (err) {
                logdata._error = err.message;
                logdata._code = err.code;
                logdata._response = err.response;
                this._server.loggelf(logdata);
                // do not return actual error to user
                return callback(null, {
                    response: 'NO',
                    code: 'TEMPFAIL'
                });
            }

            logdata._rmailbox = mailbox && mailbox.toString();
            logdata._response = success;
            this._server.loggelf(logdata);

            if (success !== true) {
                return callback(null, {
                    response: 'NO',
                    code: typeof success === 'string' ? success.toUpperCase() : false
                });
            }

            callback(null, {
                response: 'OK'
            });
        });
    }
};
