'use strict';

const imapTools = require('../imap-tools');

// tag UNSUBSCRIBE "mailbox"

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'path',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let path = imapTools.normalizeMailbox((command.attributes[0] && command.attributes[0].value) || '', !this.acceptUTF8Enabled);

        // Check if UNSUBSCRIBE method is set
        if (typeof this._server.onUnsubscribe !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'UNSUBSCRIBE not implemented'
            });
        }

        if (!path) {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'NONEXISTENT'
            });
        }

        if (path === 'INBOX') {
            return callback(null, {
                response: 'NO',
                message: 'Can not unsubscribe from INBOX'
            });
        }

        let logdata = {
            short_message: '[UNSUBSCRIBE]',
            _mail_action: 'unsubscribe',
            _user: this.session.user.id.toString(),
            _path: path,
            _sess: this.id
        };

        this._server.onUnsubscribe(path, this.session, (err, success) => {
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

            callback(null, {
                response: success === true ? 'OK' : 'NO',
                code: typeof success === 'string' ? success.toUpperCase() : false
            });
        });
    }
};
