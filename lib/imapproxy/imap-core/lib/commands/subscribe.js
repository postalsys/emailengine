'use strict';

const imapTools = require('../imap-tools');

// tag SUBSCRIBE "mailbox"

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

        // Check if SUBSCRIBE method is set
        if (typeof this._server.onSubscribe !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'SUBSCRIBE not implemented'
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
                response: 'OK'
            });
        }

        let logdata = {
            short_message: '[SUBSCRIBE]',
            _mail_action: 'subscribe',
            _user: this.session.user.id.toString(),
            _path: path,
            _sess: this.id
        };

        this._server.onSubscribe(path, this.session, (err, success) => {
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
