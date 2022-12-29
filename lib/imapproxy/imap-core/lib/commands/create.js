'use strict';

const { normalizeMailbox, utf7decode } = require('../imap-tools');

// tag CREATE "mailbox"

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

        if (!this.acceptUTF8Enabled) {
            // decode before normalizing to uncover stuff like ending / etc.
            path = utf7decode(path);
        }

        // Check if CREATE method is set
        if (typeof this._server.onCreate !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'CREATE not implemented'
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

        // ignore commands that try to create hierarchy
        if (/\/$/.test(path)) {
            return callback(null, {
                response: 'OK',
                code: 'CANNOT',
                message: 'Ignoring hierarchy declaration'
            });
        }

        // ignore commands with adjacent spaces
        if (/\/{2,}/.test(path)) {
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'Adjacent hierarchy separators are not supported'
            });
        }

        path = normalizeMailbox(path);

        let logdata = {
            short_message: '[CREATE]',
            _mail_action: 'create',
            _path: path,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        this._server.onCreate(path, this.session, (err, success, mailbox) => {
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

            callback(null, {
                response: success === true ? 'OK' : 'NO',
                code: typeof success === 'string' ? success.toUpperCase() : false
            });
        });
    }
};
