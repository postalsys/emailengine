'use strict';

const imapTools = require('../imap-tools');

// tag RENAME "mailbox"

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'path',
            type: 'string'
        },
        {
            name: 'newname',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let path = Buffer.from((command.attributes[0] && command.attributes[0].value) || '', 'binary').toString();
        let newname = Buffer.from((command.attributes[1] && command.attributes[1].value) || '', 'binary').toString();

        // Check if RENAME method is set
        if (typeof this._server.onRename !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'RENAME not implemented'
            });
        }

        if (!path || !newname) {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'No folder name given'
            });
        }

        path = imapTools.normalizeMailbox(path, !this.acceptUTF8Enabled);
        newname = imapTools.normalizeMailbox(newname, !this.acceptUTF8Enabled);

        // ignore commands with adjacent separators
        if (/\/{2,}/.test(newname)) {
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'Adjacent hierarchy separators are not supported'
            });
        }

        // Renaming INBOX is permitted by RFC3501 but not by this implementation
        if (path === 'INBOX') {
            return callback(null, {
                response: 'NO',
                code: 'CANNOT',
                message: 'INBOX can not be renamed'
            });
        }

        if (newname === 'INBOX') {
            return callback(null, {
                response: 'NO',
                code: 'ALREADYEXISTS',
                message: 'INBOX already exists'
            });
        }

        let logdata = {
            short_message: '[RENAME]',
            _mail_action: 'create',
            _path: path,
            _destination: newname,
            _user: this.session.user.id.toString(),
            _sess: this.id
        };

        this._server.onRename(path, newname, this.session, (err, success, mailbox) => {
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
