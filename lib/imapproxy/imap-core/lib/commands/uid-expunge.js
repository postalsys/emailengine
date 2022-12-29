'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: 'Selected',

    schema: [
        {
            name: 'range',
            type: 'sequence'
        }
    ],

    handler(command, callback) {
        // Check if EXPUNGE method is set
        if (typeof this._server.onExpunge !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'EXPUNGE not implemented'
            });
        }

        // Do nothing if in read only mode
        if (this.selected.readOnly) {
            return callback(null, {
                response: 'OK'
            });
        }

        let range = (command.attributes[0] && command.attributes[0].value) || '';
        if (!imapTools.validateSequnce(range)) {
            return callback(new Error('Invalid sequence set for UID EXPUNGE'));
        }
        let messages = imapTools.getMessageRange(this.selected.uidList, range, true);

        let logdata = {
            short_message: '[UID EXPUNGE]',
            _mail_action: 'uid expunge',
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox,
            _sess: this.id
        };

        this._server.onExpunge(
            this.selected.mailbox,
            {
                isUid: true,
                messages
            },
            this.session,
            (err, success) => {
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
            }
        );
    }
};
