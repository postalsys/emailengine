'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: 'Selected',

    schema: [
        {
            name: 'range',
            type: 'sequence'
        },
        {
            name: 'path',
            type: 'string'
        }
    ],

    handler(command, callback) {
        let cmd = (command.command || '').toString().toUpperCase();

        // Check if MOVE method is set
        if (typeof this._server.onMove !== 'function') {
            return callback(null, {
                response: 'NO',
                message: cmd + ' not implemented'
            });
        }

        let range = (command.attributes[0] && command.attributes[0].value) || '';
        let path = Buffer.from((command.attributes[1] && command.attributes[1].value) || '', 'binary').toString();
        path = imapTools.normalizeMailbox(path, !this.acceptUTF8Enabled);

        if (!path) {
            return callback(new Error('Invalid mailbox argument for ' + cmd));
        }

        if (!imapTools.validateSequnce(range)) {
            return callback(new Error('Invalid sequence set for ' + cmd));
        }

        let messages = imapTools.getMessageRange(this.selected.uidList, range, cmd === 'UID MOVE');

        let logdata = {
            short_message: '[MOVE]',
            _mail_action: 'move',
            _destination: path,
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox,
            _sess: this.id,
            _message_count: messages.lentgh
        };

        this._server.onMove(
            this.selected.mailbox,
            {
                destination: path,
                messages
            },
            this.session,
            (err, success, info) => {
                Object.keys(info || {}).forEach(key => {
                    let vkey = '_' + key.replace(/[A-Z]+/g, c => '_' + c.toLowerCase());
                    if (vkey === '_id') {
                        vkey = '_copy_id';
                    }

                    let value = info[key];
                    if (['sourceUid', 'destinationUid'].includes(key)) {
                        value = imapTools.packMessageRange(value);
                    }
                    logdata[vkey] = value;
                });

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

                logdata._response = success;
                this._server.loggelf(logdata);

                let code =
                    typeof success === 'string'
                        ? success.toUpperCase()
                        : 'COPYUID ' +
                          info.uidValidity +
                          ' ' +
                          imapTools.packMessageRange(info.sourceUid) +
                          ' ' +
                          imapTools.packMessageRange(info.destinationUid);

                callback(null, {
                    response: success === true ? 'OK' : 'NO',
                    code
                });
            }
        );
    }
};
