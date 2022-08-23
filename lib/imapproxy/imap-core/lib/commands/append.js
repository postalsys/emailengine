'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: ['Authenticated', 'Selected'],

    // we do not show * EXIST response for added message, so keep other notifications quet as well
    // otherwise we might end up in situation where APPEND emits an unrelated * EXISTS response
    // which does not yet take into account the appended message
    disableNotifications: true,

    schema: [
        {
            name: 'path',
            type: 'string'
        },
        {
            name: 'flags',
            type: 'array',
            optional: true
        },
        {
            name: 'datetime',
            type: 'string',
            optional: true
        },
        {
            name: 'utf8',
            type: 'atom',
            optional: true
        },
        {
            name: 'message',
            type: 'literal'
        }
    ],

    handler(command, callback) {
        // Check if APPEND method is set
        if (typeof this._server.onAppend !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'APPEND not implemented'
            });
        }

        let path = (command.attributes.shift() || {}).value;
        if (!Buffer.isBuffer(path)) {
            path = path.toString();
        } else {
            path = Buffer.from(path, 'binary').toString();
        }

        path = imapTools.normalizeMailbox(path, !this.acceptUTF8Enabled);
        let message = command.attributes.pop();

        if (Array.isArray(message) && message.length === 1 && command.attributes.length) {
            let lastOpt = command.attributes[command.attributes.length - 1];
            if (lastOpt.type === 'ATOM' && /^UTF8$/i.test(lastOpt.value)) {
                message = message.shift();
                // remove the UTF8 marker
                command.attributes.pop();
            }
        }

        let flags = [];
        let internaldate = false;
        let parsedDate;

        if (command.attributes.length === 2 && Array.isArray(command.attributes[0])) {
            flags = command.attributes[0] || [];
            internaldate = (command.attributes[1] && command.attributes[1].value) || '';
        } else if (command.attributes.length === 1) {
            if (Array.isArray(command.attributes[0])) {
                flags = command.attributes[0];
            } else {
                internaldate = (command.attributes[0] && command.attributes[0].value) || '';
            }
        }

        flags = flags.map(flag => (flag.value || '').toString());

        if (!path) {
            return callback(new Error('Invalid mailbox argument for APPEND'));
        }

        if (!/^literal$/i.test(message.type)) {
            return callback(new Error('Invalid message argument for APPEND'));
        }

        if (internaldate) {
            internaldate = internaldate.toString(); // might be Buffer

            if (!imapTools.validateInternalDate(internaldate)) {
                return callback(new Error('Invalid date argument for APPEND'));
            }

            parsedDate = new Date(internaldate);
            if (parsedDate.toString() === 'Invalid Date' || parsedDate.getTime() > Date.now() + 24 * 3600 * 1000 || parsedDate.getTime() <= 1000) {
                return callback(new Error('Invalid date-time argument for APPEND'));
            }
        }

        for (let i = flags.length - 1; i >= 0; i--) {
            if (flags[i].charAt(0) === '\\') {
                if (imapTools.systemFlags.indexOf(flags[i].toLowerCase()) < 0) {
                    return callback(new Error('Invalid system flag argument for APPEND'));
                } else {
                    // fix flag case
                    flags[i] = flags[i].toLowerCase().replace(/^\\./, c => c.toUpperCase());
                }
            }
        }

        // keep only unique flags
        flags = flags.filter((flag, i) => {
            if (i && flags.slice(0, i).indexOf(flag) >= 0) {
                return false;
            }
            return true;
        });

        let raw;
        if (Buffer.isBuffer(message.value)) {
            raw = message.value;
        } else {
            raw = Buffer.from(typeof message.value === 'string' ? message.value : (message.value || '').toString(), 'binary');
        }

        let logdata = {
            short_message: '[APPEND]',
            _mail_action: 'append',
            _path: path,
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox,
            _sess: this.id,
            _flags: flags.join(', '),
            _internaldate: internaldate,
            _size: raw.length
        };

        this._server.onAppend(path, flags, internaldate, raw, this.session, (err, success, info) => {
            Object.keys(info || {}).forEach(key => {
                let vkey = '_' + key.replace(/[A-Z]+/g, c => '_' + c.toLowerCase());
                if (['_id', '_status'].includes(vkey)) {
                    vkey = '_append' + vkey;
                }
                logdata[vkey] = info[key];
            });

            if (err) {
                logdata._error = err.message;
                logdata._code = err.code;
                logdata._response = err.response;
                logdata._responseMessage = err.responseMessage;
                logdata._ratelimit_ttl = err.ttl;
                this._server.loggelf(logdata);

                if (err.code === 10334) {
                    // 10334 is Mongodb BSONObjectTooLarge
                    return callback(null, {
                        response: 'NO',
                        message: 'Message text too large'
                    });
                }

                // do not return actual error to user
                return callback(null, {
                    response: 'NO',
                    code: 'TEMPFAIL',
                    message: err.responseMessage
                });
            }

            let code = typeof success === 'string' ? success.toUpperCase() : 'APPENDUID ' + info.uidValidity + ' ' + info.uid;

            logdata._response = success;
            this._server.loggelf(logdata);

            callback(null, {
                response: success === true ? 'OK' : 'NO',
                code
            });
        });
    }
};
