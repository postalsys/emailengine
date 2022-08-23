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
            name: 'extensions',
            type: 'array',
            optional: true
        },
        {
            name: 'action',
            type: 'string'
        },
        {
            name: 'flags',
            type: 'array'
        }
    ],

    handler(command, callback) {
        // Check if STORE method is set
        if (typeof this._server.onStore !== 'function') {
            return callback(null, {
                response: 'NO',
                message: 'STORE not implemented'
            });
        }

        let type = 'flags'; // currently hard coded, in the future might support other values as well, eg. X-GM-LABELS
        let range = (command.attributes[0] && command.attributes[0].value) || '';

        // if arguments include extenstions at index 1, then length is 4, otherwise 3
        let pos = command.attributes.length === 4 ? 1 : 0;

        let action = ((command.attributes[pos + 1] && command.attributes[pos + 1].value) || '').toString().toUpperCase();

        let flags = [].concat(command.attributes[pos + 2] || []).map(flag => ((flag && flag.value) || '').toString());

        let unchangedSince = 0;
        let silent = false;

        // extensions are available as the optional argument at index 1
        let extensions = !pos ? [] : [].concat(command.attributes[pos] || []).map(val => val && val.value);

        if (extensions.length) {
            if (extensions.length !== 2 || (extensions[0] || '').toString().toUpperCase() !== 'UNCHANGEDSINCE' || isNaN(extensions[1])) {
                return callback(new Error('Invalid modifier for STORE'));
            }
            unchangedSince = Number(extensions[1]);
            if (unchangedSince && !this.selected.condstoreEnabled) {
                this.condstoreEnabled = this.selected.condstoreEnabled = true;
            }
        }

        if (action.substr(-7) === '.SILENT') {
            action = action.substr(0, action.length - 7);
            silent = true;
        }

        if (!imapTools.validateSequnce(range)) {
            return callback(new Error('Invalid sequence set for UID STORE'));
        }

        if (!/^[-+]?FLAGS$/.test(action)) {
            return callback(new Error('Invalid message data item name for UID STORE'));
        }

        switch (action.charAt(0)) {
            case '+':
                action = 'add';
                break;
            case '-':
                action = 'remove';
                break;
            default:
                action = 'set';
        }

        for (let i = flags.length - 1; i >= 0; i--) {
            if (flags[i].charAt(0) === '\\') {
                if (imapTools.systemFlags.indexOf(flags[i].toLowerCase()) < 0) {
                    return callback(new Error('Invalid system flag argument for UID STORE'));
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

        let messages = imapTools.getMessageRange(this.selected.uidList, range, true);

        let logdata = {
            short_message: '[UID STORE]',
            _mail_action: 'store',
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox,
            _sess: this.id,
            _message_count: messages.lentgh,
            _flags: flags.join(', '),
            _store_action: action,
            _silent: silent ? 'yes' : '',
            _modseq: unchangedSince
        };

        this._server.onStore(
            this.selected.mailbox,
            {
                isUid: true,
                value: flags,
                action,
                type,
                silent,
                messages,
                unchangedSince
            },
            this.session,
            (err, success, modified) => {
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

                let message = success === true ? 'UID STORE completed' : false;
                if (modified && modified.length) {
                    logdata._modified = modified.length;
                    message = 'Conditional UID STORE failed';
                } else if (message && unchangedSince) {
                    message = 'Conditional UID STORE completed';
                }

                logdata._response = success;
                logdata._message = message;
                this._server.loggelf(logdata);

                callback(null, {
                    response: success === true ? 'OK' : 'NO',
                    code:
                        typeof success === 'string'
                            ? success.toUpperCase()
                            : modified && modified.length
                                ? 'MODIFIED ' + imapTools.packMessageRange(modified)
                                : false,
                    message
                });
            }
        );
    }
};
