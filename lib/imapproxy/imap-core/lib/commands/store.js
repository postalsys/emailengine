'use strict';

const imapTools = require('../imap-tools');

module.exports = {
    state: 'Selected',
    disableNotifications: true,

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

        // Do nothing if in read only mode
        if (this.selected.readOnly) {
            return callback(null, {
                response: 'OK',
                message: 'STORE ignored with read-only mailbox'
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
            return callback(new Error('Invalid sequence set for STORE'));
        }

        if (!/^[-+]?FLAGS$/.test(action)) {
            return callback(new Error('Invalid message data item name for STORE'));
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
                if (!imapTools.systemFlags.includes(flags[i].toLowerCase())) {
                    return callback(new Error('Invalid system flag argument for STORE'));
                } else {
                    // fix flag case
                    flags[i] = flags[i].toLowerCase().replace(/^\\./, c => c.toUpperCase());
                }
            }
            if (flags[i].length > 255) {
                return callback(new Error('Too long value for a flag'));
            }
        }

        // keep only unique flags
        flags = flags.filter((flag, i) => {
            if (i && flags.slice(0, i).indexOf(flag) >= 0) {
                return false;
            }
            return true;
        });

        let messages = imapTools.getMessageRange(this.selected.uidList, range, false);

        let logdata = {
            short_message: '[STORE]',
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

                // STORE returns MODIFIED as sequence numbers, so convert UIDs to sequence list
                if (modified && modified.length) {
                    logdata._modified = modified.length;
                    modified = modified
                        .map(uid => this.selected.uidList.indexOf(uid) + 1)
                        .filter(
                            seq =>
                                // ensure that deleted items (eg seq=0) do not end up in the list
                                seq > 0
                        );
                }

                let message = success === true ? 'STORE completed' : false;
                if (modified && modified.length) {
                    message = 'Conditional STORE failed';
                } else if (message && unchangedSince) {
                    message = 'Conditional STORE completed';
                }

                logdata._response = success;
                logdata._message = message;
                this._server.loggelf(logdata);

                let response = {
                    response: success === true ? 'OK' : 'NO',
                    code:
                        typeof success === 'string'
                            ? success.toUpperCase()
                            : modified && modified.length
                            ? 'MODIFIED ' + imapTools.packMessageRange(modified)
                            : false,
                    message
                };

                // check if only messages that exist are referenced
                if (!this._server.options.allowStoreExpunged && success === true && !silent && messages.length) {
                    for (let i = this.selected.notifications.length - 1; i >= 0; i--) {
                        if (this.selected.notifications[i].command === 'EXPUNGE' && messages.includes(this.selected.notifications[i].uid)) {
                            let err = new Error('Some of the messages no longer exist');
                            response = {
                                response: 'NO',
                                message: err.message
                            };
                            break;
                        }
                    }
                }

                callback(null, response);
            }
        );
    }
};
