'use strict';

const imapHandler = require('../handler/imap-handler');
const imapTools = require('../imap-tools');

// tag SELECT "mailbox"
// tag EXAMINE "mailbox"

module.exports = {
    state: ['Authenticated', 'Selected'],

    schema: [
        {
            name: 'mailbox',
            type: 'string'
        },
        {
            name: 'extensions',
            type: 'array',
            optional: true
        }
    ],

    handler(command, callback) {
        let path = Buffer.from((command.attributes[0] && command.attributes[0].value) || '', 'binary').toString();
        path = imapTools.normalizeMailbox(path, !this.acceptUTF8Enabled);

        let extensions = [].concat(command.attributes[1] || []).map(attr => ((attr && attr.value) || '').toString().toUpperCase());

        // Is CONDSTORE found from the optional arguments list?
        if (extensions.indexOf('CONDSTORE') >= 0) {
            this.condstoreEnabled = true;
        }

        if (typeof this._server.onOpen !== 'function') {
            return callback(null, {
                response: 'NO',
                message: command.command + ' not implemented'
            });
        }

        if (!path) {
            // nothing to check for if mailbox is not defined
            return callback(null, {
                response: 'NO',
                code: 'NONEXISTENT'
            });
        }

        if (this.session.commandCounters[command.command.toUpperCase().trim()] > 1000) {
            this.session.selected = this.selected = false;
            this.state = 'Logout';

            this.clearNotificationListener();
            this.send(`* BYE Too many ${command.command.toUpperCase().trim()} commands issued, please reconnect`);
            return setImmediate(() => this.close());
        }

        let logdata = {
            short_message: '[' + (command.command || '').toString().toUpperCase() + ']',
            _mail_action: (command.command || '').toString().toLowerCase(),
            _user: this.session.user.id.toString(),
            _path: path,
            _sess: this.id
        };

        this._server.onOpen(path, this.session, (err, mailboxData) => {
            if (err) {
                this.session.selected = this.selected = false;
                this.state = 'Authenticated';

                logdata._error = err.message;
                logdata._code = err.code;
                logdata._response = err.response;
                this._server.loggelf(logdata);
                return callback(null, {
                    response: 'NO',
                    code: 'TEMPFAIL'
                });
            }

            if (!mailboxData || typeof mailboxData === 'string') {
                this.session.selected = this.selected = false;
                this.state = 'Authenticated';
                return callback(null, {
                    response: 'NO',
                    code: typeof mailboxData === 'string' ? mailboxData : 'NONEXISTENT'
                });
            }

            // Set current state as selected
            this.session.selected = this.selected = {
                modifyIndex: mailboxData.modifyIndex,
                uidList: mailboxData.uidList,
                notifications: [],
                condstoreEnabled: this.condstoreEnabled,
                readOnly: (command.command || '').toString().toUpperCase() === 'EXAMINE' ? true : false,
                mailbox: mailboxData._id,
                path
            };
            this.state = 'Selected';

            let flagList = imapTools.systemFlagsFormatted.concat(mailboxData.flags || []);

            // * FLAGS (\Answered \Flagged \Draft \Deleted \Seen)
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'FLAGS',
                    attributes: [
                        flagList.map(flag => ({
                            type: 'atom',
                            value: flag
                        }))
                    ]
                })
            );

            // * OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen \*)] Flags permitted
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'OK',
                    attributes: [
                        {
                            type: 'section',
                            section: [
                                // unrelated comment to enforce eslint-happy indentation
                                {
                                    type: 'atom',
                                    value: 'PERMANENTFLAGS'
                                },
                                flagList
                                    .map(flag => ({
                                        type: 'atom',
                                        value: flag
                                    }))
                                    .concat({
                                        type: 'text',
                                        value: '\\*'
                                    })
                            ]
                        },
                        {
                            type: 'text',
                            value: 'Flags permitted'
                        }
                    ]
                })
            );

            // * OK [UIDVALIDITY 123] UIDs valid
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'OK',
                    attributes: [
                        {
                            type: 'section',
                            section: [
                                {
                                    type: 'atom',
                                    value: 'UIDVALIDITY'
                                },
                                {
                                    type: 'atom',
                                    value: String(Number(mailboxData.uidValidity) || 1)
                                }
                            ]
                        },
                        {
                            type: 'text',
                            value: 'UIDs valid'
                        }
                    ]
                })
            );

            // * 0 EXISTS
            this.send('* ' + mailboxData.uidList.length + ' EXISTS');

            // * 0 RECENT
            this.send('* 0 RECENT');

            // * OK [HIGHESTMODSEQ 123]
            if ('modifyIndex' in mailboxData && Number(mailboxData.modifyIndex)) {
                this.send(
                    imapHandler.compiler({
                        tag: '*',
                        command: 'OK',
                        attributes: [
                            {
                                type: 'section',
                                section: [
                                    {
                                        type: 'atom',
                                        value: 'HIGHESTMODSEQ'
                                    },
                                    {
                                        type: 'atom',
                                        value: String(Number(mailboxData.modifyIndex) || 0)
                                    }
                                ]
                            },
                            {
                                type: 'text',
                                value: 'Highest'
                            }
                        ]
                    })
                );
            }

            // * OK [UIDNEXT 1] Predicted next UID
            this.send(
                imapHandler.compiler({
                    tag: '*',
                    command: 'OK',
                    attributes: [
                        {
                            type: 'section',
                            section: [
                                {
                                    type: 'atom',
                                    value: 'UIDNEXT'
                                },
                                {
                                    type: 'atom',
                                    value: String(Number(mailboxData.uidNext) || 1)
                                }
                            ]
                        },
                        {
                            type: 'text',
                            value: 'Predicted next UID'
                        }
                    ]
                })
            );

            callback(null, {
                response: 'OK',
                code: this.selected.readOnly ? 'READ-ONLY' : 'READ-WRITE',
                message: command.command + ' completed' + (this.selected.condstoreEnabled ? ', CONDSTORE is now enabled' : '')
            });
        });
    }
};
