'use strict';

const IMAPServerModule = require('../index.js');
const IMAPServer = IMAPServerModule.IMAPServer;
const MemoryNotifier = require('./memory-notifier.js');
const fs = require('fs');
const parseMimeTree = require('../lib/indexer/parse-mime-tree');
const imapHandler = require('../lib/handler/imap-handler');

module.exports = function (options) {
    // This example uses global folders and subscriptions
    let folders = new Map();
    let subscriptions = new WeakSet();

    [
        {
            mailbox: Symbol('INBOX'),
            path: 'INBOX',
            uidValidity: 123,
            uidNext: 70,
            modifyIndex: 5000,
            messages: [
                {
                    uid: 45,
                    flags: [],
                    modseq: 100,
                    idate: new Date('14-Sep-2013 21:22:28 -0300'),
                    mimeTree: parseMimeTree(
                        Buffer.from('from: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nzzzz\r\n')
                    )
                },
                {
                    uid: 49,
                    flags: ['\\Seen'],
                    idate: new Date(),
                    modseq: 5000,
                    mimeTree: parseMimeTree(fs.readFileSync(__dirname + '/fixtures/ryan_finnie_mime_torture.eml'))
                },
                {
                    uid: 50,
                    flags: ['\\Seen'],
                    modseq: 45,
                    idate: new Date(),
                    mimeTree: parseMimeTree(
                        'MIME-Version: 1.0\r\n' +
                            'From: andris@kreata.ee\r\n' +
                            'To: andris@tr.ee\r\n' +
                            'Content-Type: multipart/mixed;\r\n' +
                            " boundary='----mailcomposer-?=_1-1328088797399'\r\n" +
                            'Message-Id: <testmessage-for-bug>;\r\n' +
                            '\r\n' +
                            '------mailcomposer-?=_1-1328088797399\r\n' +
                            'Content-Type: message/rfc822\r\n' +
                            'Content-Transfer-Encoding: 7bit\r\n' +
                            '\r\n' +
                            'MIME-Version: 1.0\r\n' +
                            'From: andris@kreata.ee\r\n' +
                            'To: andris@pangalink.net\r\n' +
                            'In-Reply-To: <test1>\r\n' +
                            '\r\n' +
                            'Hello world 1!\r\n' +
                            '------mailcomposer-?=_1-1328088797399\r\n' +
                            'Content-Type: message/rfc822\r\n' +
                            'Content-Transfer-Encoding: 7bit\r\n' +
                            '\r\n' +
                            'MIME-Version: 1.0\r\n' +
                            'From: andris@kreata.ee\r\n' +
                            'To: andris@pangalink.net\r\n' +
                            '\r\n' +
                            'Hello world 2!\r\n' +
                            '------mailcomposer-?=_1-1328088797399\r\n' +
                            'Content-Type: text/html; charset=utf-8\r\n' +
                            'Content-Transfer-Encoding: quoted-printable\r\n' +
                            '\r\n' +
                            '<b>Hello world 3!</b>\r\n' +
                            '------mailcomposer-?=_1-1328088797399--\r\n'
                    )
                },
                {
                    uid: 52,
                    flags: [],
                    modseq: 4,
                    idate: new Date(),
                    mimeTree: parseMimeTree('from: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nHello World!\r\n')
                },
                {
                    uid: 53,
                    flags: [],
                    modseq: 5,
                    idate: new Date()
                },
                {
                    uid: 60,
                    flags: [],
                    modseq: 6,
                    idate: new Date()
                }
            ],
            journal: []
        },
        {
            mailbox: Symbol('[Gmail]/Sent Mail'),
            path: '[Gmail]/Sent Mail',
            specialUse: '\\Sent',
            uidValidity: 123,
            uidNext: 90,
            modifyIndex: 1,
            messages: [],
            journal: []
        }
    ].forEach(folder => {
        folders.set(folder.path, folder);
        subscriptions.add(folder);
    });

    // Setup server
    let server = new IMAPServer(options);
    server.notifier = new MemoryNotifier({
        logger: {
            info: () => false,
            debug: () => false,
            error: () => false
        },
        folders
    });

    server.on('error', err => {
        console.log('SERVER ERR\n%s', err.stack); // eslint-disable-line no-console
    });

    server.onAuth = function (login, session, callback) {
        if (login.username !== 'testuser' || login.password !== 'pass') {
            return callback();
        }

        callback(null, {
            user: {
                id: 'id.' + login.username,
                username: login.username
            }
        });
    };

    // LIST "" "*"
    // Returns all folders, query is informational
    // folders is either an Array or a Map
    server.onList = function (query, session, callback) {
        this.logger.debug('[%s] LIST for "%s"', session.id, query);

        callback(null, folders);
    };

    // LSUB "" "*"
    // Returns all subscribed folders, query is informational
    // folders is either an Array or a Map
    server.onLsub = function (query, session, callback) {
        this.logger.debug('[%s] LSUB for "%s"', session.id, query);

        let subscribed = [];
        folders.forEach(folder => {
            if (subscriptions.has(folder)) {
                subscribed.push(folder);
            }
        });

        callback(null, subscribed);
    };

    // SUBSCRIBE "path/to/mailbox"
    server.onSubscribe = function (mailbox, session, callback) {
        this.logger.debug('[%s] SUBSCRIBE to "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        subscriptions.add(folders.get(mailbox));
        callback(null, true);
    };

    // UNSUBSCRIBE "path/to/mailbox"
    server.onUnsubscribe = function (mailbox, session, callback) {
        this.logger.debug('[%s] UNSUBSCRIBE from "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        subscriptions.delete(folders.get(mailbox));
        callback(null, true);
    };

    // CREATE "path/to/mailbox"
    server.onCreate = function (mailbox, session, callback) {
        this.logger.debug('[%s] CREATE "%s"', session.id, mailbox);

        if (folders.has(mailbox)) {
            return callback(null, 'ALREADYEXISTS');
        }

        folders.set(mailbox, {
            path: mailbox,
            uidValidity: Date.now(),
            uidNext: 1,
            modifyIndex: 0,
            messages: [],
            journal: []
        });

        subscriptions.add(folders.get(mailbox));
        callback(null, true);
    };

    // RENAME "path/to/mailbox" "new/path"
    // NB! RENAME affects child and hierarchy mailboxes as well, this example does not do this
    server.onRename = function (mailbox, newname, session, callback) {
        this.logger.debug('[%s] RENAME "%s" to "%s"', session.id, mailbox, newname);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        if (folders.has(newname)) {
            return callback(null, 'ALREADYEXISTS');
        }

        let oldMailbox = folders.get(mailbox);
        folders.delete(mailbox);

        oldMailbox.path = newname;
        folders.set(newname, oldMailbox);

        callback(null, true);
    };

    // DELETE "path/to/mailbox"
    server.onDelete = function (mailbox, session, callback) {
        this.logger.debug('[%s] DELETE "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        // keep SPECIAL-USE folders
        if (folders.get(mailbox).specialUse) {
            return callback(null, 'CANNOT');
        }

        folders.delete(mailbox);
        callback(null, true);
    };

    // SELECT/EXAMINE
    server.onOpen = function (mailbox, session, callback) {
        this.logger.debug('[%s] Opening "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = folders.get(mailbox);

        return callback(null, {
            specialUse: folder.specialUse,
            uidValidity: folder.uidValidity,
            uidNext: folder.uidNext,
            modifyIndex: folder.modifyIndex,
            uidList: folder.messages.map(message => message.uid)
        });
    };

    // STATUS (X Y X)
    server.onStatus = function (mailbox, session, callback) {
        this.logger.debug('[%s] Requested status for "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = folders.get(mailbox);

        return callback(null, {
            messages: folder.messages.length,
            uidNext: folder.uidNext,
            uidValidity: folder.uidValidity,
            highestModseq: folder.modifyIndex,
            unseen: folder.messages.filter(message => !message.flags.includes('\\Seen')).length
        });
    };

    // APPEND mailbox (flags) date message
    server.onAppend = function (mailbox, flags, date, raw, session, callback) {
        this.logger.debug('[%s] Appending message to "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'TRYCREATE');
        }

        date = (date && new Date(date)) || new Date();

        let folder = folders.get(mailbox);
        let message = {
            uid: folder.uidNext++,
            modseq: ++folder.modifyIndex,
            date: (date && new Date(date)) || new Date(),
            mimeTree: parseMimeTree(raw),
            flags
        };

        folder.messages.push(message);

        // do not write directly to stream, use notifications as the currently selected mailbox might not be the one that receives the message
        this.notifier.addEntries(
            session.user.id,
            mailbox,
            {
                command: 'EXISTS',
                uid: message.uid
            },
            () => {
                this.notifier.fire(session.user.id, mailbox);

                return callback(null, true, {
                    uidValidity: folder.uidValidity,
                    uid: message.uid
                });
            }
        );
    };

    // STORE / UID STORE, updates flags for selected UIDs
    server.onStore = function (mailbox, update, session, callback) {
        this.logger.debug('[%s] Updating messages in "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let condstoreEnabled = !!session.selected.condstoreEnabled;

        let modified = [];
        let folder = folders.get(mailbox);
        let i = 0;

        let processMessages = () => {
            if (i >= folder.messages.length) {
                this.notifier.fire(session.user.id, mailbox);
                return callback(null, true, modified);
            }

            let message = folder.messages[i++];
            let updated = false;

            if (update.messages.indexOf(message.uid) < 0) {
                return processMessages();
            }

            if (update.unchangedSince && message.modseq > update.unchangedSince) {
                modified.push(message.uid);
                return processMessages();
            }

            switch (update.action) {
                case 'set':
                    // check if update set matches current or is different
                    if (message.flags.length !== update.value.length || update.value.filter(flag => message.flags.indexOf(flag) < 0).length) {
                        updated = true;
                    }
                    // set flags
                    message.flags = [].concat(update.value);
                    break;

                case 'add':
                    message.flags = message.flags.concat(
                        update.value.filter(flag => {
                            if (message.flags.indexOf(flag) < 0) {
                                updated = true;
                                return true;
                            }
                            return false;
                        })
                    );
                    break;

                case 'remove':
                    message.flags = message.flags.filter(flag => {
                        if (update.value.indexOf(flag) < 0) {
                            return true;
                        }
                        updated = true;
                        return false;
                    });
                    break;
            }

            // notifiy only if something changed
            if (updated) {
                message.modseq = ++folder.modifyIndex;

                // Only show response if not silent or modseq is required
                if (!update.silent || condstoreEnabled) {
                    session.writeStream.write(
                        session.formatResponse('FETCH', message.uid, {
                            uid: update.isUid ? message.uid : false,
                            flags: update.silent ? false : message.flags,
                            modseq: condstoreEnabled ? message.modseq : false
                        })
                    );
                }

                this.notifier.addEntries(
                    session.user.id,
                    mailbox,
                    {
                        command: 'FETCH',
                        ignore: session.id,
                        uid: message.uid,
                        flags: message.flags
                    },
                    processMessages
                );
            } else {
                processMessages();
            }
        };

        processMessages();
    };

    // EXPUNGE deletes all messages in selected mailbox marked with \Delete
    server.onExpunge = function (mailbox, update, session, callback) {
        this.logger.debug('[%s] Deleting messages from "%s"', session.id, mailbox);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = folders.get(mailbox);
        let deleted = [];
        let i, len;

        for (i = folder.messages.length - 1; i >= 0; i--) {
            if (
                ((update.isUid && update.messages.indexOf(folder.messages[i].uid) >= 0) || !update.isUid) &&
                folder.messages[i].flags.indexOf('\\Deleted') >= 0
            ) {
                deleted.unshift(folder.messages[i].uid);
                folder.messages.splice(i, 1);
            }
        }

        let entries = [];
        for (i = 0, len = deleted.length; i < len; i++) {
            entries.push({
                command: 'EXPUNGE',
                ignore: session.id,
                uid: deleted[i]
            });
            if (!update.silent) {
                session.writeStream.write(session.formatResponse('EXPUNGE', deleted[i]));
            }
        }

        this.notifier.addEntries(session.user.id, mailbox, entries, () => {
            this.notifier.fire(session.user.id, mailbox);
            return callback(null, true);
        });
    };

    // COPY / UID COPY sequence mailbox
    server.onCopy = function (connection, mailbox, update, session, callback) {
        this.logger.debug('[%s] Copying messages from "%s" to "%s"', session.id, mailbox, update.destination);

        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        if (!folders.has(update.destination)) {
            return callback(null, 'TRYCREATE');
        }

        let sourceFolder = folders.get(mailbox);
        let destinationFolder = folders.get(update.destination);

        let messages = [];
        let sourceUid = [];
        let destinationUid = [];
        let i, len;
        let entries = [];

        for (i = sourceFolder.messages.length - 1; i >= 0; i--) {
            if (update.messages.indexOf(sourceFolder.messages[i].uid) >= 0) {
                messages.unshift(JSON.parse(JSON.stringify(sourceFolder.messages[i])));
                sourceUid.unshift(sourceFolder.messages[i].uid);
            }
        }

        for (i = 0, len = messages.length; i < len; i++) {
            messages[i].uid = destinationFolder.uidNext++;
            destinationUid.push(messages[i].uid);
            destinationFolder.messages.push(messages[i]);

            // do not write directly to stream, use notifications as the currently selected mailbox might not be the one that receives the message
            entries.push({
                command: 'EXISTS',
                uid: messages[i].uid
            });
        }

        this.notifier.addEntries(update.destination, session.user.id, entries, () => {
            this.notifier.fire(session.user.id, update.destination);

            return callback(null, true, {
                uidValidity: destinationFolder.uidValidity,
                sourceUid,
                destinationUid
            });
        });
    };

    // sends results to socket
    server.onFetch = function (mailbox, options, session, callback) {
        this.logger.debug('[%s] Requested FETCH for "%s"', session.id, mailbox);
        this.logger.debug('[%s] FETCH: %s', session.id, JSON.stringify(options.query));
        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = folders.get(mailbox);
        let entries = [];

        if (options.markAsSeen) {
            // mark all matching messages as seen
            folder.messages.forEach(message => {
                if (options.messages.indexOf(message.uid) < 0) {
                    return;
                }

                // if BODY[] is touched, then add \Seen flag and notify other clients
                if (!message.flags.includes('\\Seen')) {
                    message.flags.unshift('\\Seen');
                    entries.push({
                        command: 'FETCH',
                        ignore: session.id,
                        uid: message.uid,
                        flags: message.flags
                    });
                }
            });
        }

        this.notifier.addEntries(session.user.id, mailbox, entries, () => {
            let pos = 0;
            let processMessage = () => {
                if (pos >= folder.messages.length) {
                    // once messages are processed show relevant updates
                    this.notifier.fire(session.user.id, mailbox);
                    return callback(null, true);
                }
                let message = folder.messages[pos++];

                if (options.messages.indexOf(message.uid) < 0) {
                    return setImmediate(processMessage);
                }

                if (options.changedSince && message.modseq <= options.changedSince) {
                    return setImmediate(processMessage);
                }

                let stream = imapHandler.compileStream(
                    session.formatResponse('FETCH', message.uid, {
                        query: options.query,
                        values: session.getQueryResponse(options.query, message)
                    })
                );

                // send formatted response to socket
                session.writeStream.write(stream, () => {
                    setImmediate(processMessage);
                });
            };

            setImmediate(processMessage);
        });
    };

    // returns an array of matching UID values and the highest modseq of matching messages
    server.onSearch = function (mailbox, options, session, callback) {
        if (!folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = folders.get(mailbox);
        let highestModseq = 0;

        let uidList = [];
        let checked = 0;
        let checkNext = () => {
            if (checked >= folder.messages.length) {
                return callback(null, {
                    uidList,
                    highestModseq
                });
            }
            let message = folder.messages[checked++];
            session.matchSearchQuery(message, options.query, (err, match) => {
                if (err) {
                    // ignore
                }
                if (match && highestModseq < message.modseq) {
                    highestModseq = message.modseq;
                }
                if (match) {
                    uidList.push(message.uid);
                }
                checkNext();
            });
        };
        checkNext();
    };

    return server;
};
