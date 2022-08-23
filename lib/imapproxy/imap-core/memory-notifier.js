'use strict';

let EventEmitter = require('events').EventEmitter;

// Expects that the folder listing is a Map

class MemoryNotifier extends EventEmitter {
    constructor(options) {
        super();
        this.folders = options.folders || new Map();

        let logfunc = (...args) => {
            let level = args.shift() || 'DEBUG';
            let message = args.shift() || '';

            console.log([level].concat(message || '').join(' '), ...args); // eslint-disable-line no-console
        };

        this.logger = options.logger || {
            info: logfunc.bind(null, 'INFO'),
            debug: logfunc.bind(null, 'DEBUG'),
            error: logfunc.bind(null, 'ERROR')
        };

        this._listeners = new EventEmitter();
        this._listeners.setMaxListeners(0);

        EventEmitter.call(this);
    }

    /**
     * Registers an event handler for mailbox:username events
     *
     * @param {String} username
     * @param {String} mailbox
     * @param {Function} handler Function to run once there are new entries in the journal
     */
    addListener(session, handler) {
        this._listeners.addListener(session.user.id.toString(), handler);
    }

    /**
     * Unregisters an event handler for mailbox:username events
     *
     * @param {String} username
     * @param {String} mailbox
     * @param {Function} handler Function to run once there are new entries in the journal
     */
    removeListener(session, handler) {
        this._listeners.removeListener(session.user.id.toString(), handler);
    }

    /**
     * Stores multiple journal entries to db
     *
     * @param {String} username
     * @param {String} mailbox
     * @param {Array|Object} entries An array of entries to be journaled
     * @param {Function} callback Runs once the entry is either stored or an error occurred
     */
    addEntries(mailbox, entries, callback) {
        let folder = this.folders.get(mailbox);

        if (!folder) {
            return callback(null, new Error('Selected mailbox does not exist'));
        }

        if (entries && !Array.isArray(entries)) {
            entries = [entries];
        } else if (!entries || !entries.length) {
            return callback(null, false);
        }

        // store entires in the folder object
        if (!folder.journal) {
            folder.journal = [];
        }

        entries.forEach(entry => {
            entry.modseq = ++folder.modifyIndex;
            folder.journal.push(entry);
        });

        setImmediate(callback);
    }

    /**
     * Sends a notification that there are new updates in the selected mailbox
     *
     * @param {String} username
     * @param {String} mailbox
     */
    fire(username, payload) {
        setImmediate(() => {
            this._listeners.emit(username, payload);
        });
    }

    /**
     * Returns all entries from the journal that have higher than provided modification index
     *
     * @param {String} username
     * @param {String} mailbox
     * @param {Number} modifyIndex Last known modification id
     * @param {Function} callback Returns update entries as an array
     */
    getUpdates(mailbox, modifyIndex, callback) {
        modifyIndex = Number(modifyIndex) || 0;

        if (!this.folders.has(mailbox)) {
            return callback(null, 'NONEXISTENT');
        }

        let folder = this.folders.get(mailbox);
        let minIndex = folder.journal.length;

        for (let i = folder.journal.length - 1; i >= 0; i--) {
            if (folder.journal[i].modseq > modifyIndex) {
                minIndex = i;
            } else {
                break;
            }
        }

        return callback(null, folder.journal.slice(minIndex));
    }
}

module.exports = MemoryNotifier;
