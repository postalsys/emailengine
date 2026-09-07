'use strict';

// A SyncOperations-shaped context (this.mailbox / this.connection / this.logger) whose
// collaborators record what an operation did. Shared by the tests that drive the sync
// operations directly, so the collaborator contract is spelled out in one place.
//
// The db mock has to be installed before this module is loaded: sync-operations.js pulls
// in lib/db, which opens real Redis connections at load time.
//
// Two folders are modelled: the mailbox itself and the one the connection has open
// before the lock is granted. getMailboxStatus() reports whichever is selected at the
// time of the call, so a test can tell a read made under the lock from one made before it.

const { SyncOperations } = require('../../lib/email-client/imap/sync-operations');

const MAILBOX_PATH = 'INBOX';
const OTHER_PATH = 'Other Folder';

const COUNTERS = {
    [MAILBOX_PATH]: { uidValidity: 123n, uidNext: 6, highestModseq: 10n, messages: 5 },
    [OTHER_PATH]: { uidValidity: 999n, uidNext: 60, highestModseq: 100n, messages: 50 }
};

const silentLogger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {}
};

/**
 * @param {Object} [options]
 * @param {String} [options.imapIndexer='full'] - Indexer mode of the mailbox
 * @param {Object[]} [options.messages=[]] - What imapClient.fetch() yields
 * @param {Object|false} [options.fetchOneResult=false] - What imapClient.fetchOne() resolves with
 * @returns {{ctx: Object, calls: Object, counters: Object}} Context to call SyncOperations methods on, what they did, and the mailbox's own counters
 */
function createSyncOperationsContext({ imapIndexer = 'full', messages = [], fetchOneResult = false } = {}) {
    const calls = {
        order: [], // lock, status, stored and release in call order
        released: 0,
        entryListSet: [], // UIDs recorded in the index
        updateStoredStatus: [],
        deletedKeys: [],
        zadd: [], // any queued notification - a seed must never produce one
        resetEvents: [],
        fetchOne: [],
        fetch: undefined
    };

    let selectedPath = OTHER_PATH;

    const ctx = {
        logger: silentLogger,
        releaseSyncLock: SyncOperations.prototype.releaseSyncLock,
        connection: {
            syncing: false,
            imapClient: {
                usable: true,
                enabled: new Set(),
                fetch: (range, fields, opts) => {
                    calls.fetch = { range, fields, opts };
                    return (async function* () {
                        for (const message of messages) {
                            yield message;
                        }
                    })();
                },
                fetchOne: async (range, fields) => {
                    calls.fetchOne.push({ range, fields });
                    return fetchOneResult;
                }
            },
            redis: {
                del: async key => {
                    calls.deletedKeys.push(key);
                },
                zadd: async (...args) => {
                    calls.zadd.push(args);
                },
                hdel: async () => {},
                zcard: async () => 0,
                hSetExists: async () => {}
            },
            notify: async (mailbox, event, payload) => {
                calls.resetEvents.push({ event, payload });
            }
        },
        mailbox: {
            path: MAILBOX_PATH,
            syncing: false,
            imapIndexer,
            listingEntry: { path: MAILBOX_PATH, name: MAILBOX_PATH, specialUse: '\\Inbox' },
            getMailboxLock: async () => {
                calls.order.push('lock');
                // The grant is a SELECT of this folder
                selectedPath = MAILBOX_PATH;
                return {
                    release: () => {
                        calls.order.push('release');
                        calls.released++;
                    }
                };
            },
            getMailboxStatus: () => {
                calls.order.push('status');
                return Object.assign({ path: MAILBOX_PATH }, COUNTERS[selectedPath]);
            },
            getStoredStatus: async () => {
                calls.order.push('stored');
                return { hasStoredState: true, uidValidity: 123n, uidNext: 4, highestModseq: 8n, messages: 3, initialUidNext: 1, lastFullSync: false };
            },
            updateStoredStatus: async status => {
                calls.updateStoredStatus.push(status);
            },
            publishSyncedEvents: async () => {},
            entryListGet: async () => null,
            entryListSet: async data => {
                calls.entryListSet.push(data.uid);
                return 1;
            },
            entryListExpunge: async () => null,
            processChanges: async () => {},
            processDeleted: async () => {},
            getNotificationsKey: () => 'iam:acc:n:KEY',
            getMessagesKey: () => 'iam:acc:l:KEY',
            getMailboxKey: () => 'iam:acc:h:KEY'
        }
    };

    return { ctx, calls, counters: COUNTERS[MAILBOX_PATH] };
}

module.exports = { createSyncOperationsContext, silentLogger };
