'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();
const registerRedisTeardown = require('./helpers/redis-teardown');

const { IMAPClient } = require('../lib/email-client/imap-client');

// lib/email-client/imap-client.js transitively opens Redis handles that keep the event loop alive
registerRedisTeardown();

// Regression tests for IMAPClient.onTaskCompleted().
//
// It arms a timer that re-selects the main mailbox so the connection does not sit in a rarely-used
// one. Every caller in lib/email-client/imap/mailbox.js passes the client that ran the task, but
// the method took no parameter and ignored it, so a task served by a pooled secondary connection
// scheduled a re-select on the primary - which that task never moved. getMailboxLock() makes
// exactly this primary-vs-secondary distinction when it clears the timer, so the two disagreed.
//
// It also re-armed without clearing, leaving a superseded timer live: a later lock clears only the
// newest handle, so the orphan still fired and pulled the primary out of the mailbox that lock had
// just settled it in.

const ENSURE_MAIN_TTL = 5 * 1000;

function createClient() {
    const client = Object.create(IMAPClient.prototype);
    client.completedTimer = false;
    client.imapClient = { id: 'primary' };
    client.logger = { debug() {}, error() {} };

    let selects = 0;
    client.ensureMainMailbox = async () => {
        selects++;
    };

    return { client, selectCount: () => selects };
}

test('IMAPClient.onTaskCompleted() connection handling', async t => {
    await t.test('re-selects the main mailbox after a task on the primary connection', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();

        client.onTaskCompleted(client.imapClient);
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(selectCount(), 1, 'a task on the primary must return it to the main mailbox');
    });

    await t.test('treats an unspecified connection as the primary', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();

        client.onTaskCompleted();
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(selectCount(), 1, 'an unspecified connection defaults to the primary');
    });

    await t.test('ignores a task served by a pooled secondary connection', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();

        client.onTaskCompleted({ id: 'secondary' });
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(client.completedTimer, false, 'a secondary never moved the primary, so no timer is needed');
        assert.strictEqual(selectCount(), 0, 'a secondary must not drag the primary back to the main mailbox');
    });

    await t.test('a superseded timer is not left behind for a later lock to miss', async t => {
        // getMailboxLock() cancels the pending re-select by clearing connection.completedTimer,
        // which only ever holds the newest handle. Re-arming without clearing therefore orphaned
        // the previous timer: it survived the lock and fired anyway, pulling the primary out of
        // the mailbox that lock had just settled it in.
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();

        client.onTaskCompleted(client.imapClient);
        client.onTaskCompleted(client.imapClient);

        // What getMailboxLock() does when the primary is locked again.
        clearTimeout(client.completedTimer);
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(selectCount(), 0, 'clearing the timer must cancel every pending re-select, not just the newest');
    });
});

// deleteMailbox() closes the mailbox on the connection it ran on and, unlike every other user
// method here, took ImapFlow's own lock rather than Mailbox.getMailboxLock() - so nothing on that
// path reported the task. On the primary that left the connection in AUTHENTICATED state with no
// mailbox selected and no IDLE armed: ImapFlow can only re-arm IDLE for a mailbox it is in, so the
// account stopped seeing new mail until the next resync pass up to 15 minutes later.
// A download reports its task from a stream callback that can fire long after the account was
// paused or deleted. close() clears the timer but leaves this.imapClient pointing at the closed
// client, so a late callback passed the identity guard and armed a fresh timer against a connection
// that is gone - and once a reconnect replaced the client, the re-select landed on the new one.
test('IMAPClient.onTaskCompleted() on a closed connection', async t => {
    await t.test('arms nothing once the connection is closed', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();
        client.isClosed = true;

        client.onTaskCompleted(client.imapClient);
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(selectCount(), 0, 'a torn-down connection has no mailbox to go back to');
    });

    await t.test('arms nothing while the connection is closing', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        const { client, selectCount } = createClient();
        client.isClosing = true;

        client.onTaskCompleted(client.imapClient);
        t.mock.timers.tick(ENSURE_MAIN_TTL);

        assert.strictEqual(selectCount(), 0, 'close() clears the timer, so re-arming behind it leaves an orphan');
    });
});

test('IMAPClient.deleteMailbox() returns the connection to its mailbox', async t => {
    function createDeleteClient({ deleteThrows = false } = {}) {
        const client = Object.create(IMAPClient.prototype);
        const completed = [];

        client.mailboxes = new Map();
        client.logger = { debug() {}, error() {}, info() {} };
        client.checkIMAPConnection = () => {};
        client.resolvePathAlias = async path => path;
        client.onTaskCompleted = connectionClient => completed.push(connectionClient);

        const connectionClient = {
            id: 'primary',
            getMailboxLock: async () => ({ release() {} }),
            mailboxClose: async () => {},
            mailboxDelete: async () => {
                if (deleteThrows) {
                    throw new Error('DELETE refused');
                }
            }
        };
        client.getImapConnection = async () => connectionClient;

        return { client, connectionClient, completed };
    }

    await t.test('reports the task after closing the mailbox it deleted', async () => {
        const { client, connectionClient, completed } = createDeleteClient();

        const result = await client.deleteMailbox('Old folder');

        assert.strictEqual(result.deleted, true);
        assert.deepEqual(completed, [connectionClient], 'the connection has to be sent back to the mailbox it watches');
    });

    await t.test('reports the task even when the server refuses the delete', async () => {
        // mailboxClose() has already run by then, so the connection is sitting on no mailbox
        // whether or not the DELETE succeeded - which is the state that has to be undone.
        const { client, connectionClient, completed } = createDeleteClient({ deleteThrows: true });

        const result = await client.deleteMailbox('Old folder');

        assert.strictEqual(result.deleted, false);
        assert.deepEqual(completed, [connectionClient]);
    });
});
