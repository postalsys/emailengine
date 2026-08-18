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
