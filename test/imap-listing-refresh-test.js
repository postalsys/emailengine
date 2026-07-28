'use strict';

// Unit tests for the folder-listing refresh in IMAPClient.syncMailboxes()
// (lib/email-client/imap-client.js).
//
// connect() already lists the folders and registers a Mailbox for every entry, so
// the sync that immediately follows it used to re-issue the identical LIST command
// on every single connection setup. Worse, that duplicate LIST was fatal: the throw
// travelled up to reconnect(), which tore down an authenticated connection and
// scheduled another one, so a server that fails a repeated LIST (one Exchange-alike
// answers "NO [SERVERBUG] Internal server error") kept the account in an endless
// connect loop and it never reached the connected state.

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

function createRecordingLogger() {
    const calls = [];
    const logger = {
        child() {
            return logger;
        }
    };
    for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        logger[level] = (...args) => calls.push({ level, args });
    }
    return { logger, calls };
}

// Builds a client whose connection is already established, with the folder-listing
// refresh replaced by a counter (or a thrower) so only the refresh decision is under test
function makeClient({ refreshError, mailboxPaths = [] } = {}) {
    const { logger, calls } = createRecordingLogger();

    const client = new IMAPClient('test-account', {
        logger,
        accountLogger: { enabled: false, log() {} },
        redis: { hdel: async () => 1, hSetExists: async () => 1 }
    });

    client.imapClient = { usable: true, rawCapabilities: [], authCapabilities: new Map(), serverInfo: {} };
    client.setStateVal = async () => {};

    let refreshCalls = 0;
    client.refreshFolderList = async () => {
        refreshCalls++;
        if (refreshError) {
            throw refreshError;
        }
        return new Set();
    };

    const syncedPaths = [];
    for (const path of mailboxPaths) {
        client.mailboxes.set(path, {
            path,
            sync: async () => {
                syncedPaths.push(path);
            },
            select: async () => {}
        });
    }

    return { client, refreshCalls: () => refreshCalls, syncedPaths, logCalls: calls };
}

// syncMailboxes() schedules the next resync pass before it resolves
async function runSync(client) {
    await client.syncMailboxes();
    clearTimeout(client.resyncTimer);
}

test('IMAPClient.syncMailboxes() folder listing refresh', async t => {
    await t.test('skips the refresh right after connect() listed the folders', async () => {
        const { client, refreshCalls, syncedPaths } = makeClient({ mailboxPaths: ['INBOX', 'Sent'] });
        // Set by connect() once every listed folder has a Mailbox instance
        client.listedClient = client.imapClient;

        await runSync(client);

        assert.equal(refreshCalls(), 0, 'the listing connect() just fetched must not be fetched again');
        assert.deepEqual(syncedPaths, ['INBOX', 'Sent'], 'every known folder must still be synced');
    });

    await t.test('refreshes on the next pass of the same connection', async () => {
        const { client, refreshCalls } = makeClient({ mailboxPaths: ['INBOX'] });
        client.listedClient = client.imapClient;

        await runSync(client);
        await runSync(client);

        assert.equal(refreshCalls(), 1, 'the marker is one-shot - later passes must pick up folder changes');
    });

    await t.test('refreshes when the marker belongs to a replaced connection', async () => {
        const { client, refreshCalls } = makeClient({ mailboxPaths: ['INBOX'] });
        // A connection that was listed, then replaced by a reconnect
        client.listedClient = { usable: false };

        await runSync(client);

        assert.equal(refreshCalls(), 1, 'a marker from an older client must not skip the refresh');
    });

    await t.test('refreshes when connect() never reached the listing', async () => {
        const { client, refreshCalls } = makeClient({ mailboxPaths: ['INBOX'] });

        await runSync(client);

        assert.equal(refreshCalls(), 1, 'an unset marker must not be read as a fresh listing');
    });

    await t.test('a failed refresh syncs the known folders instead of failing the connection', async () => {
        const refreshError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'SERVERBUG',
            responseText: 'Internal server error'
        });
        const { client, syncedPaths, logCalls } = makeClient({ refreshError, mailboxPaths: ['INBOX', 'Sent'] });

        await runSync(client);

        assert.deepEqual(syncedPaths, ['INBOX', 'Sent'], 'the folders already tracked must still be synced');
        assert.equal(client.state, 'connected', 'the connection must be reported as usable');
        assert.equal(
            logCalls.filter(entry => entry.level === 'warn' && entry.args[0] && entry.args[0].msg === 'Failed to refresh folder list, syncing known folders')
                .length,
            1,
            'the skipped refresh must be logged'
        );
    });

    await t.test('a failed refresh throws when no folders are tracked yet', async () => {
        const refreshError = Object.assign(new Error('Command failed'), { responseStatus: 'NO' });
        const { client } = makeClient({ refreshError });

        await assert.rejects(() => client.syncMailboxes(), refreshError, 'without a listing there is nothing to sync');
    });

    await t.test('a failed refresh throws when the connection is gone', async () => {
        const refreshError = Object.assign(new Error('Command failed'), { responseStatus: 'NO' });
        const { client } = makeClient({ refreshError, mailboxPaths: ['INBOX'] });
        // The refresh failed because the connection died, not because the server refused it
        client.refreshFolderList = async () => {
            client.imapClient.usable = false;
            throw refreshError;
        };

        await assert.rejects(() => client.syncMailboxes(), refreshError, 'a dead connection must still be retried by reconnect()');
    });

    await t.test('a refresh failure that is not a tagged command failure still throws', async () => {
        // Network errors, and the "empty mailbox listing" server-bug error that closes the
        // client, carry no responseStatus - those must keep tearing the connection down
        const refreshError = Object.assign(new Error('Server bug: empty mailbox listing'), { code: 'ServerBug' });
        const { client } = makeClient({ refreshError, mailboxPaths: ['INBOX'] });

        await assert.rejects(() => client.syncMailboxes(), refreshError, 'only a tagged command failure may be tolerated');
    });
});

registerRedisTeardown(redis);
