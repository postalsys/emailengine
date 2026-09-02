'use strict';

// IMAPClient.deleteMailbox() used to swallow a refused DELETE ("kind of ignore"), answer
// { deleted: false } and then clear the local index anyway, which emitted mailboxDeleted for
// a folder that was still on the server and re-synced it from scratch once the next listing
// found it again. It now reports the refusal the way createMailbox()/renameMailbox() do and
// only touches the local index once the server confirmed the delete.

const test = require('node:test');
const assert = require('node:assert').strict;

const { IMAPClient } = require('../lib/email-client/imap-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

function createClient({ lockError, deleteError } = {}) {
    const client = Object.create(IMAPClient.prototype);
    const cleared = [];

    client.mailboxes = new Map([['Old folder', { clear: async () => cleared.push('Old folder') }]]);
    client.logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };
    client.checkIMAPConnection = () => {};
    client.onTaskCompleted = () => {};

    const connectionClient = {
        getMailboxLock: async () => {
            if (lockError) {
                throw lockError;
            }
            return { release() {} };
        },
        mailboxClose: async () => {},
        mailboxDelete: async () => {
            if (deleteError) {
                throw deleteError;
            }
            return true;
        }
    };
    client.getImapConnection = async () => connectionClient;

    return { client, cleared };
}

test('IMAPClient.deleteMailbox()', async t => {
    await t.test('clears the local index once the server deleted the folder', async () => {
        const { client, cleared } = createClient();

        const result = await client.deleteMailbox('Old folder');

        assert.deepEqual(result, { path: 'Old folder', deleted: true });
        assert.deepEqual(cleared, ['Old folder']);
    });

    await t.test('a refused DELETE is a coded 400 carrying the server response code, and the index is kept', async () => {
        // The shape ImapFlow gives a NO response with a response code
        const deleteError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'CANNOT',
            response: 'NO [CANNOT] Mailbox has inferior hierarchical names'
        });
        const { client, cleared } = createClient({ deleteError });

        await assert.rejects(client.deleteMailbox('Old folder'), err => {
            assert.equal(err.statusCode, 400);
            assert.equal(err.code, 'CANNOT');
            assert.equal(err.info.response, '[CANNOT] Mailbox has inferior hierarchical names');
            return true;
        });
        assert.deepEqual(cleared, [], 'the local index must survive a refused delete');
    });

    await t.test('a NO without a response code still maps to a 400', async () => {
        const deleteError = Object.assign(new Error('Command failed'), { responseStatus: 'NO', response: 'NO Permission denied' });
        const { client } = createClient({ deleteError });

        await assert.rejects(client.deleteMailbox('Old folder'), err => err.statusCode === 400 && err.code === 'DeleteFailed');
    });

    await t.test('a folder the server does not have is a 404', async () => {
        const { client, cleared } = createClient({ lockError: Object.assign(new Error('Command failed'), { mailboxMissing: true }) });

        await assert.rejects(client.deleteMailbox('Old folder'), err => err.statusCode === 404 && err.code === 'NotFound');
        assert.deepEqual(cleared, []);
    });
});
