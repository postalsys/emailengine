'use strict';

// A message moved, copied or uploaded into a folder the connection has not registered yet (created
// moments earlier through the API) used to answer with `id: false`: packUid() knew neither the folder nor its
// UIDVALIDITY. The server reports that UIDVALIDITY in the COPYUID of the same MOVE or COPY (and
// the APPENDUID of an APPEND), so the id is built from it. Found by the multi-instance tier on a slower Linux runner, where the folder's
// registration had not caught up.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db
require('./helpers/mock-db').installDbMock();

const { IMAPClient } = require('../lib/email-client/imap-client');

require('./helpers/redis-teardown')();

const { createMockLogger } = require('./helpers/mock-logger');

function client({ mailboxes = new Map() } = {}) {
    const calls = [];
    return {
        calls,
        client: Object.assign(Object.create(IMAPClient.prototype), {
            logger: createMockLogger(),
            mailboxes,
            pathCache: new Map(),
            idCache: new Map(),
            getAccountKey: () => 'iad:test',
            getMailboxHashKey: () => 'iah:test',
            redis: {
                zGetMailboxId: async (accountKey, hashKey, mailboxBuf) => {
                    calls.push(mailboxBuf);
                    return 7;
                }
            }
        })
    };
}

function expectedId(mailboxId, uid) {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(mailboxId, 0);
    buf.writeUInt32BE(uid, 4);
    return buf.toString('base64url');
}

test('packUid() with a UIDVALIDITY the server just reported', async t => {
    await t.test('builds the id for a folder the connection has not registered yet', async () => {
        const { client: imap, calls } = client();
        assert.equal(await imap.packUid('Forwarded', 3, null, 9n), expectedId(7, 3));
        // The folder record carries that UIDVALIDITY and the path as given
        assert.equal(calls[0].readBigUInt64BE(0), 9n);
        assert.equal(calls[0].subarray(8).toString(), 'Forwarded');
    });

    await t.test('without one an unknown folder still has no id', async () => {
        const { client: imap } = client();
        assert.equal(await imap.packUid('Forwarded', 3), false);
        assert.equal(await imap.packUid('Forwarded', 3, null, 0n), false);
    });

    await t.test('a registered folder not synced yet takes the reported UIDVALIDITY', async () => {
        const mailbox = {
            path: 'Forwarded',
            getStoredStatus: async () => ({ path: 'Forwarded' }),
            getMailboxStatus: () => {
                throw new Error('not selected');
            }
        };
        const { client: imap, calls } = client({ mailboxes: new Map([['Forwarded', mailbox]]) });
        assert.equal(await imap.packUid('Forwarded', 5, null, 11n), expectedId(7, 5));
        assert.equal(calls[0].readBigUInt64BE(0), 11n);
    });

    await t.test('the reported UIDVALIDITY wins over a stored one, which is not read at all', async () => {
        let reads = 0;
        const mailbox = {
            path: 'Forwarded',
            getStoredStatus: async () => {
                reads++;
                return { path: 'Forwarded', uidValidity: 4n };
            }
        };
        const { client: imap, calls } = client({ mailboxes: new Map([['Forwarded', mailbox]]) });
        await imap.packUid('Forwarded', 5, null, 11n);
        assert.equal(calls[0].readBigUInt64BE(0), 11n);
        assert.equal(reads, 0);
    });

    await t.test('a registered folder is named the way the server spells it', async () => {
        const mailbox = { path: 'INBOX', getStoredStatus: async () => ({ path: 'INBOX', uidValidity: 4n }) };
        const { client: imap, calls } = client({ mailboxes: new Map([['INBOX', mailbox]]) });
        await imap.packUid('Inbox', 5, null, 11n);
        assert.equal(calls[0].subarray(8).toString(), 'INBOX');
    });

    await t.test('without a reported one the stored UIDVALIDITY is used as before', async () => {
        const mailbox = { path: 'Forwarded', getStoredStatus: async () => ({ path: 'Forwarded', uidValidity: 4n }) };
        const { client: imap, calls } = client({ mailboxes: new Map([['Forwarded', mailbox]]) });
        await imap.packUid('Forwarded', 5);
        assert.equal(calls[0].readBigUInt64BE(0), 4n);
    });
});
