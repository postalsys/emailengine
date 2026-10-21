'use strict';

// IMAPClient.packUid() with a status cache: a listing packs the id of every message on the page,
// and each pack read the folder's whole stored status (an HGETALL) again, so a 1000 message page
// cost 1000 reads of the same hash. With the cache a page reads it once and the ids are unchanged.

const test = require('node:test');
const assert = require('node:assert').strict;
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/mock-db').installDbMock();

const { IMAPClient } = require('../lib/email-client/imap-client');
const { forAll, gen } = require('./helpers/property');

require('./helpers/redis-teardown')();

const noopLogger = createMockLogger();

function createConnection() {
    return Object.assign(Object.create(IMAPClient.prototype), {
        logger: noopLogger,
        pathCache: new Map(),
        idCache: new Map(),
        mailboxes: new Map(),
        getAccountKey: () => 'iad:acc',
        getMailboxHashKey: () => 'iah:acc',
        redis: { zGetMailboxId: async () => 7 }
    });
}

function createMailbox(status) {
    const mailbox = {
        path: 'INBOX',
        reads: 0,
        async getStoredStatus() {
            mailbox.reads++;
            return Object.assign({}, status);
        },
        getMailboxStatus() {
            throw new Error('not selected');
        }
    };
    return mailbox;
}

const VALID = { path: 'INBOX', uidValidity: 12345n, uidNext: 100 };

test('packUid() status cache', async t => {
    await t.test('a page of messages reads the stored status once', async () => {
        const connection = createConnection();
        const mailbox = createMailbox(VALID);
        const cache = new Map();
        for (let uid = 1; uid <= 50; uid++) {
            assert.ok(await connection.packUid(mailbox, uid, cache));
        }
        assert.strictEqual(mailbox.reads, 1);
    });

    await t.test('without a cache every call reads it, as before', async () => {
        const connection = createConnection();
        const mailbox = createMailbox(VALID);
        await connection.packUid(mailbox, 1);
        await connection.packUid(mailbox, 2);
        assert.strictEqual(mailbox.reads, 2);
    });

    await t.test('an unusable status is not cached, so the next message looks again', async () => {
        const connection = createConnection();
        const mailbox = createMailbox({ path: 'INBOX' });
        const cache = new Map();
        assert.strictEqual(await connection.packUid(mailbox, 1, cache), false);
        assert.strictEqual(await connection.packUid(mailbox, 2, cache), false);
        assert.strictEqual(mailbox.reads, 2);
        assert.strictEqual(cache.size, 0);
    });

    await t.test('property: cached and uncached packing give the same id for any UID', async () => {
        const connection = createConnection();
        const mailbox = createMailbox(VALID);
        const cache = new Map();
        await forAll(gen.withEdges(gen.integer(1, 0xffffffff), [1, 0xffffffff]), async uid => {
            assert.strictEqual(await connection.packUid(mailbox, uid, cache), await connection.packUid(mailbox, uid));
        });
    });
});
