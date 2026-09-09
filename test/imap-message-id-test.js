'use strict';

// The IMAP client's message identifiers, decoded back from what a caller sent.
//
// Both decoders read a caller-supplied base64url value, and both used to trust its shape.
// unpackUid() called readUInt32BE(0) on whatever it got, so any id shorter than eight bytes threw
// "RangeError: Attempt to access memory outside buffer bounds" out of every endpoint that takes a
// message id - reported from the field against 2.79.6. getMessageTextPaths() handed the tail
// straight to the msgpack decoder, which throws on a truncated or absent one, so a text id one
// byte short reached the API as a 500 where the Gmail and Graph clients answer 400.
//
// Neither decoder needs a connection: unpackUid() resolves the folder from a cache or one Redis
// read, so the receiver below carries exactly that.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. Nothing here reaches a real one.
require('./helpers/mock-db').installDbMock();

const { IMAPClient } = require('../lib/email-client/imap-client');
const msgpack = require('../lib/msgpack');

// imap-client.js pulls in modules that keep the event loop alive; the shared teardown forces the
// exit once the tests are done
require('./helpers/redis-teardown')();

const UID_VALIDITY = 12345n;
const MAILBOX_ID = 7;

// What zGetMailboxPathBuffer stores for a folder: the UIDVALIDITY as a 64 bit integer, then the path
function mailboxBuffer(path, uidValidity = UID_VALIDITY) {
    const head = Buffer.alloc(8);
    head.writeBigUInt64BE(uidValidity, 0);
    return Buffer.concat([head, Buffer.from(path)]);
}

// The eight byte head of every message id: the folder's id, then the UID
function packedUid(mailboxId, uid) {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(mailboxId, 0);
    buf.writeUInt32BE(uid, 4);
    return buf;
}

// A receiver carrying only what the two decoders touch. Built on the prototype rather than by
// listing the methods under test, so a decoder that starts calling another inherited helper does
// not fail here as "not a function".
function createClient({ knownMailboxes = { [MAILBOX_ID]: 'INBOX' } } = {}) {
    const reads = [];

    const client = Object.assign(Object.create(IMAPClient.prototype), {
        idCache: new Map(),
        pathCache: new Map(),
        getMailboxHashKey: () => 'iam:test-account:h',
        redis: {
            zGetMailboxPathBuffer: async (key, mailboxId) => {
                reads.push(mailboxId);
                const path = knownMailboxes[mailboxId];
                return path ? mailboxBuffer(path) : null;
            }
        }
    });

    return { reads, client };
}

const isInvalidId = err => err.code === 'InvalidId' && err.statusCode === 400;

test('IMAPClient.unpackUid', async t => {
    await t.test('resolves the folder and UID of an id it issued', async () => {
        const { client } = createClient();

        assert.deepEqual(await client.unpackUid(packedUid(MAILBOX_ID, 42).toString('base64url')), {
            path: 'INBOX',
            uidValidity: '12345',
            uid: 42
        });
    });

    await t.test('an id shorter than the pair it encodes is not an id', async () => {
        // The reported crash: readUInt32BE(4) - and readUInt32BE(0) below four bytes - throws a
        // RangeError, which every endpoint taking a message id passed straight to the caller
        const { client, reads } = createClient();

        for (const id of ['', 'AA', Buffer.alloc(4).toString('base64url'), Buffer.alloc(7).toString('base64url')]) {
            assert.equal(await client.unpackUid(id), false, `${JSON.stringify(id)} must not be decoded`);
        }
        assert.deepEqual(reads, [], 'and none of them is worth a Redis read');
    });

    await t.test('accepts the buffer form the callers pass', async () => {
        // Most call sites hand over buf.subarray(0, 8) rather than a string
        const { client } = createClient();

        assert.equal((await client.unpackUid(packedUid(MAILBOX_ID, 7))).uid, 7);
        assert.equal(await client.unpackUid(Buffer.alloc(3)), false);
    });

    await t.test('an id naming a folder this account does not have is not decoded', async () => {
        const { client } = createClient();

        assert.equal(await client.unpackUid(packedUid(99, 42).toString('base64url')), false);
    });

    await t.test('the folder lookup is cached', async () => {
        const { client, reads } = createClient();

        await client.unpackUid(packedUid(MAILBOX_ID, 1).toString('base64url'));
        await client.unpackUid(packedUid(MAILBOX_ID, 2).toString('base64url'));

        assert.deepEqual(reads, [MAILBOX_ID], 'the second id is answered from the cache');
    });
});

test('IMAPClient.getMessageTextPaths', async t => {
    const textId = parts => Buffer.concat([packedUid(MAILBOX_ID, 42), msgpack.encode(parts)]).toString('base64url');

    await t.test('decodes the parts list of an id it issued', async () => {
        const { client } = createClient();

        const res = await client.getMessageTextPaths(textId([['1'], ['2'], []]));

        assert.equal(res.message.path, 'INBOX');
        assert.equal(res.message.uid, 42);
        assert.deepEqual(res.textParts, [['1'], ['2'], []]);
    });

    await t.test('an id with no parts list is a coded 400', async () => {
        // The message id on its own, which is what a caller sending the wrong one of the two ids
        // produces. The decoder answers an empty buffer by throwing
        const { client } = createClient();

        await assert.rejects(() => client.getMessageTextPaths(packedUid(MAILBOX_ID, 42).toString('base64url')), isInvalidId);
    });

    await t.test('a truncated parts list is a coded 400', async () => {
        const { client } = createClient();
        const truncated = Buffer.concat([packedUid(MAILBOX_ID, 42), msgpack.encode([['1'], ['2'], []]).subarray(0, 2)]);

        await assert.rejects(() => client.getMessageTextPaths(truncated.toString('base64url')), isInvalidId);
    });

    await t.test('an id for a folder this account does not have reports no message', async () => {
        // Decodable, just not ours: a missing message is a 404, not a malformed identifier
        const { client } = createClient();
        const foreign = Buffer.concat([packedUid(99, 42), msgpack.encode([['1'], [], []])]);

        assert.deepEqual(await client.getMessageTextPaths(foreign.toString('base64url')), { message: false });
    });
});
