'use strict';

// A message id carries the UIDVALIDITY of the folder it was issued for (packUid() stores it with
// the path behind the numeric mailbox id), but nothing compared it with the folder's current value:
// every id-consuming path addressed the message by path and UID alone. Once a folder is recreated
// (a migration, a restore) the server reuses the UIDs for different messages, so an old id fetched,
// flagged, moved or deleted whatever message holds that UID now - silently, and for deletes, for
// good. The check sits under the mailbox lock, against the folder the lock actually opened.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. Nothing here reaches a real one.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { IMAPClient } = require('../lib/email-client/imap-client');

require('./helpers/redis-teardown')();

const OLD_UID_VALIDITY = 100n;
const NEW_UID_VALIDITY = 200n;

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

// A connection whose selected folder is INBOX under the given UIDVALIDITY, recording every
// command that would touch a message
function createMailboxContext(uidValidity) {
    const calls = [];
    const events = [];

    const connectionClient = {
        mailbox: { path: 'INBOX', uidValidity },
        fetchOne: async uid => {
            calls.push(['fetchOne', uid]);
            return { uid, flags: new Set(), envelope: {} };
        },
        download: async (uid, part) => {
            calls.push(['download', uid, part]);
            const { PassThrough } = require('node:stream');
            const content = new PassThrough();
            content.end('body');
            return { meta: { contentType: 'text/plain' }, content };
        },
        messageFlagsAdd: async uid => {
            calls.push(['messageFlagsAdd', uid]);
            return true;
        },
        messageMove: async (uid, path) => {
            calls.push(['messageMove', uid, path]);
            return { destination: path, uidMap: new Map() };
        },
        messageDelete: async uid => {
            calls.push(['messageDelete', uid]);
            return true;
        }
    };

    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Trash' },
        logger: noopLogger,
        getMailboxLock: async () => ({
            release() {
                events.push('release');
            }
        }),
        connection: {
            account: 'test-account',
            getImapConnection: async () => connectionClient,
            getSpecialUseMailbox: async () => null,
            packUid: async () => 'packed'
        }
    });

    return { ctx, calls, events };
}

// What unpackUid() returns: the UIDVALIDITY as a decimal string
const staleMessage = { path: 'INBOX', uidValidity: OLD_UID_VALIDITY.toString(), uid: 5 };
const currentMessage = { path: 'INBOX', uidValidity: NEW_UID_VALIDITY.toString(), uid: 5 };

const operations = {
    getText: (ctx, message) => ctx.getText(message, ['1'], {}, {}),
    getAttachment: (ctx, message) => ctx.getAttachment(message, '2', {}, {}),
    getMessage: (ctx, message) => ctx.getMessage(message, { fields: { uid: true, flags: true } }, {}),
    updateMessage: (ctx, message) => ctx.updateMessage(message, { flags: { add: ['\\Seen'] } }, {}),
    moveMessage: (ctx, message) => ctx.moveMessage(message, { path: 'Archive' }, {}, {}),
    deleteMessage: (ctx, message) => ctx.deleteMessage(message, true, {})
};

test('Mailbox id-consuming methods check the UIDVALIDITY the id was issued under', async t => {
    for (const [name, run] of Object.entries(operations)) {
        await t.test(`${name}() answers not found for an id from a previous incarnation of the folder`, async () => {
            const { ctx, calls, events } = createMailboxContext(NEW_UID_VALIDITY);

            const result = await run(ctx, staleMessage);

            assert.strictEqual(result, false);
            assert.deepEqual(calls, [], 'no command may reach the message that holds the UID now');
            assert.deepEqual(events, ['release'], 'the lock is given back');
        });

        await t.test(`${name}() proceeds when the UIDVALIDITY matches`, async () => {
            const { ctx, calls } = createMailboxContext(NEW_UID_VALIDITY);

            const result = await run(ctx, currentMessage);
            if (result && typeof result.destroy === 'function') {
                result.destroy();
            }

            assert.notStrictEqual(result, false);
            assert.ok(calls.length > 0, 'the command reaches the server');
        });
    }

    await t.test('a reference built internally, without a UIDVALIDITY, is not checked', async () => {
        const { ctx, calls } = createMailboxContext(NEW_UID_VALIDITY);

        await ctx.deleteMessage({ uid: 5 }, true, {});

        assert.deepEqual(calls, [['messageDelete', 5]]);
    });

    await t.test('a server reporting no UIDVALIDITY leaves nothing to compare against', async () => {
        const { ctx, calls } = createMailboxContext(false);

        await ctx.deleteMessage(staleMessage, true, {});

        assert.deepEqual(calls, [['messageDelete', 5]]);
    });
});

test('IMAPClient.deleteMessage() with an id issued before the folder was recreated', async () => {
    // The whole path: the id decodes to INBOX UID 5 under the old UIDVALIDITY (the mailbox id
    // mapping for it is never retired), the folder now reports the new one, and UID 5 is a
    // different message. Before the check this deleted it.
    const { ctx: mailbox, calls } = createMailboxContext(NEW_UID_VALIDITY);

    const oldMailboxBuf = Buffer.concat([Buffer.alloc(8), Buffer.from('INBOX')]);
    oldMailboxBuf.writeBigUInt64BE(OLD_UID_VALIDITY, 0);

    const client = Object.assign(Object.create(IMAPClient.prototype), {
        logger: noopLogger,
        idCache: new Map([[7, oldMailboxBuf]]),
        pathCache: new Map(),
        mailboxes: new Map([['INBOX', mailbox]]),
        checkIMAPConnection: () => {}
    });

    const id = Buffer.alloc(8);
    id.writeUInt32BE(7, 0);
    id.writeUInt32BE(5, 4);

    const result = await client.deleteMessage(id.toString('base64url'), true);

    assert.strictEqual(result, false, 'reported as not found, which the API turns into a 404');
    assert.deepEqual(calls, [], 'the message now holding UID 5 is left alone');
});
