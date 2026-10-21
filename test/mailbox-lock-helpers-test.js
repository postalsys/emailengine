'use strict';

// Mailbox.withMessageLock() and Mailbox.withMailboxLock(), which the update, move, delete and list
// methods take their folder lock through. A lock that is not released holds the folder for every
// other command on that connection, so each path out of the work has to release it.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');

function createMailbox(opts) {
    opts = opts || {};
    const locks = [];
    const client = {
        mailbox: { path: 'INBOX', uidValidity: 7n },
        messageMove: async () => {
            if (opts.moveError) {
                throw opts.moveError;
            }
            return { destination: 'Archive', uidMap: new Map([[5, 50]]) };
        },
        messageDelete: async () => true
    };
    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        connection: {
            getImapConnection: async () => client,
            packUid: async (folder, uid) => `${folder}:${uid}`,
            getSpecialUseMailbox: async () => ({ path: 'Trash' })
        },
        getMailboxLock: async (connectionClient, options) => {
            const lock = { description: options.description, released: 0, release: () => lock.released++ };
            locks.push(lock);
            return lock;
        }
    });
    return { ctx, locks, client };
}

test('Mailbox lock helpers', async t => {
    await t.test('withMailboxLock returns what the work returned and releases', async () => {
        const { ctx, locks, client } = createMailbox();
        assert.strictEqual(await ctx.withMailboxLock(client, { description: 'x' }, async () => 'done'), 'done');
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('withMailboxLock releases when the work throws', async () => {
        const { ctx, locks, client } = createMailbox();
        await assert.rejects(
            ctx.withMailboxLock(client, {}, async () => {
                throw new Error('boom');
            }),
            /boom/
        );
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('withMessageLock skips the work for a reference to a previous folder incarnation', async () => {
        const { ctx, locks, client } = createMailbox();
        let ran = false;
        const result = await ctx.withMessageLock(client, { uid: 5, uidValidity: 6n }, {}, async () => {
            ran = true;
        });
        assert.strictEqual(result, false);
        assert.strictEqual(ran, false);
        assert.strictEqual(locks[0].released, 1, 'the lock taken for the check is released too');
    });

    await t.test('withMessageLock runs the work for a current reference and releases', async () => {
        const { ctx, locks, client } = createMailbox();
        assert.strictEqual(await ctx.withMessageLock(client, { uid: 5, uidValidity: 7n }, {}, async () => 42), 42);
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('withMessageLock does not release a lock it did not take under skipLock', async () => {
        const { ctx, locks, client } = createMailbox();
        assert.strictEqual(await ctx.withMessageLock(client, { uid: 5 }, { skipLock: true }, async () => 'ok'), 'ok');
        assert.strictEqual(locks.length, 0);
    });
});

test('the API methods release their lock on every path', async t => {
    await t.test('moveMessage() on success', async () => {
        const { ctx, locks } = createMailbox();
        const result = await ctx.moveMessage({ uid: 5, uidValidity: 7n }, { path: 'Archive' });
        assert.deepStrictEqual(result, { path: 'Archive', id: 'Archive:50', uid: 50 });
        assert.match(locks[0].description, /^Move message: 5 to: Archive$/);
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('moveMessage() when the server refuses the move', async () => {
        const { ctx, locks } = createMailbox({ moveError: new Error('NO [TRYCREATE]') });
        await assert.rejects(ctx.moveMessage({ uid: 5, uidValidity: 7n }, { path: 'Archive' }), /TRYCREATE/);
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('moveMessage() for a stale reference', async () => {
        const { ctx, locks } = createMailbox();
        assert.strictEqual(await ctx.moveMessage({ uid: 5, uidValidity: 1n }, { path: 'Archive' }), false);
        assert.strictEqual(locks[0].released, 1);
    });

    await t.test('moveMessages() and deleteMessages() when the server fails', async () => {
        const { ctx, locks } = createMailbox({ moveError: new Error('connection lost') });
        await assert.rejects(ctx.moveMessages({ uid: '1:*' }, { path: 'Archive' }), /connection lost/);
        await assert.rejects(ctx.deleteMessages({ uid: '1:*' }, false), /connection lost/);
        assert.deepStrictEqual(
            locks.map(l => l.released),
            [1, 1]
        );
    });

    await t.test('deleteMessage() moves to Trash under the lock', async () => {
        const { ctx, locks } = createMailbox();
        const result = await ctx.deleteMessage({ uid: 5, uidValidity: 7n }, false);
        assert.deepStrictEqual(result, { deleted: false, moved: { destination: 'Archive', message: 'Trash:50' } });
        assert.strictEqual(locks[0].released, 1);
    });
});

test('reading a folder the connection already has open refreshes it first', async t => {
    // the real getMailboxLock(), on a client standing in for ImapFlow
    const createReader = ({ openPath, idling = false, noopError = null } = {}) => {
        const commands = [];
        const client = {
            mailbox: openPath ? { path: openPath } : false,
            idling,
            getMailboxLock: async () => {
                if (!client.mailbox || client.mailbox.path.toUpperCase() !== 'INBOX') {
                    commands.push('SELECT');
                    client.mailbox = { path: 'INBOX' };
                }
                return { release: () => commands.push('RELEASE') };
            },
            noop: async () => {
                commands.push('NOOP');
                if (noopError) {
                    throw noopError;
                }
            },
            search: async () => {
                commands.push('SEARCH');
                return [];
            },
            messageDelete: async () => {
                commands.push('DELETE');
                return true;
            }
        };
        const ctx = Object.assign(Object.create(Mailbox.prototype), {
            path: 'INBOX',
            listingEntry: { path: 'INBOX', specialUse: '\\Trash' },
            // a command connection, not the primary one
            connection: { imapClient: {}, getImapConnection: async () => client },
            getMailboxStatus: () => ({ messages: 0 })
        });
        return { ctx, commands };
    };

    await t.test('a listing sends a NOOP before it reads, so changes made over another connection are reported', async () => {
        const { ctx, commands } = createReader({ openPath: 'Inbox' });
        const result = await ctx.listMessages({ search: { unseen: true } });
        assert.deepStrictEqual(commands, ['NOOP', 'SEARCH', 'RELEASE']);
        assert.strictEqual(result.total, 0);
    });

    await t.test('a bulk operation on a search does the same', async () => {
        const { ctx, commands } = createReader({ openPath: 'INBOX' });
        await ctx.deleteMessages({ seen: true }, true);
        assert.deepStrictEqual(commands, ['NOOP', 'DELETE', 'RELEASE']);
    });

    await t.test('no NOOP when the lock selects the folder', async () => {
        const { ctx, commands } = createReader({ openPath: 'Archive' });
        await ctx.listMessages({ search: { unseen: true } });
        assert.deepStrictEqual(commands, ['SELECT', 'SEARCH', 'RELEASE']);
    });

    await t.test('no NOOP when the connection was idling, IDLE already reported the changes', async () => {
        const { ctx, commands } = createReader({ openPath: 'INBOX', idling: true });
        await ctx.listMessages({ search: { unseen: true } });
        assert.deepStrictEqual(commands, ['SEARCH', 'RELEASE']);
    });

    await t.test('a single-message operation takes no refresh', async () => {
        const { ctx, commands } = createReader({ openPath: 'INBOX' });
        await ctx.deleteMessage({ uid: 5 }, true);
        assert.deepStrictEqual(commands, ['DELETE', 'RELEASE']);
    });

    await t.test('a failed NOOP releases the lock and fails the read', async () => {
        const { ctx, commands } = createReader({ openPath: 'INBOX', noopError: new Error('Connection not available') });
        await assert.rejects(ctx.listMessages({}), /Connection not available/);
        assert.deepStrictEqual(commands, ['NOOP', 'RELEASE']);
    });
});
