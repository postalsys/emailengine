'use strict';

// Mailbox.getMessage() runs the content-based bounce check only when the caller asks for it, and
// downloads the raw message under the lock the fetch already holds rather than taking another,
// which on the primary connection is a SELECT away from the watched folder and back.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. Nothing here reaches a real one.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

function createContext() {
    const events = [];
    const ctx = {
        path: 'INBOX',
        listingEntry: {},
        logger: noopLogger,
        connection: {
            getImapConnection: async () => ({
                fetchOne: async () => ({ uid: 42, flags: new Set() }),
                download: async () => {
                    events.push('download');
                    return { meta: {}, content: Buffer.from('raw') };
                }
            }),
            detectBounce: async (messageInfo, getContent) => {
                events.push('detect');
                assert.equal((await getContent()).toString(), 'raw');
            }
        },
        getMailboxLock: async () => ({
            release() {
                events.push('release');
            }
        }),
        getMessageInfo: async () => ({ id: 'm1', uid: 42 })
    };
    return { ctx, events };
}

const getMessage = (ctx, options) => Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, options);

test('Mailbox.getMessage() bounce detection option', async t => {
    await t.test('the details route asks for the check, and its download rides on the fetch lock', async () => {
        const { ctx, events } = createContext();

        const message = await getMessage(ctx, { detectBounce: true });

        assert.equal(message.id, 'm1');
        assert.deepEqual(events, ['detect', 'download', 'release']);
    });

    await t.test('a fetch that does not ask for it is left alone', async () => {
        const { ctx, events } = createContext();

        await getMessage(ctx, {});

        assert.deepEqual(events, ['release']);
    });

    await t.test('a message the folder no longer has is not checked', async () => {
        const { ctx, events } = createContext();
        ctx.getMessageInfo = async () => false;

        assert.equal(await getMessage(ctx, { detectBounce: true }), false);
        assert.deepEqual(events, ['release']);
    });
});
